//! Direct low-latency QUIC P2P screen and audio streaming (Tailscale & LAN ready).
//! Bypasses Discord's Go Live media servers with 1-click `serein-p2p://` links,
//! ephemeral ECDSA TLS 1.3 cert pinning, per-GOP QUIC uni-streams (no cross-GOP
//! head-of-line blocking), and QUIC datagrams for 48 kHz stereo Opus audio.
#![forbid(unsafe_code)]

use crate::screen::Video;
use crate::video_codec::Codec;
use crate::video_receive::{Encoded, P2P_MAX_FRAME_BYTES, VideoSink, offer, spawn_p2p_decoder};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use opus2::{Application, Bitrate, Channels, Decoder as OpusDecoder, Encoder as OpusEncoder};
use quinn::{
	ClientConfig, Connection, Endpoint, IdleTimeout, RecvStream, SendStream, ServerConfig,
	TransportConfig, VarInt,
};
use ring::digest::{SHA256, digest};
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{
	Arc, Mutex,
	atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use tokio::{
	sync::{Semaphore, mpsc, watch},
	task::JoinSet,
};

pub const SCHEME: &str = "serein-p2p";
pub const MAX_VIEWERS: usize = 8;

const ALPN: &[u8] = b"serein-p2p/1";
const AUTH_MAGIC: [u8; 5] = *b"SP2P\x01";
const AUTH_OK: u8 = 0x01;
const AUTH_FULL: u8 = 0x02;
const CTRL_PLI: u8 = 0x01;
const AUDIO_TAG: u8 = b'A';
const AUDIO_HEADER_LEN: usize = 9;
const AUDIO_FRAME_FRAMES: usize = 960;
const AUDIO_FRAME_FLOATS: usize = AUDIO_FRAME_FRAMES * 2;
const MAX_AUDIO_DGRAM: usize = 1150;
const QUIC_KEEPALIVE: Duration = Duration::from_secs(2);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

// Close established connections as well as the socket when the owner cancels the task.
struct CloseEndpoint(Endpoint);

impl Drop for CloseEndpoint {
	fn drop(&mut self) {
		self.0.close(0u32.into(), b"session stopped");
	}
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalNetworkInfo {
	pub tailscale: Option<Ipv4Addr>,
	pub lan: Option<Ipv4Addr>,
}

impl LocalNetworkInfo {
	pub fn best_ip(&self) -> IpAddr {
		IpAddr::V4(self.tailscale.or(self.lan).unwrap_or(Ipv4Addr::LOCALHOST))
	}
}

/// Tailscale allocates CGNAT addresses from `100.64.0.0/10`.
pub fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
	let octets = ip.octets();
	octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn udp_route_ipv4(remote: &str) -> Option<Ipv4Addr> {
	let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
	sock.connect(remote).ok()?;
	match sock.local_addr().ok()?.ip() {
		IpAddr::V4(v4) if !v4.is_unspecified() && !v4.is_loopback() => Some(v4),
		_ => None,
	}
}

fn tailscale_cli_ipv4() -> Option<Ipv4Addr> {
	let output = std::process::Command::new("tailscale")
		.args(["ip", "-4"])
		.output()
		.ok()?;
	if !output.status.success() {
		return None;
	}
	let stdout = String::from_utf8_lossy(&output.stdout);
	stdout
		.lines()
		.find_map(|line| line.trim().parse::<Ipv4Addr>().ok())
		.filter(|ip| is_tailscale_ipv4(*ip))
}

/// Discovers Tailscale (`100.64.0.0/10`) and primary LAN IPv4 addresses cross-platform.
pub fn discover_local_ips() -> LocalNetworkInfo {
	let tailscale = udp_route_ipv4("100.100.100.100:80")
		.filter(|ip| is_tailscale_ipv4(*ip))
		.or_else(tailscale_cli_ipv4);
	let lan = udp_route_ipv4("1.1.1.1:80").filter(|ip| ip.is_private() || ip.is_link_local());
	LocalNetworkInfo { tailscale, lan }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pTarget {
	pub host: String,
	pub port: u16,
	pub token: [u8; 16],
	pub fingerprint: [u8; 32],
}

pub fn looks_like_p2p_link(input: &str) -> bool {
	input
		.trim()
		.get(..SCHEME.len() + 3)
		.is_some_and(|prefix| prefix.eq_ignore_ascii_case("serein-p2p://"))
}

impl P2pTarget {
	pub fn parse(input: &str) -> Result<Self, &'static str> {
		let trimmed = input.trim();
		if !looks_like_p2p_link(trimmed) {
			return Err("Link must start with serein-p2p://");
		}
		let parsed = url::Url::parse(trimmed).map_err(|_| "Invalid serein-p2p:// link")?;
		if !parsed.scheme().eq_ignore_ascii_case(SCHEME) {
			return Err("Unsupported link scheme");
		}
		let raw_host = parsed.host_str().ok_or("Missing host in P2P link")?;
		let host = raw_host
			.trim()
			.trim_start_matches('[')
			.trim_end_matches(']')
			.to_owned();
		if host.is_empty() || host.chars().any(char::is_whitespace) {
			return Err("Invalid host in P2P link");
		}
		let port = parsed
			.port()
			.filter(|port| *port != 0)
			.ok_or("Missing or invalid port in P2P link")?;

		let mut token_hex = None;
		let mut fp_hex = None;
		for (k, v) in parsed.query_pairs() {
			if k == "t" {
				token_hex = Some(v);
			} else if k == "fp" {
				fp_hex = Some(v);
			}
		}
		let token = decode_hex_array::<16>(
			token_hex
				.as_deref()
				.ok_or("Missing auth token (t=) in P2P link")?,
		)
		.ok_or("Invalid auth token in P2P link")?;
		let fingerprint = decode_hex_array::<32>(
			fp_hex
				.as_deref()
				.ok_or("Missing cert fingerprint (fp=) in P2P link")?,
		)
		.ok_or("Invalid cert fingerprint in P2P link")?;

		Ok(Self {
			host,
			port,
			token,
			fingerprint,
		})
	}

	pub fn to_link(&self) -> String {
		let host = if self.host.contains(':') && !self.host.starts_with('[') {
			format!("[{}]", self.host)
		} else {
			self.host.clone()
		};
		format!(
			"{SCHEME}://{host}:{}?t={}&fp={}",
			self.port,
			encode_hex(&self.token),
			encode_hex(&self.fingerprint)
		)
	}
}

fn encode_hex(bytes: &[u8]) -> String {
	const HEX: &[u8; 16] = b"0123456789abcdef";
	let mut out = String::with_capacity(bytes.len() * 2);
	for &b in bytes {
		out.push(HEX[(b >> 4) as usize] as char);
		out.push(HEX[(b & 0x0f) as usize] as char);
	}
	out
}

fn decode_hex_array<const N: usize>(hex: &str) -> Option<[u8; N]> {
	if hex.len() != N * 2 {
		return None;
	}
	let mut out = [0u8; N];
	let bytes = hex.as_bytes();
	for i in 0..N {
		let hi = from_hex_nibble(bytes[i * 2])?;
		let lo = from_hex_nibble(bytes[i * 2 + 1])?;
		out[i] = (hi << 4) | lo;
	}
	Some(out)
}

fn from_hex_nibble(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum P2pHostState {
	#[default]
	Starting,
	Listening,
	Streaming,
	Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2pHostStats {
	pub state: P2pHostState,
	pub link: String,
	pub ip: String,
	pub port: u16,
	pub tailscale: bool,
	pub viewers: usize,
	pub fps: u32,
	pub bitrate_kbps: u32,
	pub status: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum P2pWatchState {
	#[default]
	Connecting,
	Authenticating,
	WaitingVideo,
	Watching,
	Failed,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2pWatchStats {
	pub state: P2pWatchState,
	pub rtt_ms: u32,
	pub fps: u32,
	pub bitrate_kbps: u32,
	pub width: u32,
	pub height: u32,
	pub hardware_decode: bool,
	pub audio_active: bool,
	pub status: String,
}

#[derive(Clone, Copy, Debug)]
pub struct P2pHostConfig {
	pub bind_port: u16,
	pub initial_bitrate_bps: u32,
}

impl Default for P2pHostConfig {
	fn default() -> Self {
		Self {
			bind_port: 0,
			initial_bitrate_bps: 25_000_000,
		}
	}
}

fn build_transport_config() -> TransportConfig {
	let mut transport = TransportConfig::default();
	transport.initial_mtu(1200);
	transport.mtu_discovery_config(None);
	transport.receive_window(VarInt::from_u32(4 * 1024 * 1024));
	transport.stream_receive_window(VarInt::from_u32(2 * 1024 * 1024));
	transport.send_window(2 * 1024 * 1024);
	transport.keep_alive_interval(Some(QUIC_KEEPALIVE));
	transport.max_idle_timeout(IdleTimeout::try_from(QUIC_IDLE_TIMEOUT).ok());
	transport.datagram_receive_buffer_size(Some(256 * 1024));
	transport.datagram_send_buffer_size(256 * 1024);
	transport.max_concurrent_bidi_streams(VarInt::from_u32(4));
	transport.max_concurrent_uni_streams(VarInt::from_u32(8));
	transport
}

#[derive(Debug)]
struct PinnedCertVerifier {
	expected_sha256: [u8; 32],
	crypto: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCertVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		_intermediates: &[CertificateDer<'_>],
		_server_name: &ServerName<'_>,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		let cert_digest = digest(&SHA256, end_entity.as_ref());
		if cert_digest.as_ref() == self.expected_sha256 {
			Ok(ServerCertVerified::assertion())
		} else {
			Err(rustls::Error::InvalidCertificate(
				rustls::CertificateError::BadSignature,
			))
		}
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls12_signature(
			message,
			cert,
			dss,
			&self.crypto.signature_verification_algorithms,
		)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		rustls::crypto::verify_tls13_signature(
			message,
			cert,
			dss,
			&self.crypto.signature_verification_algorithms,
		)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.crypto
			.signature_verification_algorithms
			.supported_schemes()
	}
}

fn generate_ephemeral_server_config() -> Result<(ServerConfig, [u8; 32]), String> {
	let certified = rcgen::generate_simple_self_signed(vec!["serein-p2p".to_owned()])
		.map_err(|e| format!("Failed to generate P2P TLS cert: {e}"))?;
	let cert_bytes = certified.cert.der().to_vec();
	let fp_digest = digest(&SHA256, &cert_bytes);
	let mut fingerprint = [0u8; 32];
	fingerprint.copy_from_slice(fp_digest.as_ref());

	let cert_der = CertificateDer::from(cert_bytes);
	let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
		certified.signing_key.serialize_der(),
	));

	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13])
		.map_err(|e| format!("TLS 1.3 setup error: {e}"))?
		.with_no_client_auth()
		.with_single_cert(vec![cert_der], key_der)
		.map_err(|e| format!("TLS server cert error: {e}"))?;
	server_crypto.alpn_protocols = vec![ALPN.to_vec()];

	let quic_server = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
		.map_err(|e| format!("QUIC server TLS config error: {e}"))?;
	let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server));
	server_config.transport_config(Arc::new(build_transport_config()));
	Ok((server_config, fingerprint))
}

fn build_client_config(expected_sha256: [u8; 32]) -> Result<ClientConfig, String> {
	let provider = Arc::new(rustls::crypto::ring::default_provider());
	let verifier = Arc::new(PinnedCertVerifier {
		expected_sha256,
		crypto: provider.clone(),
	});
	let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
		.with_protocol_versions(&[&rustls::version::TLS13])
		.map_err(|e| format!("TLS 1.3 client setup error: {e}"))?
		.dangerous()
		.with_custom_certificate_verifier(verifier)
		.with_no_client_auth();
	client_crypto.alpn_protocols = vec![ALPN.to_vec()];

	let quic_client = quinn::crypto::rustls::QuicClientConfig::try_from(client_crypto)
		.map_err(|e| format!("QUIC client TLS config error: {e}"))?;
	let mut client_config = ClientConfig::new(Arc::new(quic_client));
	client_config.transport_config(Arc::new(build_transport_config()));
	Ok(client_config)
}

#[derive(Clone)]
struct EncodedPacket {
	gop_id: u64,
	keyframe: bool,
	timestamp: u32,
	data: Vec<u8>,
}

struct ViewerSlot {
	id: u64,
	conn: Connection,
	video_tx: mpsc::Sender<Arc<EncodedPacket>>,
}

struct HostShared {
	token: [u8; 16],
	width: u32,
	height: u32,
	fps: u32,
	has_audio: bool,
	video_ready: Arc<AtomicBool>,
	video_keyframe: Arc<AtomicBool>,
	next_viewer_id: AtomicU64,
	viewers: Mutex<Vec<ViewerSlot>>,
	stats_tx: watch::Sender<P2pHostStats>,
	wake: Arc<dyn Fn() + Send + Sync>,
}

impl HostShared {
	fn viewer_count(&self) -> usize {
		self.viewers.lock().map_or(0, |v| v.len())
	}

	fn update_viewer_state(&self) {
		let count = self.viewer_count();
		if count > 0 {
			self.video_keyframe.store(true, Ordering::Release);
			self.video_ready.store(true, Ordering::Release);
		} else {
			self.video_ready.store(false, Ordering::Release);
		}
		self.stats_tx.send_modify(|s| {
			s.viewers = count;
			if count > 0 {
				s.state = P2pHostState::Streaming;
				s.status = format!(
					"P2P active · {count} viewer{}",
					if count == 1 { "" } else { "s" }
				);
			} else if s.state != P2pHostState::Failed {
				s.state = P2pHostState::Listening;
				s.status = "P2P ready · waiting for viewers".to_owned();
			}
		});
		(self.wake)();
	}

	fn remove_viewer(&self, id: u64) {
		if let Ok(mut list) = self.viewers.lock() {
			list.retain(|entry| entry.id != id);
		}
		self.update_viewer_state();
	}
}

/// Runs a direct QUIC P2P host serving `video` to up to `MAX_VIEWERS` authenticated peers.
pub async fn run_p2p_host(
	video: Video,
	config: P2pHostConfig,
	stats: watch::Sender<P2pHostStats>,
	wake: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
	let net = tokio::task::spawn_blocking(discover_local_ips)
		.await
		.map_err(|_| "Could not discover a local network address".to_owned())?;
	let ip = net.best_ip();
	run_p2p_host_with_bind(
		video,
		config,
		SocketAddr::new(ip, config.bind_port),
		Some(ip.to_string()),
		stats,
		wake,
	)
	.await
}

async fn run_p2p_host_with_bind(
	mut video: Video,
	config: P2pHostConfig,
	bind_addr: SocketAddr,
	advertised_host: Option<String>,
	stats: watch::Sender<P2pHostStats>,
	wake: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
	let mut token = [0u8; 16];
	getrandom::fill(&mut token).map_err(|_| "System randomness unavailable".to_owned())?;

	let (server_config, fingerprint) = generate_ephemeral_server_config()?;
	let endpoint = Endpoint::server(server_config, bind_addr)
		.map_err(|e| format!("Failed to bind P2P UDP port {}: {e}", bind_addr.port()))?;
	let local_port = endpoint
		.local_addr()
		.map_err(|e| format!("Failed to read bound P2P port: {e}"))?
		.port();
	let endpoint = CloseEndpoint(endpoint);

	let ip = advertised_host.unwrap_or_else(|| bind_addr.ip().to_string());
	let tailscale = ip.parse().is_ok_and(is_tailscale_ipv4);
	let mut link = P2pTarget {
		host: ip.clone(),
		port: local_port,
		token,
		fingerprint,
	}
	.to_link();
	if video.settings.width > 0 && video.settings.height > 0 && video.settings.fps > 0 {
		link.push_str(&format!(
			"&w={}&h={}&fps={}",
			video.settings.width, video.settings.height, video.settings.fps
		));
	}

	let initial_bps = config
		.initial_bitrate_bps
		.clamp(250_000, client_core::screen::MAX_P2P_BITRATE_BPS);
	video.bitrate.store(initial_bps, Ordering::Release);
	video.ready.store(false, Ordering::Release);

	stats.send_replace(P2pHostStats {
		state: P2pHostState::Listening,
		link: link.clone(),
		ip,
		port: local_port,
		tailscale,
		viewers: 0,
		fps: 0,
		bitrate_kbps: initial_bps / 1000,
		status: "P2P ready · waiting for viewers".to_owned(),
	});
	(wake)();

	let shared = Arc::new(HostShared {
		token,
		width: video.settings.width,
		height: video.settings.height,
		fps: video.settings.fps,
		has_audio: video.audio.is_some(),
		video_ready: video.ready.clone(),
		video_keyframe: video.keyframe.clone(),
		next_viewer_id: AtomicU64::new(1),
		viewers: Mutex::new(Vec::new()),
		stats_tx: stats.clone(),
		wake: wake.clone(),
	});

	let audio_rx = video.audio.take();
	let audio_epoch = video.audio_epoch.clone();
	let audio_shared = shared.clone();
	let mut tasks = JoinSet::new();
	if let Some(rx) = audio_rx {
		tasks.spawn(async move {
			host_audio_loop(rx, audio_epoch, audio_shared).await;
		});
	}

	let video_shared = shared.clone();
	let mut video_frames = video.frames;
	let video_keyframe_flag = video.keyframe.clone();
	tasks.spawn(async move {
		let mut gop_id = 0u64;
		let mut frames_window = 0u32;
		let mut bytes_window = 0u64;
		let mut window_start = Instant::now();
		let mut last_pli_request = Instant::now() - Duration::from_secs(5);

		while let Some(frame) = video_frames.recv().await {
			if frame.keyframe {
				gop_id = gop_id.wrapping_add(1).max(1);
			} else if gop_id == 0 {
				gop_id = 1;
			}
			frames_window = frames_window.saturating_add(1);
			bytes_window = bytes_window.saturating_add(frame.data.len() as u64);

			let packet = Arc::new(EncodedPacket {
				gop_id,
				keyframe: frame.keyframe,
				timestamp: frame.timestamp,
				data: frame.data,
			});

			let mut any_dropped = false;
			if let Ok(list) = video_shared.viewers.lock() {
				for viewer in list.iter() {
					if viewer.video_tx.try_send(packet.clone()).is_err() {
						any_dropped = true;
					}
				}
			}
			if any_dropped && last_pli_request.elapsed() >= Duration::from_millis(250) {
				last_pli_request = Instant::now();
				video_keyframe_flag.store(true, Ordering::Release);
			}

			let elapsed = window_start.elapsed();
			if elapsed >= Duration::from_secs(1) {
				let secs = elapsed.as_secs_f64();
				let fps = (f64::from(frames_window) / secs).round() as u32;
				let bitrate_kbps = ((bytes_window as f64 * 8.0) / secs / 1000.0).round() as u32;
				video_shared.stats_tx.send_modify(|s| {
					s.fps = fps;
					s.bitrate_kbps = bitrate_kbps;
				});
				(video_shared.wake)();
				frames_window = 0;
				bytes_window = 0;
				window_start = Instant::now();
			}
		}
	});

	let connections = Arc::new(Semaphore::new(MAX_VIEWERS + 8));
	while let Some(incoming) = endpoint.0.accept().await {
		while tasks.try_join_next().is_some() {}
		let Ok(permit) = connections.clone().try_acquire_owned() else {
			incoming.refuse();
			continue;
		};
		let shared = shared.clone();
		tasks.spawn(async move {
			let _permit = permit;
			let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), incoming).await else {
				return;
			};
			let _ = handle_viewer_connection(conn, shared).await;
		});
	}
	Ok(())
}

async fn handle_viewer_connection(conn: Connection, shared: Arc<HostShared>) -> Result<(), ()> {
	let (mut ctrl_send, mut ctrl_recv) =
		tokio::time::timeout(Duration::from_secs(5), conn.accept_bi())
			.await
			.map_err(|_| ())?
			.map_err(|_| ())?;
	let mut auth_buf = [0u8; 21];
	tokio::time::timeout(Duration::from_secs(5), ctrl_recv.read_exact(&mut auth_buf))
		.await
		.map_err(|_| ())?
		.map_err(|_| ())?;

	if auth_buf[..5] != AUTH_MAGIC || !bool::from(auth_buf[5..21].ct_eq(&shared.token)) {
		let _ = ctrl_send.write_all(&[0x00]).await;
		let _ = ctrl_send.finish();
		conn.close(1u32.into(), b"unauthorized");
		return Err(());
	}

	let (video_tx, mut video_rx) = mpsc::channel::<Arc<EncodedPacket>>(4);
	let viewer_id = shared.next_viewer_id.fetch_add(1, Ordering::Relaxed);
	let accepted = {
		let mut list = shared.viewers.lock().map_err(|_| ())?;
		if list.len() >= MAX_VIEWERS {
			false
		} else {
			list.push(ViewerSlot {
				id: viewer_id,
				conn: conn.clone(),
				video_tx,
			});
			true
		}
	};
	if !accepted {
		let _ = ctrl_send.write_all(&[AUTH_FULL]).await;
		let _ = ctrl_send.finish();
		conn.close(2u32.into(), b"max viewers reached");
		return Err(());
	}

	let mut accept_msg = [0u8; 14];
	accept_msg[0] = AUTH_OK;
	accept_msg[1..5].copy_from_slice(&shared.width.to_be_bytes());
	accept_msg[5..9].copy_from_slice(&shared.height.to_be_bytes());
	accept_msg[9..13].copy_from_slice(&shared.fps.to_be_bytes());
	accept_msg[13] = u8::from(shared.has_audio);
	if ctrl_send.write_all(&accept_msg).await.is_err() {
		shared.remove_viewer(viewer_id);
		return Err(());
	}

	shared.update_viewer_state();

	let ctrl_shared = shared.clone();
	let ctrl_conn = conn.clone();
	let mut control = JoinSet::new();
	control.spawn(async move {
		let _response = ctrl_send;
		let mut opcode = [0u8; 1];
		let mut last_pli = None::<Instant>;
		while ctrl_recv.read_exact(&mut opcode).await.is_ok() {
			if opcode[0] != CTRL_PLI {
				break;
			}
			if last_pli.is_none_or(|last| last.elapsed() >= Duration::from_millis(250)) {
				last_pli = Some(Instant::now());
				ctrl_shared.video_keyframe.store(true, Ordering::Release);
			}
		}
		ctrl_conn.close(0u32.into(), b"control closed");
	});

	let mut active_gop: Option<(u64, SendStream)> = None;
	let mut need_keyframe = true;
	let mut header = [0u8; 9];

	while let Some(packet) = tokio::select! {
		packet = video_rx.recv() => packet,
		_ = conn.closed() => None,
	} {
		if need_keyframe && !packet.keyframe {
			continue;
		}
		if packet.keyframe || active_gop.is_none() {
			if let Some((_, mut old_stream)) = active_gop.take() {
				let _ = old_stream.reset(0u32.into());
			}
			let Ok(stream) = conn.open_uni().await else {
				break;
			};
			active_gop = Some((packet.gop_id, stream));
			need_keyframe = false;
		}

		let Some((stream_gop, stream)) = active_gop.as_mut() else {
			break;
		};
		if *stream_gop != packet.gop_id && !packet.keyframe {
			continue;
		}

		let Ok(len) = u32::try_from(packet.data.len()) else {
			continue;
		};
		header[0] = u8::from(packet.keyframe);
		header[1..5].copy_from_slice(&packet.timestamp.to_be_bytes());
		header[5..9].copy_from_slice(&len.to_be_bytes());
		let sent = tokio::time::timeout(Duration::from_millis(250), async {
			stream.write_all(&header).await?;
			stream.write_all(&packet.data).await
		})
		.await;
		if !matches!(sent, Ok(Ok(()))) {
			if let Some((_, mut old_stream)) = active_gop.take() {
				let _ = old_stream.reset(0u32.into());
			}
			need_keyframe = true;
			shared.video_keyframe.store(true, Ordering::Release);
			if conn.close_reason().is_some() {
				break;
			}
		}
	}

	shared.remove_viewer(viewer_id);
	Ok(())
}

async fn host_audio_loop(
	mut audio_rx: mpsc::Receiver<crate::screen::AudioChunk>,
	audio_epoch: Arc<AtomicU64>,
	shared: Arc<HostShared>,
) {
	let Ok(mut encoder) = OpusEncoder::new(48_000, Channels::Stereo, Application::Audio) else {
		return;
	};
	let _ = encoder.set_bitrate(Bitrate::Bits(128_000));

	let mut last_epoch = audio_epoch.load(Ordering::Acquire);
	let mut staging: Vec<f32> = Vec::with_capacity(AUDIO_FRAME_FLOATS * 4);
	let mut opus_out = [0u8; MAX_AUDIO_DGRAM];
	let mut seq = 0u32;
	let mut ts = 0u32;

	while let Some(chunk) = audio_rx.recv().await {
		if chunk.epoch != last_epoch {
			last_epoch = chunk.epoch;
			staging.clear();
			let _ = encoder.reset_state();
		}
		if shared.viewer_count() == 0 {
			staging.clear();
			continue;
		}
		staging.extend_from_slice(&chunk.samples);
		// Keep staging bounded so stale audio never accumulates during CPU spikes.
		if staging.len() > AUDIO_FRAME_FLOATS * 8 {
			let drop_count = staging.len() - AUDIO_FRAME_FLOATS * 2;
			let aligned = drop_count - (drop_count % 2);
			staging.drain(..aligned);
		}
		while staging.len() >= AUDIO_FRAME_FLOATS {
			let encoded = encoder.encode_float(&staging[..AUDIO_FRAME_FLOATS], &mut opus_out);
			staging.drain(..AUDIO_FRAME_FLOATS);
			let Ok(n) = encoded else {
				continue;
			};
			if n == 0 || n + AUDIO_HEADER_LEN > MAX_AUDIO_DGRAM {
				continue;
			}
			let mut dgram = Vec::with_capacity(AUDIO_HEADER_LEN + n);
			dgram.push(AUDIO_TAG);
			dgram.extend_from_slice(&seq.to_be_bytes());
			dgram.extend_from_slice(&ts.to_be_bytes());
			dgram.extend_from_slice(&opus_out[..n]);
			seq = seq.wrapping_add(1);
			ts = ts.wrapping_add(AUDIO_FRAME_FRAMES as u32);

			let payload: bytes_compat::Bytes = dgram;
			if let Ok(list) = shared.viewers.lock() {
				for viewer in list.iter() {
					let _ = viewer.conn.send_datagram(payload.clone().into());
				}
			}
		}
	}
}

mod bytes_compat {
	pub type Bytes = Vec<u8>;
}

/// Connects to a remote `P2pTarget`, validates its pinned cert & auth token, decodes
/// incoming H.264 video with zero presentation delay (`presentation: None`), and plays
/// 48 kHz stereo Opus datagrams independently of any Discord voice call.
pub async fn run_p2p_viewer(
	target: P2pTarget,
	sink: VideoSink,
	volume_percent: Arc<AtomicU16>,
	output_device: Option<String>,
	stats: watch::Sender<P2pWatchStats>,
	wake: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
	run_p2p_viewer_with_call_audio(
		target,
		sink,
		volume_percent,
		output_device,
		None,
		stats,
		wake,
	)
	.await
}

/// Connects to a remote `P2pTarget` and routes stream audio either into Serein's active call
/// playback mixer (`call_audio = Some(...)`) or a standalone `P2pAudioPlayer` (`None`).
pub async fn run_p2p_viewer_with_call_audio(
	target: P2pTarget,
	sink: VideoSink,
	volume_percent: Arc<AtomicU16>,
	output_device: Option<String>,
	call_audio: Option<std::sync::mpsc::SyncSender<crate::PlaybackFrame>>,
	stats: watch::Sender<P2pWatchStats>,
	wake: Arc<dyn Fn() + Send + Sync>,
) -> Result<(), String> {
	stats.send_modify(|s| {
		s.state = P2pWatchState::Connecting;
		s.status = format!("Connecting to {}:{}…", target.host, target.port);
	});
	(wake)();

	let mut resolved = tokio::net::lookup_host((target.host.as_str(), target.port))
		.await
		.map_err(|e| format!("Could not resolve {}:{}: {e}", target.host, target.port))?;
	let addr = resolved
		.find(|a| a.is_ipv4())
		.or_else(|| {
			std::net::ToSocketAddrs::to_socket_addrs(&(target.host.as_str(), target.port))
				.ok()
				.and_then(|mut it| it.next())
		})
		.ok_or_else(|| format!("No address resolved for {}:{}", target.host, target.port))?;

	let bind_addr: SocketAddr = if addr.is_ipv4() {
		SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
	} else {
		SocketAddr::from(([0u16; 8], 0))
	};

	let client_config = build_client_config(target.fingerprint)?;
	let mut endpoint =
		Endpoint::client(bind_addr).map_err(|e| format!("Failed to open P2P UDP socket: {e}"))?;
	endpoint.set_default_client_config(client_config);
	let endpoint = CloseEndpoint(endpoint);

	let connecting = endpoint
		.0
		.connect(addr, "serein-p2p")
		.map_err(|e| format!("Failed to initiate P2P connection: {e}"))?;
	let conn = tokio::time::timeout(Duration::from_secs(10), connecting)
		.await
		.map_err(|_| "P2P connection timed out (check Tailscale / firewall UDP)".to_owned())?
		.map_err(|e| format!("P2P TLS/QUIC handshake failed: {e}"))?;

	stats.send_modify(|s| {
		s.state = P2pWatchState::Authenticating;
		s.status = "Authenticating P2P session…".to_owned();
	});
	(wake)();

	let (mut ctrl_send, mut ctrl_recv) = conn
		.open_bi()
		.await
		.map_err(|e| format!("Failed to open P2P control stream: {e}"))?;
	let mut auth_msg = [0u8; 21];
	auth_msg[..5].copy_from_slice(&AUTH_MAGIC);
	auth_msg[5..21].copy_from_slice(&target.token);
	ctrl_send
		.write_all(&auth_msg)
		.await
		.map_err(|e| format!("Failed to send P2P auth: {e}"))?;

	let mut status_byte = [0u8; 1];
	tokio::time::timeout(
		Duration::from_secs(5),
		ctrl_recv.read_exact(&mut status_byte),
	)
	.await
	.map_err(|_| "P2P auth response timed out".to_owned())?
	.map_err(|e| format!("Failed reading P2P auth response: {e}"))?;

	if status_byte[0] == AUTH_FULL {
		return Err("Host reached maximum P2P viewers (8)".to_owned());
	}
	if status_byte[0] != AUTH_OK {
		return Err("Invalid P2P access token".to_owned());
	}

	let mut meta = [0u8; 13];
	ctrl_recv
		.read_exact(&mut meta)
		.await
		.map_err(|e| format!("Failed reading P2P stream metadata: {e}"))?;
	let width = u32::from_be_bytes([meta[0], meta[1], meta[2], meta[3]]);
	let height = u32::from_be_bytes([meta[4], meta[5], meta[6], meta[7]]);
	let _announced_fps = u32::from_be_bytes([meta[8], meta[9], meta[10], meta[11]]);
	let has_audio = meta[12] != 0;

	let stats_for_sink = stats.clone();
	let wake_for_sink = wake.clone();
	let frames_seen = Arc::new(AtomicU32::new(0));
	let frames_seen_sink = frames_seen.clone();
	let wrapped_sink: VideoSink = Arc::new(move |frame| {
		frames_seen_sink.fetch_add(1, Ordering::Relaxed);
		let w = frame.picture.width;
		let h = frame.picture.height;
		stats_for_sink.send_modify(|s| {
			if s.state != P2pWatchState::Watching {
				s.state = P2pWatchState::Watching;
				s.status = "Watching P2P stream".to_owned();
			}
			s.width = w;
			s.height = h;
		});
		sink(frame);
		(wake_for_sink)();
	});

	let (decoder, lost) = spawn_p2p_decoder(wrapped_sink).map_err(|e| e.to_owned())?;
	let decoder = Arc::new(decoder);

	stats.send_modify(|s| {
		s.state = P2pWatchState::WaitingVideo;
		s.width = width;
		s.height = height;
		s.status = "P2P connected · waiting for keyframe…".to_owned();
	});
	(wake)();

	let (pli_tx, mut pli_rx) = mpsc::channel::<()>(8);
	let _ = pli_tx.try_send(());

	let mut tasks = JoinSet::new();
	tasks.spawn(async move {
		while pli_rx.recv().await.is_some() {
			if ctrl_send.write_all(&[CTRL_PLI]).await.is_err() {
				break;
			}
		}
	});

	let audio_conn = conn.clone();
	let audio_stats = stats.clone();
	let audio_wake = wake.clone();
	if has_audio {
		let push_call_frame = |tx: &std::sync::mpsc::SyncSender<crate::PlaybackFrame>, interleaved: &[f32]| {
			for chunk in interleaved.as_chunks::<AUDIO_FRAME_FLOATS>().0 {
				let mut mono = [0.0f32; AUDIO_FRAME_FRAMES];
				for (i, pair) in chunk.as_chunks::<2>().0.iter().enumerate() {
					mono[i] = ((pair[0] + pair[1]) * 0.5).clamp(-1.0, 1.0);
				}
				let _ = tx.try_send(crate::PlaybackFrame {
					samples: mono,
					presentation: None,
					mixed: false,
				});
			}
		};
		tasks.spawn(async move {
			let mut standalone = if call_audio.is_none() {
				let player = tokio::task::spawn_blocking(move || {
					P2pAudioPlayer::open(output_device.as_deref(), volume_percent)
				})
				.await;
				let Ok(Ok(player)) = player else {
					return;
				};
				Some(player)
			} else {
				None
			};
			let Ok(mut opus_dec) = OpusDecoder::new(48_000, Channels::Stereo) else {
				return;
			};
			audio_stats.send_modify(|s| s.audio_active = true);
			audio_wake();
			let mut pcm = vec![0.0f32; AUDIO_FRAME_FLOATS * 2];
			let mut last_seq: Option<u32> = None;

			while let Ok(dgram) = audio_conn.read_datagram().await {
				let data: &[u8] = &dgram;
				if data.len() < AUDIO_HEADER_LEN || data[0] != AUDIO_TAG {
					continue;
				}
				let seq = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
				if let Some(prev) = last_seq {
					let diff = seq.wrapping_sub(prev);
					if diff == 0 || diff > 1000 {
						if diff > 1000 && diff < u32::MAX - 1000 {
							let _ = opus_dec.reset_state();
						} else {
							continue;
						}
					} else if diff > 1 {
						let lost_frames = (diff - 1).min(3);
						for _ in 0..lost_frames {
							if let Ok(decoded_samples) =
								opus_dec.decode_float(&[], &mut pcm[..AUDIO_FRAME_FLOATS], false)
							{
								let slice = &pcm[..decoded_samples * 2];
								if let Some(tx) = &call_audio {
									push_call_frame(tx, slice);
								} else if let Some(player) = &mut standalone {
									player.push_interleaved(slice);
								}
							}
						}
					}
				}
				last_seq = Some(seq);
				if let Ok(decoded_samples) =
					opus_dec.decode_float(&data[AUDIO_HEADER_LEN..], &mut pcm, false)
				{
					let slice = &pcm[..decoded_samples * 2];
					if let Some(tx) = &call_audio {
						push_call_frame(tx, slice);
					} else if let Some(player) = &mut standalone {
						player.push_interleaved(slice);
					}
				}
			}
		});
	}

	let bytes_rx = Arc::new(AtomicU64::new(0));
	let latest_gop_stream = Arc::new(AtomicU64::new(0));
	let stats_conn = conn.clone();
	let stats_decoder_counters = decoder.counters.clone();
	let stats_lost = lost.clone();
	let stats_pli = pli_tx.clone();
	let stats_bytes = bytes_rx.clone();
	let stats_frames = frames_seen.clone();
	let stats_tx = stats.clone();
	let stats_wake = wake.clone();

	tasks.spawn(async move {
		let mut ticker = tokio::time::interval(Duration::from_millis(500));
		let mut last_tick = Instant::now();
		loop {
			ticker.tick().await;
			if stats_conn.close_reason().is_some() {
				break;
			}
			if let Ok(mut guard) = stats_lost.try_lock()
				&& !guard.is_empty()
			{
				guard.clear();
				let _ = stats_pli.try_send(());
			}
			let elapsed = last_tick.elapsed().as_secs_f64().max(0.1);
			if elapsed >= 1.0 {
				let rx = stats_bytes.swap(0, Ordering::Relaxed);
				let fps_count = stats_frames.swap(0, Ordering::Relaxed);
				let fps = (f64::from(fps_count) / elapsed).round() as u32;
				let bitrate_kbps = ((rx as f64 * 8.0) / elapsed / 1000.0).round() as u32;
				let rtt_ms = stats_conn.rtt().as_millis().min(9999) as u32;
				let hw = stats_decoder_counters.hardware.load(Ordering::Relaxed) > 0;
				stats_tx.send_modify(|s| {
					s.rtt_ms = rtt_ms;
					s.fps = fps;
					s.bitrate_kbps = bitrate_kbps;
					s.hardware_decode = hw;
				});
				(stats_wake)();
				last_tick = Instant::now();
			}
		}
	});

	loop {
		while tasks.try_join_next().is_some() {}
		let stream = match conn.accept_uni().await {
			Ok(stream) => stream,
			Err(_) => break,
		};
		let stream_index = stream.id().index();
		latest_gop_stream.fetch_max(stream_index, Ordering::AcqRel);

		let decoder = decoder.clone();
		let pli_tx = pli_tx.clone();
		let bytes_rx = bytes_rx.clone();
		let latest_gop = latest_gop_stream.clone();

		tasks.spawn(async move {
			read_gop_stream(stream, stream_index, decoder, pli_tx, bytes_rx, latest_gop).await;
		});
	}

	Ok(())
}

async fn read_gop_stream(
	mut stream: RecvStream,
	stream_index: u64,
	decoder: Arc<crate::video_receive::DecoderQueue>,
	pli_tx: mpsc::Sender<()>,
	bytes_rx: Arc<AtomicU64>,
	latest_gop: Arc<AtomicU64>,
) {
	let mut header = [0u8; 9];
	let mut awaiting_keyframe = true;

	loop {
		if latest_gop.load(Ordering::Acquire) > stream_index {
			let _ = stream.stop(0u32.into());
			break;
		}
		if stream.read_exact(&mut header).await.is_err() {
			break;
		}
		let keyframe = header[0] != 0;
		let _timestamp = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
		let len = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
		if len == 0 || len > P2P_MAX_FRAME_BYTES {
			let _ = pli_tx.try_send(());
			let _ = stream.stop(0u32.into());
			break;
		}
		let mut payload = vec![0u8; len];
		if stream.read_exact(&mut payload).await.is_err() {
			let _ = pli_tx.try_send(());
			break;
		}
		if latest_gop.load(Ordering::Acquire) > stream_index {
			let _ = stream.stop(0u32.into());
			break;
		}
		bytes_rx.fetch_add(len as u64, Ordering::Relaxed);
		if awaiting_keyframe && !keyframe {
			continue;
		}
		awaiting_keyframe = false;
		let frame = Encoded {
			codec: Codec::H264,
			user: 1,
			data: payload,
			keyframe,
		};
		match offer(&decoder, frame) {
			Ok(true) => {}
			Ok(false) => {
				awaiting_keyframe = true;
				let _ = pli_tx.try_send(());
			}
			Err(_) => break,
		}
	}
}

/// Standalone lock-free 48 kHz stereo playback for P2P screen audio outside Discord calls.
pub struct P2pAudioPlayer {
	producer: rtrb::Producer<(f32, f32)>,
	_stream: cpal::Stream,
}

impl P2pAudioPlayer {
	pub fn open(
		output_device_id: Option<&str>,
		volume_percent: Arc<AtomicU16>,
	) -> Result<Self, &'static str> {
		let host = cpal::default_host();
		let device = output_device_id
			.and_then(|id| id.parse().ok())
			.and_then(|id| host.device_by_id(&id))
			.or_else(|| host.default_output_device())
			.ok_or("No default audio device is available")?;

		let config = platform::audio::output_config(
			&device,
			platform::audio::OutputConfigPreference::Notification,
		)?;
		let stream_config = config.config();
		#[cfg(target_os = "linux")]
		let stream_config = {
			let mut cfg = stream_config;
			if host.id() == cpal::HostId::PulseAudio {
				cfg.buffer_size = cpal::BufferSize::Fixed(cfg.sample_rate / 50);
			}
			cfg
		};

		let (producer, consumer) = rtrb::RingBuffer::<(f32, f32)>::new(12_000);
		let renderer = StereoRenderer::new(config.sample_rate(), consumer, volume_percent);

		let stream = match config.sample_format() {
			cpal::SampleFormat::F32 => {
				build_stereo_stream::<f32>(&device, &stream_config, renderer)
			}
			cpal::SampleFormat::I16 => {
				build_stereo_stream::<i16>(&device, &stream_config, renderer)
			}
			cpal::SampleFormat::I32 => {
				build_stereo_stream::<i32>(&device, &stream_config, renderer)
			}
			cpal::SampleFormat::U16 => {
				build_stereo_stream::<u16>(&device, &stream_config, renderer)
			}
			_ => return Err("Unsupported speaker sample format"),
		}?;
		stream
			.play()
			.map_err(|_| "Could not start P2P audio output")?;
		Ok(Self {
			producer,
			_stream: stream,
		})
	}

	pub fn push_interleaved(&mut self, samples: &[f32]) {
		// Drop an entire packet on overflow. The output worker trims stale queued samples.
		let (pairs, _) = samples.as_chunks::<2>();
		if self.producer.slots() < pairs.len() {
			return;
		}
		for pair in pairs {
			let l = if pair[0].is_finite() { pair[0] } else { 0.0 };
			let r = if pair[1].is_finite() { pair[1] } else { 0.0 };
			if self.producer.push((l, r)).is_err() {
				break;
			}
		}
	}
}

struct StereoRenderer {
	consumer: rtrb::Consumer<(f32, f32)>,
	volume_percent: Arc<AtomicU16>,
	step: f64,
	phase: f64,
	prev: (f32, f32),
	next: (f32, f32),
	primed: bool,
}

impl StereoRenderer {
	fn new(
		device_rate: u32,
		consumer: rtrb::Consumer<(f32, f32)>,
		volume_percent: Arc<AtomicU16>,
	) -> Self {
		Self {
			consumer,
			volume_percent,
			step: 48_000.0 / f64::from(device_rate.max(8_000)),
			phase: 0.0,
			prev: (0.0, 0.0),
			next: (0.0, 0.0),
			primed: false,
		}
	}

	fn next_stereo(&mut self) -> (f32, f32) {
		if !self.primed {
			if self.consumer.slots() < AUDIO_FRAME_FRAMES {
				return (0.0, 0.0);
			}
			self.primed = true;
			self.prev = self.consumer.pop().unwrap_or((0.0, 0.0));
			self.next = self.consumer.pop().unwrap_or(self.prev);
			self.phase = 0.0;
		}

		// Gently drop excess buffered samples (> 120 ms) to keep P2P audio synced to video.
		while self.consumer.slots() > 5760 {
			let _ = self.consumer.pop();
		}

		while self.phase >= 1.0 {
			self.phase -= 1.0;
			self.prev = self.next;
			match self.consumer.pop() {
				Ok(sample) => self.next = sample,
				Err(_) => {
					self.primed = false;
					return (0.0, 0.0);
				}
			}
		}

		let t = self.phase as f32;
		let l = self.prev.0 + (self.next.0 - self.prev.0) * t;
		let r = self.prev.1 + (self.next.1 - self.prev.1) * t;
		self.phase += self.step;
		(l, r)
	}

	fn render<T>(&mut self, data: &mut [T], channels: usize)
	where
		T: cpal::SizedSample + cpal::FromSample<f32>,
	{
		let vol = self.volume_percent.load(Ordering::Relaxed).min(200);
		if vol == 0 {
			while self.consumer.slots() > AUDIO_FRAME_FRAMES {
				let _ = self.consumer.pop();
			}
			data.fill(T::from_sample(0.0));
			return;
		}
		let gain = f32::from(vol) / 100.0;
		for frame in data.chunks_mut(channels) {
			let (l, r) = self.next_stereo();
			let l = (l * gain).clamp(-1.0, 1.0);
			let r = (r * gain).clamp(-1.0, 1.0);
			match channels {
				0 => {}
				1 => frame[0] = T::from_sample((l + r) * 0.5),
				2 => {
					frame[0] = T::from_sample(l);
					frame[1] = T::from_sample(r);
				}
				_ => {
					frame[0] = T::from_sample(l);
					frame[1] = T::from_sample(r);
					for extra in &mut frame[2..] {
						*extra = T::from_sample(0.0);
					}
				}
			}
		}
	}
}

fn build_stereo_stream<T>(
	device: &cpal::Device,
	config: &cpal::StreamConfig,
	mut renderer: StereoRenderer,
) -> Result<cpal::Stream, &'static str>
where
	T: cpal::SizedSample + cpal::FromSample<f32>,
{
	let channels = usize::from(config.channels);
	device
		.build_output_stream(
			*config,
			move |data: &mut [T], _| renderer.render(data, channels),
			|_| {},
			None,
		)
		.map_err(|_| "Could not open P2P audio playback stream")
}

#[cfg(test)]
mod tests {
	use super::*;
	use openh264::OpenH264API;
	use openh264::encoder::{
		BitRate, Complexity, Encoder as H264Encoder, EncoderConfig, FrameRate, IntraFramePeriod,
		RateControlMode, UsageType,
	};
	use openh264::formats::YUVBuffer;

	#[test]
	fn tailscale_cidr_and_link_validation() {
		assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 64, 0, 1)));
		assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 126, 230, 3)));
		assert!(is_tailscale_ipv4(Ipv4Addr::new(100, 127, 255, 254)));
		assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 63, 255, 255)));
		assert!(!is_tailscale_ipv4(Ipv4Addr::new(100, 128, 0, 0)));
		assert!(!is_tailscale_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
		assert!(!is_tailscale_ipv4(Ipv4Addr::LOCALHOST));

		let target = P2pTarget {
			host: "100.126.230.3".into(),
			port: 49152,
			token: [0xab; 16],
			fingerprint: [0xcd; 32],
		};
		let link = target.to_link();
		assert!(looks_like_p2p_link(&link));
		let parsed = P2pTarget::parse(&link).unwrap();
		assert_eq!(parsed, target);

		let v6 = P2pTarget {
			host: "::1".into(),
			port: 50001,
			token: [0x12; 16],
			fingerprint: [0x34; 32],
		};
		assert_eq!(P2pTarget::parse(&v6.to_link()).unwrap(), v6);

		assert!(P2pTarget::parse("https://100.64.0.1:443?t=00&fp=00").is_err());
		assert!(P2pTarget::parse("serein-p2p://100.64.0.1:0?t=00&fp=00").is_err());
		assert!(P2pTarget::parse("serein-p2p://100.64.0.1:5000?t=short&fp=00").is_err());
		assert!(
			P2pTarget::parse(&format!(
				"serein-p2p://100.64.0.1:5000?t={}&fp=bad",
				"aa".repeat(16)
			))
			.is_err()
		);
	}

	#[test]
	fn quic_loopback_handshake_auth_pinning_and_media_transfer() {
		let rt = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(2)
			.enable_all()
			.build()
			.unwrap();

		rt.block_on(async {
			let (frame_tx, frame_rx) = mpsc::channel(8);
			let ready = Arc::new(AtomicBool::new(false));
			let keyframe = Arc::new(AtomicBool::new(true));
			let bitrate = Arc::new(AtomicU32::new(10_000_000));
			let audio_epoch = Arc::new(AtomicU64::new(1));

			let video = Video {
				settings: client_core::screen::Settings {
					source: client_core::screen::SourceId::Display(1),
					width: 320,
					height: 180,
					fps: 60,
					cursor: true,
					audio: false,
				},
				frames: frame_rx,
				ready: ready.clone(),
				keyframe: keyframe.clone(),
				bitrate,
				audio: None,
				audio_epoch,
			};

			let (host_stats_tx, mut host_stats_rx) = watch::channel(P2pHostStats::default());
			let wake: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {});
			let host_task = tokio::spawn(run_p2p_host_with_bind(
				video,
				P2pHostConfig {
					bind_port: 0,
					initial_bitrate_bps: 10_000_000,
				},
				SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
				Some("127.0.0.1".to_owned()),
				host_stats_tx,
				wake.clone(),
			));

			tokio::time::timeout(Duration::from_secs(5), async {
				loop {
					if host_stats_rx.borrow().state == P2pHostState::Listening {
						break;
					}
					host_stats_rx.changed().await.unwrap();
				}
			})
			.await
			.unwrap();

			let target = P2pTarget::parse(&host_stats_rx.borrow().link).unwrap();

			// 1. Wrong cert fingerprint must fail TLS pinning.
			let mut bad_fp = target.clone();
			bad_fp.fingerprint[0] ^= 0xff;
			let (bad_stats_tx, _bad_stats_rx) = watch::channel(P2pWatchStats::default());
			let err = run_p2p_viewer(
				bad_fp,
				Arc::new(|_| {}),
				Arc::new(AtomicU16::new(100)),
				None,
				bad_stats_tx,
				wake.clone(),
			)
			.await
			.unwrap_err();
			assert!(err.contains("handshake") || err.contains("TLS") || err.contains("timed out"));

			// 2. Wrong token must fail auth.
			let mut bad_tok = target.clone();
			bad_tok.token[0] ^= 0xff;
			let (bad_stats_tx, _bad_stats_rx) = watch::channel(P2pWatchStats::default());
			let err = run_p2p_viewer(
				bad_tok,
				Arc::new(|_| {}),
				Arc::new(AtomicU16::new(100)),
				None,
				bad_stats_tx,
				wake.clone(),
			)
			.await
			.unwrap_err();
			assert!(err.contains("token") || err.contains("auth"));

			// 3. Valid target receives decoded video frame with presentation == None.
			let (decoded_tx, mut decoded_rx) = mpsc::channel::<(u32, u32, bool)>(4);
			let sink: VideoSink = Arc::new(move |frame| {
				let _ = decoded_tx.try_send((
					frame.picture.width,
					frame.picture.height,
					frame.presentation.is_none(),
				));
			});
			let (watch_stats_tx, mut watch_stats_rx) = watch::channel(P2pWatchStats::default());
			let viewer_task = tokio::spawn(run_p2p_viewer(
				target,
				sink,
				Arc::new(AtomicU16::new(100)),
				None,
				watch_stats_tx,
				wake.clone(),
			));

			tokio::time::timeout(Duration::from_secs(5), async {
				loop {
					if ready.load(Ordering::Acquire) {
						break;
					}
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
			})
			.await
			.unwrap();

			// Feed a real H.264 Annex-B keyframe without opening capture or audio devices.
			let cfg = EncoderConfig::new()
				.bitrate(BitRate::from_bps(2_000_000))
				.max_frame_rate(FrameRate::from_hz(60.0))
				.rate_control_mode(RateControlMode::Bitrate)
				.usage_type(UsageType::ScreenContentRealTime)
				.complexity(Complexity::Low)
				.intra_frame_period(IntraFramePeriod::from_num_frames(120));
			let mut enc = H264Encoder::with_api_config(OpenH264API::from_source(), cfg).unwrap();
			let rgba = vec![120u8; 320 * 180 * 4];
			let mut yuv = YUVBuffer::new(320, 180);
			yuv.read_rgb8(openh264::formats::BgraSliceU8::new(&rgba, (320, 180)));
			enc.force_intra_frame();
			let bitstream = enc.encode(&yuv).unwrap();
			let idr = bitstream.to_vec();
			frame_tx
				.send(crate::screen::EncodedFrame {
					data: idr,
					timestamp: 90,
					keyframe: true,
				})
				.await
				.unwrap();

			let (w, h, no_presentation) =
				tokio::time::timeout(Duration::from_secs(5), decoded_rx.recv())
					.await
					.unwrap()
					.unwrap();
			assert_eq!((w, h), (320, 180));
			assert!(no_presentation);

			tokio::time::timeout(Duration::from_secs(2), async {
				loop {
					if watch_stats_rx.borrow().state == P2pWatchState::Watching {
						break;
					}
					watch_stats_rx.changed().await.unwrap();
				}
			})
			.await
			.unwrap();
			assert_eq!(host_stats_rx.borrow().viewers, 1);

			viewer_task.abort();
			assert!(viewer_task.await.unwrap_err().is_cancelled());
			tokio::time::timeout(Duration::from_secs(2), async {
				while host_stats_rx.borrow().viewers != 0 {
					host_stats_rx.changed().await.unwrap();
				}
			})
			.await
			.expect("a viewer leaving must release its slot even when capture is idle");
			assert!(!ready.load(Ordering::Acquire));
			host_task.abort();
		});
	}
}
