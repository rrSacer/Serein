//! Bounded screen-share settings and ephemeral Gateway negotiation events.
use crate::voice;
use model::Id;
use std::net::Ipv4Addr;

pub const MAX_SOURCES: usize = 64;
pub const MAX_SOURCE_NAME_BYTES: usize = 256;
pub const MAX_P2P_ANNOUNCEMENTS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceId {
	/// macOS chooses a display/window only after an explicit Share action.
	SystemPicker,
	/// The Linux desktop chooses the source after an explicit Share action.
	Portal,
	/// Explicit whole-desktop capture on a native X11 session, without a portal.
	X11Desktop,
	Display(u64),
	Window(u64),
}

impl SourceId {
	/// The Linux portal reports the picked display's size before capture starts, so the
	/// capture worker sizes the picture then ([`Settings::fitted_to`]). Other sources of
	/// unknown size never learn it in time.
	pub fn sized_after_pick(self) -> bool {
		matches!(self, Self::Portal)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
	pub id: SourceId,
	pub name: String,
	/// Native pixel size. Zero means the platform has not reported one yet.
	pub width: u32,
	pub height: u32,
	/// Monitor refresh in hertz. Zero means unknown, which hides 90 and 120 fps.
	pub refresh_hz: u32,
}

/// A share picture the picker can offer. `Source` is the monitor or window's own size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
	Source,
	Preset { width: u32, height: u32 },
}

pub const MAX_SHARE_WIDTH: u32 = 3840;
pub const MAX_SHARE_HEIGHT: u32 = 2160;
pub const MAX_P2P_BITRATE_BPS: u32 = 60_000_000;

/// Smallest to largest, so the quality row reads 480p … 2160p, then Source.
const PRESETS: [Resolution; 5] = [
	Resolution::Preset {
		width: 854,
		height: 480,
	},
	Resolution::Preset {
		width: 1280,
		height: 720,
	},
	Resolution::Preset {
		width: 1920,
		height: 1080,
	},
	Resolution::Preset {
		width: 2560,
		height: 1440,
	},
	Resolution::Preset {
		width: 3840,
		height: 2160,
	},
];

/// Resolutions offered for a source, smallest first and Source last. Like Discord, a
/// preset is an upper bound: a smaller source keeps its native size, never upscaled. A
/// source of unknown size offers them all only when it is sized after the pick
/// (`sized_after_pick`); otherwise it keeps 1080p, 720p, and 480p, without Source.
pub fn offered_resolutions(
	width: u32,
	height: u32,
	sized_after_pick: bool,
) -> impl Iterator<Item = Resolution> {
	let all = (width > 0 && height > 0) || sized_after_pick;
	let source = all.then_some(Resolution::Source);
	let presets = PRESETS.into_iter().filter(move |preset| {
		all || matches!(preset, Resolution::Preset { height, .. } if *height <= 1080)
	});
	presets.chain(source)
}

/// 15, 30, and 60 always. 90 and 120 only when the monitor refreshes at least that fast.
pub fn offered_frame_rates(refresh_hz: u32) -> impl Iterator<Item = u32> {
	[15, 30, 60, 90, 120]
		.into_iter()
		.filter(move |fps| *fps <= 60 || refresh_hz >= *fps)
}

/// High-FPS options for P2P gamer screen sharing. Sources that do not expose monitor
/// refresh (`refresh_hz == 0`, such as Linux Wayland portals) still unlock 90–165 fps.
pub fn offered_p2p_frame_rates(refresh_hz: u32) -> impl Iterator<Item = u32> {
	[15, 30, 60, 90, 120, 144, 165]
		.into_iter()
		.filter(move |fps| refresh_hz == 0 || *fps <= 60 || refresh_hz >= *fps)
}

/// Transport chosen inside the native screen-share dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ShareTransport {
	#[default]
	P2p,
	Discord,
}

/// Bitrate ceiling offered for direct P2P streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum P2pBitrate {
	#[default]
	Auto,
	Mbps8,
	Mbps16,
	Mbps25,
	Mbps40,
	Mbps60,
}

impl P2pBitrate {
	pub const ALL: [Self; 6] = [
		Self::Auto,
		Self::Mbps8,
		Self::Mbps16,
		Self::Mbps25,
		Self::Mbps40,
		Self::Mbps60,
	];

	pub fn bps(self, settings: Settings) -> u32 {
		match self {
			Self::Auto => settings.p2p_bit_rate(),
			Self::Mbps8 => 8_000_000,
			Self::Mbps16 => 16_000_000,
			Self::Mbps25 => 25_000_000,
			Self::Mbps40 => 40_000_000,
			Self::Mbps60 => 60_000_000,
		}
	}

	pub fn label(self) -> &'static str {
		match self {
			Self::Auto => "Auto (Gamer)",
			Self::Mbps8 => "8 Mbps",
			Self::Mbps16 => "16 Mbps",
			Self::Mbps25 => "25 Mbps",
			Self::Mbps40 => "40 Mbps",
			Self::Mbps60 => "60 Mbps",
		}
	}
}

/// Live telemetry for an active P2P host share displayed in Serein's native UI.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct P2pShareStats {
	pub link: String,
	pub ip: String,
	pub tailscale: bool,
	pub viewers: u32,
	pub fps: u32,
	pub bitrate_kbps: u32,
}

/// Parsed metadata from a `serein-p2p://` invite URL without opening any socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pLinkInfo {
	pub raw: String,
	pub host: String,
	pub port: u16,
	pub tailscale: bool,
	pub width: Option<u32>,
	pub height: Option<u32>,
	pub fps: Option<u32>,
}

impl P2pLinkInfo {
	pub fn quality_summary(&self) -> Option<String> {
		match (self.height, self.fps) {
			(Some(h), Some(fps)) => Some(format!("{h}p {fps}fps")),
			(Some(h), None) => Some(format!("{h}p")),
			(None, Some(fps)) => Some(format!("{fps} fps")),
			(None, None) => None,
		}
	}
}

/// Active P2P stream announcement observed from a call participant's chat message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2pAnnouncement {
	pub channel: Id,
	pub message_id: Id,
	pub user: Id,
	pub link: P2pLinkInfo,
}

fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
	let octets = ip.octets();
	octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_hex(s: &str, expected_len: usize) -> bool {
	s.len() == expected_len && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parses a `serein-p2p://host:port?t=<32hex>&fp=<64hex>[&w=..&h=..&fps=..]` link.
pub fn parse_p2p_link(input: &str) -> Option<P2pLinkInfo> {
	let trimmed = input
		.trim()
		.trim_matches(|c: char| matches!(c, '<' | '>' | '"' | '\'' | ',' | '.' | ')'));
	let prefix = trimmed.get(..13)?;
	if !prefix.eq_ignore_ascii_case("serein-p2p://") {
		return None;
	}
	let rest = &trimmed[13..];
	let (authority, query) = rest.split_once('?')?;
	let authority = authority.trim_end_matches('/');
	let (host, port_str) = if let Some(bracketed) = authority.strip_prefix('[') {
		let (h, after) = bracketed.split_once(']')?;
		let port_str = after.strip_prefix(':')?;
		(h, port_str)
	} else {
		authority.rsplit_once(':')?
	};
	if host.is_empty() || host.chars().any(char::is_whitespace) {
		return None;
	}
	let port: u16 = port_str.parse().ok().filter(|p| *p != 0)?;
	let mut has_token = false;
	let mut has_fp = false;
	let mut width = None;
	let mut height = None;
	let mut fps = None;
	for pair in query.split('&') {
		let (k, v) = pair.split_once('=')?;
		match k {
			"t" => {
				if !is_hex(v, 32) {
					return None;
				}
				has_token = true;
			}
			"fp" => {
				if !is_hex(v, 64) {
					return None;
				}
				has_fp = true;
			}
			"w" => width = v.parse::<u32>().ok().filter(|n| *n > 0),
			"h" => height = v.parse::<u32>().ok().filter(|n| *n > 0),
			"fps" => fps = v.parse::<u32>().ok().filter(|n| *n > 0),
			_ => {}
		}
	}
	if !has_token || !has_fp {
		return None;
	}
	let tailscale = host.parse::<Ipv4Addr>().is_ok_and(is_tailscale_ipv4);
	Some(P2pLinkInfo {
		raw: format!("serein-p2p://{authority}?{query}"),
		host: host.to_owned(),
		port,
		tailscale,
		width,
		height,
		fps,
	})
}

/// Extracts all valid `serein-p2p://` invite links from message text (bounded to 4).
pub fn extract_p2p_links(content: &str) -> Vec<P2pLinkInfo> {
	let mut links = Vec::new();
	for token in content.split_whitespace() {
		if links.len() >= 4 {
			break;
		}
		if let Some(info) = parse_p2p_link(token)
			&& !links.iter().any(|existing: &P2pLinkInfo| existing.raw == info.raw)
		{
			links.push(info);
		}
	}
	links
}

/// Output size for a choice, `None` when the source cannot use it. For a source sized
/// after the pick this is only the bound (Source: the largest share size), which the
/// capture worker narrows with [`Settings::fitted_to`].
pub fn picture(
	resolution: Resolution,
	width: u32,
	height: u32,
	sized_after_pick: bool,
) -> Option<(u32, u32)> {
	let bound = match resolution {
		Resolution::Source => (MAX_SHARE_WIDTH, MAX_SHARE_HEIGHT),
		Resolution::Preset { width, height } => (width, height),
	};
	if width > 0 && height > 0 {
		return fit_within(bound, width, height);
	}
	(sized_after_pick || matches!(resolution, Resolution::Preset { height, .. } if height <= 1080))
		.then_some(bound)
}

/// The shortest edge scaling may produce: OpenH264, the software fallback, rejects less.
const MIN_SCALED_EDGE: u32 = 16;

/// A source that fits inside the (even) `bound` keeps its native even size; a larger one
/// is scaled down onto one edge of `bound` at its own aspect ratio, so an ultrawide share
/// is not letterboxed into a 16:9 picture. A sliver keeps an encodable minimum edge.
fn fit_within(bound: (u32, u32), width: u32, height: u32) -> Option<(u32, u32)> {
	let (fitted_width, fitted_height) = if width <= bound.0 && height <= bound.1 {
		(width, height)
	} else {
		// The scaled edge rounds to the nearest even pixel.
		let scaled = |edge: u32, to: u32, from: u32| {
			let (edge, to, from) = (u128::from(edge), u128::from(to), u128::from(from));
			u32::try_from((edge * to + from) / (2 * from) * 2)
				.unwrap_or(0)
				.max(MIN_SCALED_EDGE)
		};
		if u64::from(width) * u64::from(bound.1) >= u64::from(height) * u64::from(bound.0) {
			(bound.0, scaled(height, bound.0, width))
		} else {
			(scaled(width, bound.1, height), bound.1)
		}
	};
	let (fitted_width, fitted_height) = (fitted_width & !1, fitted_height & !1);
	(fitted_width >= 2 && fitted_height >= 2).then_some((fitted_width, fitted_height))
}

#[derive(Clone, Copy, Debug)]
pub struct Settings {
	pub source: SourceId,
	pub width: u32,
	pub height: u32,
	pub fps: u32,
	pub cursor: bool,
	/// Share system audio with the screen; call microphone settings are independent.
	pub audio: bool,
}
impl Settings {
	/// Narrows a bound chosen before the pick to the picked source's size, never upscaling.
	pub fn fitted_to(self, width: u32, height: u32) -> Self {
		if width == 0 || height == 0 {
			return self;
		}
		let Some((width, height)) = fit_within((self.width, self.height), width, height) else {
			return self;
		};
		let fitted = Self {
			width,
			height,
			..self
		};
		if fitted.valid() { fitted } else { self }
	}

	pub fn valid(self) -> bool {
		!matches!(self.source, SourceId::Display(0) | SourceId::Window(0))
			&& self.width >= 2
			&& self.height >= 2
			&& self.width <= MAX_SHARE_WIDTH
			&& self.height <= MAX_SHARE_HEIGHT
			&& self.width.is_multiple_of(2)
			&& self.height.is_multiple_of(2)
			&& matches!(self.fps, 15 | 30 | 60 | 90 | 120 | 144 | 165)
	}

	pub fn bit_rate(self) -> u32 {
		let pixels = u64::from(self.width) * u64::from(self.height);
		let base = if pixels <= 854 * 480 {
			2_000_000
		} else if pixels <= 1280 * 720 {
			4_000_000
		} else if pixels <= 1920 * 1080 {
			8_000_000
		} else if pixels >= 3840 * 2160 {
			16_000_000
		} else {
			let scaled = 8_000_000u64 * pixels / (1920 * 1080);
			u32::try_from(scaled.min(12_000_000)).unwrap_or(12_000_000)
		};
		let scale = match self.fps {
			120 | 144 | 165 => 4,
			90 => 3,
			60 => 2,
			_ => 1,
		};
		base.saturating_mul(scale).min(16_000_000)
	}

	/// Target bitrate for gamer P2P streams (no Discord 16 Mbps cap).
	pub fn p2p_bit_rate(self) -> u32 {
		let pixels = u64::from(self.width) * u64::from(self.height);
		let base: u64 = if pixels <= 854 * 480 {
			4_000_000
		} else if pixels <= 1280 * 720 {
			8_000_000
		} else if pixels <= 1920 * 1080 {
			16_000_000
		} else if pixels <= 2560 * 1440 {
			25_000_000
		} else {
			36_000_000
		};
		let scaled = match self.fps {
			144 | 165 => base.saturating_mul(2),
			120 => base.saturating_mul(16) / 10,
			90 => base.saturating_mul(14) / 10,
			60 => base.saturating_mul(125) / 100,
			_ => base,
		};
		u32::try_from(scaled.clamp(2_000_000, u64::from(MAX_P2P_BITRATE_BPS)))
			.unwrap_or(MAX_P2P_BITRATE_BPS)
	}
}

#[derive(Debug)]
pub enum Event {
	Created {
		rtc_server: Id,
		rtc_channel: Id,
	},
	Server {
		token: Option<voice::Secret>,
		endpoint: Option<String>,
	},
	/// The stream is gone. `reason` names Discord's cause when it sent one we recognise.
	Deleted {
		reason: Option<&'static str>,
	},
	Failed(&'static str),
	/// Discord's latest viewer count for this device's own stream (unofficial `STREAM_UPDATE`).
	Viewers(u16),
}
impl Event {
	pub(crate) fn bytes(&self) -> usize {
		match self {
			Self::Server { token, endpoint } => {
				token.as_ref().map_or(0, voice::Secret::bytes)
					+ endpoint.as_ref().map_or(0, String::capacity)
			}
			_ => 0,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn p2p_frame_rates_and_bitrates_unlock_gamer_tiers() {
		let portal_rates: Vec<_> = offered_p2p_frame_rates(0).collect();
		assert_eq!(portal_rates, [15, 30, 60, 90, 120, 144, 165]);
		let monitor_144: Vec<_> = offered_p2p_frame_rates(144).collect();
		assert_eq!(monitor_144, [15, 30, 60, 90, 120, 144]);
		let hd_144 = Settings {
			source: SourceId::Portal,
			width: 1920,
			height: 1080,
			fps: 144,
			cursor: true,
			audio: true,
		};
		assert!(hd_144.valid());
		assert!(hd_144.p2p_bit_rate() >= 30_000_000);
		assert_eq!(P2pBitrate::Mbps60.bps(hd_144), 60_000_000);
	}

	#[test]
	fn p2p_link_parser_validates_tailscale_and_quality() {
		let raw = "Assistir agora: serein-p2p://100.64.12.9:45123?t=0123456789abcdef0123456789abcdef&fp=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef&w=1920&h=1080&fps=120";
		let links = extract_p2p_links(raw);
		assert_eq!(links.len(), 1);
		assert!(links[0].tailscale);
		assert_eq!(links[0].port, 45123);
		assert_eq!(links[0].quality_summary().as_deref(), Some("1080p 120fps"));
		assert!(parse_p2p_link("serein-p2p://127.0.0.1:45123?t=short&fp=bad").is_none());
	}
}
