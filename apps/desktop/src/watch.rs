//! Desktop ownership for watching one other participant's screen share (Discord or P2P) or a
//! direct `serein-p2p://` invitation. Frames are decoded off the render thread and never written
//! to disk.
use crate::gpu_video::Wake;
use client_core::{Command, Event, State, screen, voice};
use discord_voice::{
	Identity, Status,
	p2p_stream::{self, P2pTarget, P2pWatchState, P2pWatchStats},
};
use eframe::egui;
use model::Id;
use std::{
	borrow::Cow,
	sync::{
		Arc, Mutex,
		atomic::{AtomicU16, Ordering},
	},
	time::{Duration, Instant},
};
use tokio::{runtime::Runtime, sync::watch, task::JoinHandle};
use zeroize::Zeroizing;

const SIGNAL_TIMEOUT: Duration = Duration::from_secs(30);
// Eight UHD YUV pictures plus the displayed picture fit without increasing the item bound.
const DECODED_BUDGET: usize = 128 * 1024 * 1024;
const MAX_ENDED_LINKS: usize = 32;

/// Latest stream picture and whether the UI still has to upload it.
type Slot = Option<(platform::video::Picture, bool)>;

/// Replace the latest picture in place: a plain copy of the decoder's planes into one reused
/// allocation. Colour conversion happens on the GPU when the UI uploads it.
fn store_frame(slot: &mut Slot, frame: discord_voice::RemoteFrame<'_>) -> bool {
	let picture = frame.picture;
	if !picture.is_valid() {
		return false;
	}
	let len = picture.data.len();
	let mut data = slot.take().map(|(old, _)| old.data).unwrap_or_default();
	if data.capacity() > 1024 * 1024 && data.capacity() > len.saturating_mul(4) {
		// Release a previous large resolution while keeping ordinary resize reuse.
		data = Vec::new();
	}
	data.clear();
	// Exact growth: never double a previous resolution's allocation beyond the frame.
	data.reserve_exact(len);
	data.extend_from_slice(picture.data);
	*slot = Some((picture.with_data(data), true));
	true
}

// Decode early, display on the audio/device clock. Only decoded pictures may be
// skipped here: the H.264 decoder has already consumed their reference state.
#[derive(Default)]
struct Scheduled {
	latest: Slot,
	pending: std::collections::VecDeque<(platform::video::Picture, discord_voice::Presentation)>,
	bytes: usize,
}
impl Scheduled {
	fn store(&mut self, frame: discord_voice::RemoteFrame<'_>) -> bool {
		let Some(presentation) = frame.presentation.clone() else {
			return store_frame(&mut self.latest, frame);
		};
		if !presentation.is_current() || !frame.picture.is_valid() {
			return false;
		}
		let length = frame.picture.data.len();
		if length > DECODED_BUDGET {
			return false;
		}
		let old = if self.latest.as_ref().is_some_and(|(_, fresh)| !*fresh) {
			self.latest.take()
		} else {
			None
		};
		let mut data = old.map(|(picture, _)| picture.data).unwrap_or_default();
		if data.capacity() > length.saturating_mul(4) {
			data = Vec::new();
		}
		let required = data.capacity().max(length);
		while self.pending.len() >= 8
			|| self.bytes
				+ required + self
				.latest
				.as_ref()
				.map_or(0, |(picture, _)| picture.data.capacity())
				> DECODED_BUDGET
		{
			let Some((old, _)) = self.pending.pop_front() else {
				return false;
			};
			self.bytes -= old.data.capacity();
		}
		data.clear();
		data.reserve_exact(length);
		data.extend_from_slice(frame.picture.data);
		self.bytes += data.capacity();
		self.pending
			.push_back((frame.picture.with_data(data), presentation));
		true
	}
	/// When the ui next has something to show: `None` for now, else the deadline of the
	/// earliest queued picture.
	fn due(&self, now: Instant) -> Option<Instant> {
		if self.latest.as_ref().is_some_and(|(_, fresh)| *fresh) {
			return None;
		}
		let (_, stamp) = self.pending.front()?;
		let deadline = stamp.deadline(now);
		(stamp.is_current() && deadline > now).then_some(deadline)
	}
	fn advance(&mut self, now: Instant) -> Option<Instant> {
		while let Some((_, stamp)) = self.pending.front() {
			if stamp.is_current() && stamp.deadline(now) > now {
				return Some(stamp.deadline(now));
			}
			let (picture, stamp) = self.pending.pop_front().expect("front exists");
			self.bytes -= picture.data.capacity();
			if stamp.is_current() {
				self.latest = Some((picture, true));
			}
		}
		None
	}
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Context {
	generation: u64,
	channel: Id,
	request: u64,
	stream_request: u64,
	streamer: Id,
}

#[derive(Clone, PartialEq, Eq)]
enum WatchSource {
	Discord {
		generation: u64,
		channel: Id,
		request: u64,
		streamer: Id,
	},
	InCallP2p {
		generation: u64,
		channel: Id,
		request: u64,
		streamer: Id,
		link: String,
	},
	DirectP2p {
		link: String,
		label: String,
	},
}

struct Pending {
	context: Context,
	user: Id,
	peer: Option<Id>,
	session: Zeroizing<String>,
	identity: Arc<Identity>,
	audio: Option<std::sync::mpsc::SyncSender<discord_voice::PlaybackFrame>>,
	rtc: Option<(Id, Id)>,
	server: Option<(voice::Secret, String)>,
	started: Instant,
}
#[derive(Clone)]
enum Notice {
	Status(&'static str),
	Ended,
	Failed(Cow<'static, str>),
}
enum LiveKind {
	Discord {
		context: Context,
		events: watch::Receiver<Option<Notice>>,
	},
	P2p {
		source: WatchSource,
		events: watch::Receiver<Option<Notice>>,
		stats: watch::Receiver<P2pWatchStats>,
		volume: Arc<AtomicU16>,
		link: String,
	},
}
struct Live {
	task: JoinHandle<()>,
	kind: LiveKind,
	frames: Arc<Mutex<Scheduled>>,
	wake: Wake,
}

/// Stores the streamer's pictures and asks for a frame when the next one is due. Only the
/// picture changes then, so the request is for a paint-only frame.
fn sink(frames: Arc<Mutex<Scheduled>>, expected_user: Option<u64>, wake: Wake) -> discord_voice::VideoSink {
	Arc::new(move |frame: discord_voice::RemoteFrame| {
		if let Some(streamer) = expected_user
			&& frame.user != streamer
		{
			return;
		}
		let now = Instant::now();
		let due = frames
			.lock()
			.ok()
			.and_then(|mut slot| slot.store(frame).then(|| slot.due(now)));
		match due {
			Some(Some(deadline)) => wake.picture_after(deadline.saturating_duration_since(now)),
			Some(None) => wake.picture(),
			None => {}
		}
	})
}

/// `--demo-call-stream-live`: the offline stream stage receives generated pictures through
/// the same queue, deadlines and wake-ups as a real stream, so playback can be checked and
/// measured without a call.
#[cfg(feature = "demo")]
fn synthetic_stream() -> bool {
	static LIVE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
	*LIVE.get_or_init(|| std::env::args().any(|arg| arg == "--demo-call-stream-live"))
}
#[cfg(not(feature = "demo"))]
fn synthetic_stream() -> bool {
	false
}

#[derive(Default)]
pub(super) struct Watch {
	pending: Option<Pending>,
	live: Option<Live>,
	/// The streamer stopped or the view failed; cleared on the next poll.
	ended: Option<(ui::design::Level, Cow<'static, str>, Option<String>)>,
	sequence: u64,
	status: &'static str,
	/// GPU texture behind `ui.voice_stream_view`.
	texture: crate::gpu_video::VideoTexture,
	/// Asks the renderer for a frame that only presents a new picture.
	presenter: Option<eframe::PaintOnlyRequester>,
}
impl Watch {
	/// Hands over the renderer's paint-only handle once it exists; `None` keeps full repaints.
	pub fn set_presenter(&mut self, presenter: Option<eframe::PaintOnlyRequester>) {
		if self.presenter.is_none() {
			self.presenter = presenter;
		}
	}
	/// A stream is being received; its pictures are presented by [`Self::paint_only`].
	pub fn live(&self) -> bool {
		self.live.is_some()
	}
	/// Shows the stream's due picture in the texture the last ui pass drew, without a ui
	/// pass. `false` when the ui has to run instead: a first picture or another size.
	pub fn paint_only(&mut self, ctx: &egui::Context) -> bool {
		let Some(live) = &self.live else {
			return true;
		};
		// The decoder holds the lock only while it copies a picture in; its own wake follows.
		let Ok(mut slot) = live.frames.try_lock() else {
			return true;
		};
		let now = Instant::now();
		if let Some(deadline) = slot.advance(now) {
			live.wake
				.picture_after(deadline.saturating_duration_since(now));
		}
		match slot.latest.as_mut() {
			Some((picture, fresh)) if *fresh => {
				if !self.texture.fits_picture(&picture.borrow()) {
					return false;
				}
				*fresh = false;
				self.texture
					.upload(ctx, "remote-stream", picture.borrow())
					.is_some()
			}
			_ => true,
		}
	}
	pub fn stop(&mut self) {
		self.pending = None;
		self.ended = None;
		if let Some(live) = self.live.take() {
			live.task.abort();
		}
		// Logout stops polling, so release the GPU picture here; disposal waits a frame.
		self.texture = Default::default();
	}
	fn discord_context(&self) -> Option<Context> {
		self.pending
			.as_ref()
			.map(|pending| pending.context)
			.or_else(|| match self.live.as_ref().map(|live| &live.kind) {
				Some(LiveKind::Discord { context, .. }) => Some(*context),
				_ => None,
			})
	}
	fn current_source(&self) -> Option<WatchSource> {
		self.pending
			.as_ref()
			.map(|pending| WatchSource::Discord {
				generation: pending.context.generation,
				channel: pending.context.channel,
				request: pending.context.request,
				streamer: pending.context.streamer,
			})
			.or_else(|| match self.live.as_ref().map(|live| &live.kind) {
				Some(LiveKind::Discord { context, .. }) => Some(WatchSource::Discord {
					generation: context.generation,
					channel: context.channel,
					request: context.request,
					streamer: context.streamer,
				}),
				Some(LiveKind::P2p { source, .. }) => Some(source.clone()),
				None => None,
			})
	}
	/// Take negotiation secrets before the UI reduces the event. Nothing is persisted.
	pub fn observe(&mut self, state: &State, event: &mut Event) {
		let Event::Voice(voice::Event::Watch {
			channel,
			request,
			stream_request,
			streamer,
			event,
		}) = event
		else {
			return;
		};
		let Some(context) = self.discord_context() else {
			return;
		};
		if context.generation != state.generation
			|| (
				context.channel,
				context.request,
				context.stream_request,
				context.streamer,
			) != (*channel, *request, *stream_request, *streamer)
		{
			return;
		}
		match event {
			screen::Event::Created {
				rtc_server,
				rtc_channel,
			} => {
				if let Some(pending) = &mut self.pending {
					pending.rtc = Some((*rtc_server, *rtc_channel));
				}
			}
			screen::Event::Server { token, endpoint } => {
				if let Some(pending) = &mut self.pending {
					match (token.take(), endpoint.take()) {
						(Some(token), Some(endpoint)) => pending.server = Some((token, endpoint)),
						// A null endpoint means Discord is still allocating the stream server.
						(_, None) => pending.server = None,
						(None, Some(_)) => {
							self.ended = Some((
								ui::design::Level::Warning,
								Cow::Borrowed("Discord omitted the stream connection token"),
								None,
							));
						}
					}
				}
			}
			screen::Event::Deleted { reason } => {
				self.ended = Some((
					ui::design::Level::Info,
					Cow::Borrowed(reason.unwrap_or("The stream ended")),
					None,
				));
			}
			screen::Event::Failed(message) => {
				self.ended = Some((ui::design::Level::Warning, Cow::Borrowed(message), None));
			}
			screen::Event::Viewers(_) => {}
		}
	}
	pub fn poll(
		&mut self,
		runtime: &Runtime,
		state: &mut State,
		ui: &mut ui::MessagingUi,
		ctx: &egui::Context,
		call: Option<super::screen::Call<'_>>,
		audio: Option<std::sync::mpsc::SyncSender<discord_voice::PlaybackFrame>>,
	) -> Option<Command> {
		let mut direct_requested = false;
		if let Some(request) = ui.p2p_watch_request.take() {
			match request {
				Some((link, label)) => {
					direct_requested = true;
					ui.p2p_ended_links.retain(|item| item != &link);
					state.stop_watching();
					ui.p2p_watch = ui::p2p_cards::DirectWatchState {
						active: true,
						link,
						label,
						status: "Connecting to P2P stream…".to_owned(),
						..Default::default()
					};
				}
				None => {
					ui.p2p_watch = Default::default();
					if matches!(
						self.live.as_ref().map(|live| &live.kind),
						Some(LiveKind::P2p {
							source: WatchSource::DirectP2p { .. },
							..
						})
					) {
						self.stop();
						self.status = "Stopped watching";
					}
				}
			}
		}

		let in_call_wanted = state.voice.active.as_ref().and_then(|active| {
			let streamer = active.watching?;
			// The separate stream transport survives call rekeys and voice resumption.
			(active.phase != voice::Phase::Failed).then(|| {
				let discord_streaming = active
					.participants
					.iter()
					.find(|p| p.user == streamer)
					.is_some_and(|p| p.streaming);
				if !discord_streaming
					&& let Some(ann) = state.p2p_stream_for(active.channel, streamer)
				{
					WatchSource::InCallP2p {
						generation: state.generation,
						channel: active.channel,
						request: active.request,
						streamer,
						link: ann.link.raw.clone(),
					}
				} else {
					WatchSource::Discord {
						generation: state.generation,
						channel: active.channel,
						request: active.request,
						streamer,
					}
				}
			})
		});
		if in_call_wanted.is_some() && !direct_requested && ui.p2p_watch.active {
			ui.p2p_watch = Default::default();
		}
		let wanted = in_call_wanted.or_else(|| {
			ui.p2p_watch.active.then(|| WatchSource::DirectP2p {
				link: ui.p2p_watch.link.clone(),
				label: ui.p2p_watch.label.clone(),
			})
		});

		let current = self.current_source();
		let discord_context = self.discord_context();
		let mut command = None;
		let synthetic = state.demo && synthetic_stream();
		if let Some(current_source) = current
			&& ((state.demo && !synthetic) || wanted.as_ref() != Some(&current_source))
		{
			self.stop();
			self.status = "Stopped watching";
			if let Some(context) = discord_context
				&& context.generation == state.generation
				&& !state.demo
			{
				command = Some(Command::Voice(voice::Command::StopWatching {
					channel: context.channel,
					request: context.request,
					stream_request: context.stream_request,
				}));
			}
		}
		if let Some((level, message, ended_link)) = self.ended.take() {
			let discord_context = self.discord_context();
			let was_direct = matches!(
				self.live.as_ref().map(|live| &live.kind),
				Some(LiveKind::P2p {
					source: WatchSource::DirectP2p { .. },
					..
				})
			) || ended_link
				.as_ref()
				.is_some_and(|link| ui.p2p_watch.active && ui.p2p_watch.link == *link);
			let was_in_call = matches!(
				self.live.as_ref().map(|live| &live.kind),
				Some(LiveKind::P2p {
					source: WatchSource::InCallP2p { .. },
					..
				})
			) || discord_context.is_some();
			self.stop();
			self.status = "The stream ended";
			// Said once; the stage keeps no line for a view that already ended.
			ui.toasts.push(level, message);
			if let Some(link) = ended_link {
				if !ui.p2p_ended_links.contains(&link) {
					if ui.p2p_ended_links.len() >= MAX_ENDED_LINKS {
						ui.p2p_ended_links.remove(0);
					}
					ui.p2p_ended_links.push(link.clone());
				}
				state.remove_p2p_stream_link(&link);
			}
			if was_direct {
				ui.p2p_watch = Default::default();
			}
			if was_in_call {
				state.stop_watching();
			}
			ui.voice_stream_view = None;
			self.texture = Default::default();
			ui.voice_stream_status = if wanted.is_some() && !was_direct && !was_in_call {
				self.status
			} else {
				""
			};
			return command.or_else(|| {
				let context = discord_context.filter(|context| context.generation == state.generation)?;
				Some(Command::Voice(voice::Command::StopWatching {
					channel: context.channel,
					request: context.request,
					stream_request: context.stream_request,
				}))
			});
		}
		if state.demo && !synthetic {
			if ui.p2p_watch.active {
				ui.p2p_watch.status = "Offline preview · no stream is received".to_owned();
			}
			ui.voice_stream_status = if wanted.is_some() {
				"Offline preview · no stream is received"
			} else {
				""
			};
			return command;
		}
		#[cfg(feature = "demo")]
		if synthetic
			&& let Some(WatchSource::Discord {
				generation,
				channel,
				request,
				streamer,
			}) = wanted.clone()
			&& self.live.is_none()
		{
			self.sequence = self.sequence.wrapping_add(1);
			let context = Context {
				generation,
				channel,
				request,
				stream_request: self.sequence,
				streamer,
			};
			self.start_synthetic(runtime, context, ctx);
		}
		if !synthetic
			&& self.current_source().is_none()
			&& command.is_none()
			&& let Some(wanted_source) = wanted.clone()
		{
			match wanted_source {
				WatchSource::Discord {
					generation,
					channel,
					request,
					streamer,
				} => {
					let Some(call) = call.filter(|call| {
						call.generation == generation
							&& call.channel == channel
							&& call.request == request
					}) else {
						ui.voice_stream_status = "Connect the call before watching a stream";
						return None;
					};
					self.sequence = self.sequence.wrapping_add(1);
					let context = Context {
						generation,
						channel,
						request,
						stream_request: self.sequence,
						streamer,
					};
					self.pending = Some(Pending {
						context,
						user: call.user,
						peer: call.peer,
						session: Zeroizing::new(call.session.to_owned()),
						identity: call.identity,
						audio,
						rtc: None,
						server: None,
						started: Instant::now(),
					});
					self.status = "Requesting the stream…";
					command = Some(Command::Voice(voice::Command::WatchStream {
						channel,
						request,
						stream_request: context.stream_request,
						streamer,
					}));
				}
				WatchSource::InCallP2p {
					generation,
					channel,
					request,
					..
				} => {
					let Some(_call) = call.filter(|call| {
						call.generation == generation
							&& call.channel == channel
							&& call.request == request
					}) else {
						ui.voice_stream_status = "Connect the call before watching a stream";
						return None;
					};
					if let Err((error, link)) = self.start_p2p(
						runtime,
						wanted_source,
						audio,
						ui.voice_output.clone(),
						ui.voice_stream_volume(),
						ctx,
					) {
						self.ended = Some((ui::design::Level::Warning, error, Some(link)));
						ctx.request_repaint();
					}
				}
				WatchSource::DirectP2p { .. } => {
					if let Err((error, link)) = self.start_p2p(
						runtime,
						wanted_source,
						audio,
						ui.voice_output.clone(),
						ui.voice_stream_volume(),
						ctx,
					) {
						self.ended = Some((ui::design::Level::Warning, error, Some(link)));
						ctx.request_repaint();
					}
				}
			}
		}
		if let Some(pending) = &self.pending {
			if pending.started.elapsed() >= SIGNAL_TIMEOUT {
				self.ended = Some((
					ui::design::Level::Warning,
					Cow::Borrowed("Discord did not provide the stream connection; try again"),
					None,
				));
				ctx.request_repaint();
			} else {
				ctx.request_repaint_after(SIGNAL_TIMEOUT.saturating_sub(pending.started.elapsed()));
			}
		}
		if self
			.pending
			.as_ref()
			.is_some_and(|pending| pending.rtc.is_some() && pending.server.is_some())
		{
			let pending = self.pending.take().expect("complete stream negotiation");
			if let Err(error) = self.start(runtime, pending, ctx) {
				self.ended = Some((ui::design::Level::Warning, Cow::Borrowed(error), None));
			}
		}
		if let Some(live) = &mut self.live {
			let stream_volume = ui.voice_stream_volume();
			match &mut live.kind {
				LiveKind::Discord { events, .. } => {
					match events.borrow_and_update().clone() {
						Some(Notice::Status(status)) => self.status = status,
						Some(Notice::Ended) => {
							self.ended = Some((
								ui::design::Level::Info,
								Cow::Borrowed("The stream ended"),
								None,
							));
						}
						Some(Notice::Failed(error)) => {
							self.ended = Some((ui::design::Level::Warning, error, None));
						}
						None => {}
					}
					if live.task.is_finished() && self.ended.is_none() {
						self.ended = Some((
							ui::design::Level::Warning,
							Cow::Borrowed("The stream connection ended"),
							None,
						));
					}
				}
				LiveKind::P2p {
					source,
					events,
					stats,
					volume,
					link,
				} => {
					volume.store(stream_volume, Ordering::Relaxed);
					let p2p_stats = stats.borrow_and_update().clone();
					self.status = match p2p_stats.state {
						P2pWatchState::Connecting => "Connecting to P2P stream…",
						P2pWatchState::Authenticating => "Authenticating P2P session…",
						P2pWatchState::WaitingVideo => "P2P connected · waiting for keyframe…",
						P2pWatchState::Watching => "Watching P2P stream",
						P2pWatchState::Failed => "P2P stream failed",
					};
					if matches!(source, WatchSource::DirectP2p { .. }) {
						ui.p2p_watch.status = p2p_stats.status;
						ui.p2p_watch.width = p2p_stats.width;
						ui.p2p_watch.height = p2p_stats.height;
						ui.p2p_watch.fps = p2p_stats.fps;
						ui.p2p_watch.bitrate_kbps = p2p_stats.bitrate_kbps;
						ui.p2p_watch.rtt_ms = p2p_stats.rtt_ms;
					}
					match events.borrow_and_update().clone() {
						Some(Notice::Status(status)) => self.status = status,
						Some(Notice::Ended) => {
							self.ended = Some((
								ui::design::Level::Info,
								Cow::Borrowed("The P2P stream ended"),
								Some(link.clone()),
							));
						}
						Some(Notice::Failed(error)) => {
							self.ended = Some((
								ui::design::Level::Warning,
								error,
								Some(link.clone()),
							));
						}
						None => {}
					}
					if live.task.is_finished() && self.ended.is_none() {
						self.ended = Some((
							ui::design::Level::Info,
							Cow::Borrowed("The P2P stream ended"),
							Some(link.clone()),
						));
					}
				}
			}
			// Uploading copies the planes into GPU staging, so it runs under the slot lock
			// and the decoder keeps refilling the same allocation.
			if let Ok(mut slot) = live.frames.try_lock() {
				let now = Instant::now();
				if let Some(deadline) = slot.advance(now) {
					live.wake
						.picture_after(deadline.saturating_duration_since(now));
				}
				if let Some((picture, fresh)) = slot.latest.as_mut()
					&& std::mem::take(fresh)
					&& let Some(texture) =
						self.texture.upload(ctx, "remote-stream", picture.borrow())
				{
					ui.voice_stream_view = Some(texture);
					self.status = "Watching the stream";
				}
			}
		} else {
			ui.voice_stream_view = None;
			self.texture = Default::default();
		}
		ui.voice_stream_status = if wanted.is_some() { self.status } else { "" };
		command
	}

	fn start_p2p(
		&mut self,
		runtime: &Runtime,
		source: WatchSource,
		audio: Option<std::sync::mpsc::SyncSender<discord_voice::PlaybackFrame>>,
		output_device: Option<String>,
		initial_volume: u16,
		ctx: &egui::Context,
	) -> Result<(), (Cow<'static, str>, String)> {
		let link = match &source {
			WatchSource::InCallP2p { link, .. } | WatchSource::DirectP2p { link, .. } => {
				link.clone()
			}
			WatchSource::Discord { .. } => unreachable!("Discord source in start_p2p"),
		};
		let target = P2pTarget::parse(&link).map_err(|err| (Cow::Borrowed(err), link.clone()))?;
		let frames = Arc::new(Mutex::new(Scheduled::default()));
		let pictures = Wake::new(ctx, self.presenter.clone());
		let video_sink = sink(frames.clone(), None, pictures.clone());
		let (send, events) = watch::channel(None);
		let (stats_tx, stats_rx) = watch::channel(P2pWatchStats::default());
		let volume = Arc::new(AtomicU16::new(initial_volume));
		let viewer_volume = volume.clone();
		let wake_task = ctx.clone();
		let wake_viewer = Arc::new({
			let wake = ctx.clone();
			move || wake.request_repaint()
		});
		let task = runtime.spawn(async move {
			let result = p2p_stream::run_p2p_viewer_with_call_audio(
				target,
				video_sink,
				viewer_volume,
				output_device,
				audio,
				stats_tx,
				wake_viewer,
			)
			.await;
			match result {
				Ok(()) => {
					send.send_replace(Some(Notice::Ended));
				}
				Err(error) => {
					send.send_replace(Some(Notice::Failed(Cow::Owned(error))));
				}
			}
			wake_task.request_repaint();
		});
		self.status = "Connecting to P2P stream…";
		self.live = Some(Live {
			task,
			kind: LiveKind::P2p {
				source,
				events,
				stats: stats_rx,
				volume,
				link,
			},
			frames,
			wake: pictures,
		});
		Ok(())
	}

	fn start(
		&mut self,
		runtime: &Runtime,
		mut pending: Pending,
		ctx: &egui::Context,
	) -> Result<(), &'static str> {
		let (rtc_server, rtc_channel) = pending.rtc.take().ok_or("Missing stream RTC identity")?;
		let (token, endpoint) = pending.server.take().ok_or("Missing stream server")?;
		let session = voice::Secret::new(pending.session.to_string())
			.map_err(|_| "Invalid stream voice session")?;
		let credentials = voice::VoiceConnection {
			channel: rtc_channel,
			guild: Some(rtc_server),
			user: pending.user,
			peer: pending.peer,
			session,
			token,
			endpoint,
			request: pending.context.stream_request,
		};
		let frames = Arc::new(Mutex::new(Scheduled::default()));
		let pictures = Wake::new(ctx, self.presenter.clone());
		let sink = sink(frames.clone(), Some(pending.context.streamer.0), pictures.clone());
		let (send, events) = watch::channel(None);
		let wake = ctx.clone();
		let identity = pending.identity;
		let audio = pending.audio;
		let task = runtime.spawn(async move {
			let (status_send, status_wake) = (send.clone(), wake.clone());
			let result =
				discord_voice::watch_stream(credentials, identity, sink, audio, move |event| {
					let status = match event {
						Status::Connecting => "Connecting to the stream…",
						Status::Discovering => "Checking the stream network…",
						Status::TransportReady | Status::Securing => "Securing the stream…",
						Status::WaitingForPeer => "Waiting for the streamer…",
						Status::Ready { .. } => "Stream secured · waiting for video",
						Status::RemoteAudio
						| Status::Speaking(_)
						| Status::CameraAvailable(_)
						| Status::Latency(_) => {
							return Ok(());
						}
					};
					status_send.send_replace(Some(Notice::Status(status)));
					status_wake.request_repaint();
					Ok(())
				})
				.await;
			if let Err(error) = result {
				send.send_replace(Some(Notice::Failed(Cow::Borrowed(error))));
			}
			wake.request_repaint();
		});
		self.status = "Connecting to the stream…";
		self.live = Some(Live {
			task,
			kind: LiveKind::Discord {
				context: pending.context,
				events,
			},
			frames,
			wake: pictures,
		});
		Ok(())
	}
	/// Generated 1080p60 pictures, stamped 80 ms ahead like a jitter-buffered stream.
	#[cfg(feature = "demo")]
	fn start_synthetic(&mut self, runtime: &Runtime, context: Context, ctx: &egui::Context) {
		use platform::video::{Color, Layout, Picture};
		const SIZE: (u32, u32) = (1920, 1080);
		let frames = Arc::new(Mutex::new(Scheduled::default()));
		let wake = Wake::new(ctx, self.presenter.clone());
		let sink = sink(frames.clone(), Some(context.streamer.0), wake.clone());
		let user = context.streamer.0;
		let task = runtime.spawn(async move {
			let (width, height) = (SIZE.0 as usize, SIZE.1 as usize);
			let mut data = vec![128_u8; width * height * 3 / 2];
			let mut ticks = tokio::time::interval(Duration::from_micros(16_667));
			let mut frame = 0_usize;
			loop {
				ticks.tick().await;
				frame = frame.wrapping_add(1);
				// A diagonal ramp that moves a little every picture.
				for (y, row) in data[..width * height].chunks_exact_mut(width).enumerate() {
					let start = (y / 4).wrapping_add(frame.wrapping_mul(3)) as u8;
					for (x, luma) in row.iter_mut().enumerate() {
						*luma = start.wrapping_add((x / 8) as u8);
					}
				}
				sink(discord_voice::RemoteFrame {
					presentation: Some(discord_voice::Presentation::new(
						Instant::now() + Duration::from_millis(80),
					)),
					user,
					picture: Picture {
						width: SIZE.0,
						height: SIZE.1,
						layout: Layout::Nv12,
						color: Color::WEBRTC,
						rotation: 0,
						data: data.as_slice(),
					},
				});
			}
		});
		self.status = "Watching the stream";
		self.live = Some(Live {
			task,
			kind: LiveKind::Discord {
				context,
				events: watch::channel(None).1,
			},
			frames,
			wake,
		});
	}
}
impl Drop for Watch {
	fn drop(&mut self) {
		self.stop();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn watch_survives_call_recovery_until_its_selection_ends() {
		let runtime = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();
		let mut state = test_support::voice_demo_state();
		state.demo = false;
		state.watch_stream(Id(3)).unwrap();
		let call = state.voice.active.as_ref().unwrap();
		let context = Context {
			generation: state.generation,
			channel: call.channel,
			request: call.request,
			stream_request: 2,
			streamer: Id(3),
		};
		let mut ui = ui::MessagingUi::default();
		let ctx = egui::Context::default();
		for failed in [false, true] {
			state.voice.active.as_mut().unwrap().watching = Some(context.streamer);
			let (_send, events) = watch::channel(None);
			let mut watch = Watch {
				pending: None,
				live: Some(Live {
					task: runtime.spawn(std::future::pending()),
					kind: LiveKind::Discord { context, events },
					frames: Arc::new(Mutex::new(Scheduled::default())),
					wake: Wake::new(&ctx, None),
				}),
				ended: None,
				sequence: 0,
				status: "",
				texture: Default::default(),
				presenter: None,
			};
			for phase in [
				voice::Phase::Connected,
				voice::Phase::Securing,
				voice::Phase::ConnectingTransport,
				voice::Phase::OpeningAudio,
				voice::Phase::Waiting,
				voice::Phase::Connected,
			] {
				state.voice.active.as_mut().unwrap().phase = phase;
				assert!(
					watch
						.poll(&runtime, &mut state, &mut ui, &ctx, None, None)
						.is_none()
				);
				assert!(watch.live.is_some());
			}
			if failed {
				state.voice.active.as_mut().unwrap().phase = voice::Phase::Failed;
			} else {
				state.stop_watching();
			}
			assert!(matches!(
				watch.poll(&runtime, &mut state, &mut ui, &ctx, None, None),
				Some(Command::Voice(voice::Command::StopWatching {
					channel, request, stream_request: 2,
				})) if channel == context.channel && request == context.request
			));
			assert!(watch.live.is_none());
		}
	}

	fn frame(width: u32, height: u32, data: &[u8]) -> discord_voice::RemoteFrame<'_> {
		discord_voice::RemoteFrame {
			presentation: None,
			user: 7,
			picture: platform::video::Picture {
				width,
				height,
				layout: platform::video::Layout::I420,
				color: platform::video::Color::WEBRTC,
				rotation: 0,
				data,
			},
		}
	}

	fn i420(width: u32, height: u32, value: u8) -> Vec<u8> {
		vec![value; platform::video::Layout::I420.len(width, height).unwrap()]
	}

	#[test]
	fn watch_reuses_the_frame_buffer_and_flags_only_updates() {
		let mut slot = None;
		assert!(store_frame(&mut slot, frame(2, 2, &i420(2, 2, 1))));
		let planes = slot.as_ref().unwrap().0.data.as_ptr();
		for value in 0..20 {
			slot.as_mut().unwrap().1 = false;
			assert!(store_frame(&mut slot, frame(2, 2, &i420(2, 2, value))));
			let (picture, fresh) = slot.as_ref().unwrap();
			assert!(*fresh);
			assert_eq!(picture.data.as_ptr(), planes);
			assert_eq!(picture.data, i420(2, 2, value));
		}
		// A smaller picture reuses the allocation too.
		assert!(store_frame(&mut slot, frame(1, 1, &i420(1, 1, 9))));
		let (picture, _) = slot.as_ref().unwrap();
		assert_eq!(picture.data.as_ptr(), planes);
		assert_eq!((picture.width, picture.height), (1, 1));
	}

	#[test]
	fn watch_invalid_frames_preserve_the_last_valid_picture() {
		let mut slot = None;
		assert!(store_frame(&mut slot, frame(1, 1, &i420(1, 1, 4))));
		let planes = slot.as_ref().unwrap().0.data.as_ptr();
		for invalid in [
			frame(0, 1, &[]),
			frame(1, 0, &[]),
			frame(1, 1, &[0; 2]),
			frame(u32::MAX, u32::MAX, &[]),
		] {
			assert!(!store_frame(&mut slot, invalid));
			let (picture, _) = slot.as_ref().unwrap();
			assert_eq!(picture.data.as_ptr(), planes);
			assert_eq!((picture.width, picture.height), (1, 1));
		}
	}

	#[test]
	fn watch_releases_large_capacity_after_a_resolution_drop() {
		let mut slot = None;
		assert!(store_frame(
			&mut slot,
			frame(1920, 1080, &i420(1920, 1080, 0))
		));
		assert!(store_frame(&mut slot, frame(16, 16, &i420(16, 16, 0))));
		let (picture, _) = slot.take().unwrap();
		assert_eq!(picture.data.len(), 16 * 16 * 3 / 2);
		assert!(picture.data.capacity() <= 16 * 16 * 6);
	}

	#[test]
	fn watch_resolution_growth_does_not_double_the_capacity() {
		let mut slot = None;
		assert!(store_frame(
			&mut slot,
			frame(1600, 900, &i420(1600, 900, 0))
		));
		assert!(store_frame(
			&mut slot,
			frame(1920, 1080, &i420(1920, 1080, 0))
		));
		let (picture, _) = slot.take().unwrap();
		assert_eq!(picture.data.len(), 1920 * 1080 * 3 / 2);
		assert!(picture.data.capacity() <= 1920 * 1080 * 3 / 2);
	}
	#[test]
	fn decoded_stream_pictures_wait_for_presentation_and_pressure_skips_only_decoded_frames() {
		let now = Instant::now();
		let mut queue = Scheduled::default();
		let pixels = i420(3840, 2160, 4);
		for n in 0..16 {
			let mut picture = frame(3840, 2160, &pixels);
			picture.presentation = Some(discord_voice::Presentation::new(
				now + Duration::from_millis(100 + n * 16),
			));
			assert!(queue.store(picture));
		}
		assert_eq!(queue.pending.len(), 8);
		assert!(queue.bytes <= DECODED_BUDGET);
		assert!(queue.latest.is_none());
		assert_eq!(queue.advance(now), Some(now + Duration::from_millis(228)));
		queue.advance(now + Duration::from_millis(260));
		assert_eq!(queue.pending.len(), 5);
		assert!(queue.latest.as_ref().unwrap().1);
		assert!(queue.bytes + queue.latest.as_ref().unwrap().0.data.capacity() <= DECODED_BUDGET);
		drop(queue);
		// A backend's RGBA fallback reaches the byte bound before the eight-picture bound.
		let mut queue = Scheduled::default();
		let pixels = vec![4; 3840 * 2160 * 4];
		for n in 0..16 {
			let mut picture = frame(3840, 2160, &pixels);
			picture.picture.layout = platform::video::Layout::Rgba;
			picture.presentation = Some(discord_voice::Presentation::new(
				now + Duration::from_millis(100 + n * 16),
			));
			assert!(queue.store(picture));
		}
		assert_eq!(queue.pending.len(), 4);
		assert!(queue.bytes <= DECODED_BUDGET);
		queue.advance(now + Duration::from_secs(1));
		assert!(queue.pending.is_empty());
		assert_eq!(queue.bytes, 0);
		assert!(queue.latest.as_ref().unwrap().1);
	}
}
