//! Screen sessions independent of the Discord account and call.
use client_core::screen::{self, P2pBitrate, Resolution, Settings, Source};
use discord_voice::{
	VideoSink,
	p2p_stream::{self, P2pHostConfig, P2pHostStats, P2pTarget, P2pWatchStats},
	screen::Worker,
};
use eframe::egui;
use std::{
	sync::{Arc, Mutex, atomic::AtomicU16},
	time::Duration,
};
use tokio::{runtime::Handle, sync::watch, task::JoinHandle};

type Sources = Result<Vec<Source>, &'static str>;
type SessionResult = JoinHandle<Result<(), String>>;

struct Session<T> {
	task: SessionResult,
	stats: watch::Receiver<T>,
}

impl<T> Drop for Session<T> {
	fn drop(&mut self) {
		self.task.abort();
	}
}

struct Host {
	network: Session<P2pHostStats>,
	worker: Worker,
}

#[derive(Default)]
pub struct Panel {
	open: bool,
	sources: Vec<Source>,
	scanning: Option<JoinHandle<Sources>>,
	source: usize,
	resolution: Option<Resolution>,
	fps: Option<u32>,
	bitrate: P2pBitrate,
	audio: bool,
	hide_cursor: bool,
	link: String,
	host: Option<Host>,
	viewer: Option<Session<P2pWatchStats>>,
	latest: Arc<Mutex<Option<platform::video::Picture>>>,
	texture: crate::gpu_video::VideoTexture,
	host_error: Option<String>,
	view_error: Option<String>,
}

impl Panel {
	pub fn stop(&mut self) {
		self.host = None;
		if self.viewer.is_some() {
			self.stop_viewing();
		}
	}

	pub fn show(&mut self, ui: &mut egui::Ui, runtime: &Handle) {
		let ctx = ui.ctx().clone();
		self.poll(&ctx);
		egui::Panel::top("direct-screen-controls").show(ui, |ui| {
			ui.horizontal(|ui| {
				let label = if self.host.is_some() {
					"Screen P2P · Sharing"
				} else if self.viewer.is_some() {
					"Screen P2P · Viewing"
				} else {
					"Screen P2P"
				};
				if ui.button(label).clicked() {
					self.open = !self.open;
					if self.open && self.sources.is_empty() {
						self.scan(runtime, &ctx);
					}
				}
			});
		});
		let mut open = self.open;
		egui::Window::new("Screen P2P")
			.open(&mut open)
			.default_width(640.0)
			.max_height((ctx.content_rect().height() - 48.0).max(120.0))
			.vscroll(true)
			.show(&ctx, |ui| {
				ui.heading("Share your screen");
				self.share_ui(ui, runtime);
				ui.separator();
				ui.heading("Watch a stream");
				self.watch_ui(ui, runtime);
			});
		self.open = open;
	}

	fn scan(&mut self, runtime: &Handle, ctx: &egui::Context) {
		if self.scanning.is_none() && discord_voice::screen::supported() {
			let ctx = ctx.clone();
			self.scanning = Some(runtime.spawn_blocking(move || {
				let result = discord_voice::screen::sources();
				ctx.request_repaint();
				result
			}));
		}
	}

	fn poll(&mut self, ctx: &egui::Context) {
		if let Some(scan) = &mut self.scanning
			&& let Some(result) = futures_util::FutureExt::now_or_never(scan)
		{
			self.scanning = None;
			match result {
				Ok(Ok(sources)) => {
					self.sources = sources;
					self.source = 0;
					self.resolution = None;
					self.fps = None;
				}
				Ok(Err(error)) => self.host_error = Some(error.into()),
				Err(error) => self.host_error = Some(error.to_string()),
			}
		}
		if let Some(host) = &mut self.host {
			if host.worker.captured() {
				host.worker.set_preview_visible(false);
				let _ = host.worker.take_preview();
			}
			if let Some(result) = host.worker.result() {
				self.host_error = result.err().map(|error| error.into_owned());
				self.host = None;
			} else if let Some(result) =
				futures_util::FutureExt::now_or_never(&mut host.network.task)
			{
				self.host_error = Some(session_end(result));
				self.host = None;
			}
		}
		if let Some(viewer) = &mut self.viewer
			&& let Some(result) = futures_util::FutureExt::now_or_never(&mut viewer.task)
		{
			self.view_error = Some(session_end(result));
			self.stop_viewing();
		}
		if self.host.is_some() || self.viewer.is_some() || self.scanning.is_some() {
			ctx.request_repaint_after(Duration::from_millis(250));
		}
	}

	fn share_ui(&mut self, ui: &mut egui::Ui, runtime: &Handle) {
		if let Some(host) = &self.host {
			let stats = host.network.stats.borrow();
			if !host.worker.captured() {
				ui.label(
					host.worker
						.capture_status()
						.unwrap_or("Waiting for screen capture…"),
				);
			} else {
				ui.label(&stats.status);
				if !stats.link.is_empty() {
					ui.label(if stats.tailscale {
						"Tailscale"
					} else if stats.ip == "127.0.0.1" {
						"This device only · no network address found"
					} else {
						"Local network"
					});
					ui.label(format!(
						"{} viewers · {} fps · {:.1} Mbps",
						stats.viewers,
						stats.fps,
						stats.bitrate_kbps as f64 / 1000.0
					));
					if ui.button("Copy invitation").clicked() {
						ui.ctx().copy_text(stats.link.clone());
					}
					ui.label(
						"Share the invitation privately with people who can reach this device.",
					);
				}
			}
			drop(stats);
			if ui.button("Stop sharing").clicked() {
				self.host = None;
			}
			return;
		}
		if let Some(error) = &self.host_error {
			ui.colored_label(ui.visuals().error_fg_color, error);
		}
		if !discord_voice::screen::supported() {
			ui.label("Screen capture is unavailable on this platform.");
			return;
		}
		if ui
			.add_enabled(
				self.scanning.is_none(),
				egui::Button::new("Refresh sources"),
			)
			.clicked()
		{
			self.host_error = None;
			self.scan(runtime, ui.ctx());
		}
		let Some(current) = self.sources.get(self.source) else {
			ui.label(if self.scanning.is_some() {
				"Finding capture sources…"
			} else {
				"No capture source available."
			});
			return;
		};
		let old_source = self.source;
		egui::ComboBox::from_id_salt("p2p-source")
			.selected_text(&current.name)
			.show_ui(ui, |ui| {
				for (index, source) in self.sources.iter().enumerate() {
					ui.selectable_value(&mut self.source, index, &source.name);
				}
			});
		if old_source != self.source {
			self.resolution = None;
			self.fps = None;
		}
		let source = &self.sources[self.source];
		let sized_after_pick = source.id.sized_after_pick();
		let resolution = self.resolution.get_or_insert(Resolution::Preset {
			width: 1920,
			height: 1080,
		});
		let fps = self.fps.get_or_insert(60);
		ui.horizontal_wrapped(|ui| {
			egui::ComboBox::from_id_salt("p2p-resolution")
				.selected_text(resolution_label(*resolution))
				.show_ui(ui, |ui| {
					for option in
						screen::offered_resolutions(source.width, source.height, sized_after_pick)
					{
						ui.selectable_value(resolution, option, resolution_label(option));
					}
				});
			egui::ComboBox::from_id_salt("p2p-fps")
				.selected_text(format!("{fps} fps"))
				.show_ui(ui, |ui| {
					for option in screen::offered_p2p_frame_rates(source.refresh_hz) {
						ui.selectable_value(fps, option, format!("{option} fps"));
					}
				});
			egui::ComboBox::from_id_salt("p2p-bitrate")
				.selected_text(self.bitrate.label())
				.show_ui(ui, |ui| {
					for option in P2pBitrate::ALL {
						ui.selectable_value(&mut self.bitrate, option, option.label());
					}
				});
		});
		ui.checkbox(&mut self.hide_cursor, "Hide cursor");
		if discord_voice::screen::audio_supported() {
			ui.checkbox(&mut self.audio, "Share system audio");
		}
		if ui
			.add_enabled(self.scanning.is_none(), egui::Button::new("Start sharing"))
			.clicked()
		{
			let Some((width, height)) =
				screen::picture(*resolution, source.width, source.height, sized_after_pick)
			else {
				self.host_error = Some("This source cannot use the selected resolution.".into());
				return;
			};
			let settings = Settings {
				source: source.id,
				width,
				height,
				fps: *fps,
				cursor: !self.hide_cursor,
				audio: self.audio,
			};
			self.start_host(settings, runtime, ui.ctx());
		}
	}

	fn start_host(&mut self, settings: Settings, runtime: &Handle, ctx: &egui::Context) {
		self.host_error = None;
		let bitrate = self.bitrate.bps(settings);
		let capture_ctx = ctx.clone();
		match Worker::start_p2p(settings, bitrate, move || capture_ctx.request_repaint()) {
			Ok((worker, video)) => {
				let (tx, stats) = watch::channel(P2pHostStats::default());
				let ctx = ctx.clone();
				let task = runtime.spawn(async move {
					let wake = ctx.clone();
					let config = P2pHostConfig {
						initial_bitrate_bps: bitrate,
						..Default::default()
					};
					let result = p2p_stream::run_p2p_host(
						video,
						config,
						tx,
						Arc::new(move || wake.request_repaint()),
					)
					.await;
					ctx.request_repaint();
					result
				});
				self.host = Some(Host {
					network: Session { task, stats },
					worker,
				});
			}
			Err(error) => self.host_error = Some(error.into()),
		}
	}

	fn watch_ui(&mut self, ui: &mut egui::Ui, runtime: &Handle) {
		if let Some(viewer) = &self.viewer {
			let stats = viewer.stats.borrow().clone();
			ui.label(&stats.status);
			if stats.state == p2p_stream::P2pWatchState::Watching {
				ui.label(format!(
					"{}×{} · {} fps · {:.1} Mbps · {} ms RTT",
					stats.width,
					stats.height,
					stats.fps,
					stats.bitrate_kbps as f64 / 1000.0,
					stats.rtt_ms
				));
			}
			if ui.button("Stop watching").clicked() {
				self.stop_viewing();
				return;
			}
			let first_picture = self.texture.texture().is_none();
			if let Some(picture) = self.latest.try_lock().ok().and_then(|mut slot| slot.take()) {
				self.texture
					.upload(ui.ctx(), "p2p-stream", picture.borrow());
			}
			if let Some(texture) = self.texture.texture() {
				let available = ui.ctx().content_rect().size() * 0.42;
				let picture = ui.add(egui::Image::new(texture).fit_to_exact_size(
					texture.size
						* (ui.available_width() / texture.size.x).min(available.y / texture.size.y),
				));
				if first_picture {
					picture.scroll_to_me(Some(egui::Align::BOTTOM));
				}
			}
			return;
		}
		if let Some(error) = &self.view_error {
			ui.colored_label(ui.visuals().error_fg_color, error);
		}
		ui.horizontal(|ui| {
			let field = ui.add(
				egui::TextEdit::singleline(&mut self.link)
					.hint_text("Paste a serein-p2p:// invitation")
					.password(true)
					.char_limit(1024),
			);
			if ui.button("Paste").clicked() {
				field.request_focus();
				ui.ctx()
					.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
			}
			if ui
				.add_enabled(!self.link.trim().is_empty(), egui::Button::new("Watch"))
				.clicked()
			{
				match P2pTarget::parse(&self.link) {
					Ok(target) => self.start_viewing(target, runtime, ui.ctx()),
					Err(error) => self.view_error = Some(error.into()),
				}
			}
		});
	}

	fn start_viewing(&mut self, target: P2pTarget, runtime: &Handle, ctx: &egui::Context) {
		self.link.clear();
		self.view_error = None;
		let latest = self.latest.clone();
		let sink: VideoSink = Arc::new(move |frame| {
			if frame.picture.is_valid()
				&& let Ok(mut slot) = latest.lock()
			{
				*slot = Some(frame.picture.with_data(frame.picture.data.to_vec()));
			}
		});
		let (tx, stats) = watch::channel(P2pWatchStats::default());
		let ctx = ctx.clone();
		let task = runtime.spawn(async move {
			let wake = ctx.clone();
			let result = p2p_stream::run_p2p_viewer(
				target,
				sink,
				Arc::new(AtomicU16::new(100)),
				None,
				tx,
				Arc::new(move || wake.request_repaint()),
			)
			.await;
			ctx.request_repaint();
			result
		});
		self.viewer = Some(Session { task, stats });
	}

	fn stop_viewing(&mut self) {
		self.viewer = None;
		self.latest = Default::default();
		self.texture = Default::default();
	}
}

fn resolution_label(resolution: Resolution) -> String {
	match resolution {
		Resolution::Source => "Source".into(),
		Resolution::Preset { height, .. } => format!("{height}p"),
	}
}

fn session_end(result: Result<Result<(), String>, tokio::task::JoinError>) -> String {
	match result {
		Ok(Ok(())) => "P2P session ended.".into(),
		Ok(Err(error)) => error,
		Err(error) => format!("P2P session stopped: {error}"),
	}
}
