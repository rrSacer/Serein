//! Native P2P stream cards inside chat messages and a link-watch dialog for the call UI.
use client_core::{
	State,
	screen::{P2pLinkInfo, extract_p2p_links, parse_p2p_link},
};
use model::{Id, Message};

const CARD_WIDTH: f32 = 432.0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchAction {
	StartInCall(Id),
	StopInCall,
	StartDirect {
		link: String,
		label: String,
	},
	StopDirect,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectWatchState {
	pub active: bool,
	pub link: String,
	pub label: String,
	pub status: String,
	pub width: u32,
	pub height: u32,
	pub fps: u32,
	pub bitrate_kbps: u32,
	pub rtt_ms: u32,
}

#[derive(Clone, Debug, Default)]
pub struct WatchDialog {
	pub open: bool,
	pub input: String,
	pub error: Option<String>,
}

impl WatchDialog {
	pub fn launch(&mut self) {
		self.open = true;
		self.error = None;
	}

	pub fn show(&mut self, ctx: &egui::Context) -> Option<(String, String)> {
		if !self.open {
			return None;
		}
		let mut cancel = false;
		let mut confirm = false;
		let mut paste = false;
		let field_id = egui::Id::unique("p2p-watch-link-input");
		let response = crate::dialog::Dialog::new(
			"p2p-watch-link-dialog",
			crate::i18n::translate("p2p-watch-dialog-title"),
		)
		.subtitle(crate::i18n::translate("p2p-watch-dialog-subtitle"))
		.icon(crate::icons::Icon::ScreenShare)
		.width(480.0)
		.show(ctx, |d| {
			d.content(|ui| {
				let colors = crate::design::palette(ui);
				ui.horizontal(|ui| {
					let available = (ui.available_width() - 88.0).max(160.0);
					let edit = ui.add_sized(
						[available, 34.0],
						egui::TextEdit::singleline(&mut self.input)
							.id(field_id)
							.hint_text(crate::i18n::translate("p2p-watch-dialog-placeholder"))
							.password(true)
							.char_limit(1024),
					);
					if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
						confirm = true;
					}
					if crate::design::button(
						ui,
						"p2p-watch-dialog-paste",
						crate::design::ButtonKind::Outline,
					)
					.clicked()
					{
						paste = true;
					}
				});
				if paste {
					ctx.memory_mut(|m| m.request_focus(field_id));
					ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
				}
				if let Some(error) = &self.error {
					ui.add_space(6.0);
					ui.label(egui::RichText::new(error).size(12.0).color(colors.danger));
				}
			});
			d.footer(|ui| {
				let enabled = !self.input.trim().is_empty();
				ui.add_enabled_ui(enabled, |ui| {
					confirm |= crate::dialog::action(
						ui,
						"p2p-watch-stream",
						crate::dialog::Action::Primary,
					)
					.clicked();
				});
				cancel |=
					crate::dialog::action(ui, "screen-show-cancel", crate::dialog::Action::Neutral)
						.clicked();
			});
		});
		cancel |= response.close;
		if cancel {
			self.open = false;
			self.error = None;
			return None;
		}
		if confirm {
			let Some(parsed) = parse_p2p_link(&self.input) else {
				self.error = Some("Invalid serein-p2p:// link.".to_owned());
				return None;
			};
			let label = parsed
				.quality_summary()
				.map_or_else(|| "P2P".to_owned(), |q| format!("P2P · {q}"));
			self.open = false;
			self.input.clear();
			self.error = None;
			return Some((parsed.raw, label));
		}
		None
	}
}

pub fn estimated_height(message: &Message) -> f32 {
	if extract_p2p_links(&message.content).is_empty() {
		0.0
	} else {
		76.0
	}
}

pub fn show(
	ui: &mut egui::Ui,
	message: &Message,
	state: &State,
	direct_watch: &DirectWatchState,
	ended_links: &[String],
	action: &mut Option<WatchAction>,
) {
	let links = extract_p2p_links(&message.content);
	if links.is_empty() {
		return;
	}
	let own = state.user.as_ref().map(|u| u.id);
	let author_name = message
		.author_nick
		.as_deref()
		.unwrap_or(&message.author.name);

	for link in links {
		ui.push_id(("p2p-card", message.id, &link.raw), |ui| {
			render_card(
				ui,
				message,
				author_name,
				own,
				state,
				&link,
				direct_watch,
				ended_links,
				action,
			);
		});
	}
}

#[allow(clippy::too_many_arguments)]
fn render_card(
	ui: &mut egui::Ui,
	message: &Message,
	author_name: &str,
	own: Option<Id>,
	state: &State,
	link: &P2pLinkInfo,
	direct_watch: &DirectWatchState,
	ended_links: &[String],
	action: &mut Option<WatchAction>,
) {
	let colors = crate::design::palette(ui);
	let width = ui.available_width().min(CARD_WIDTH);
	let is_own = own == Some(message.author.id);
	let in_call_with_author = state.voice.active.as_ref().is_some_and(|call| {
		call.channel == message.channel
			&& state
				.p2p_stream_for(call.channel, message.author.id)
				.is_some_and(|ann| ann.link.raw == link.raw)
			&& call
				.participants
				.iter()
				.any(|p| p.user == message.author.id)
	});
	let watching_in_call = in_call_with_author
		&& state
			.voice
			.active
			.as_ref()
			.is_some_and(|call| call.watching == Some(message.author.id));
	let watching_direct = direct_watch.active && direct_watch.link == link.raw;
	let watching = watching_in_call || watching_direct;
	let ended = !watching && ended_links.iter().any(|item| item == &link.raw);

	let mut detail_parts = Vec::new();
	if let Some(quality) = link.quality_summary() {
		detail_parts.push(quality);
	}
	detail_parts.push(if link.tailscale {
		"Tailscale".to_owned()
	} else {
		"LAN / Direto".to_owned()
	});
	let subtitle = detail_parts.join(" · ");

	ui.add_space(4.0);
	egui::Frame::new()
		.fill(colors.base)
		.stroke(egui::Stroke::new(
			1.0,
			if watching {
				colors.accent
			} else {
				colors.border
			},
		))
		.corner_radius(10)
		.inner_margin(egui::Margin::symmetric(14, 12))
		.show(ui, |ui| {
			ui.set_width((width - 28.0).max(120.0));
			ui.horizontal(|ui| {
				ui.spacing_mut().item_spacing.x = 12.0;
				let (badge, _) =
					ui.allocate_exact_size(egui::Vec2::splat(40.0), egui::Sense::hover());
				ui.painter().rect_filled(
					badge,
					10,
					if ended {
						colors.hover
					} else {
						colors.accent.gamma_multiply(0.18)
					},
				);
				crate::icons::paint(
					ui.painter(),
					crate::icons::Icon::ScreenShare,
					badge.shrink(10.0),
					if ended { colors.muted } else { colors.accent },
				);

				ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
					let (btn_label, btn_kind, enabled) = if ended {
						("p2p-stream-ended", crate::design::ButtonKind::Outline, false)
					} else if watching {
						("p2p-stop-watching", crate::design::ButtonKind::Danger, true)
					} else if is_own {
						("p2p-watch-stream", crate::design::ButtonKind::Outline, false)
					} else {
						("p2p-watch-stream", crate::design::ButtonKind::Primary, true)
					};
					let clicked = ui
						.add_enabled_ui(enabled, |ui| crate::design::button(ui, btn_label, btn_kind))
						.inner
						.clicked();
					if clicked {
						*action = Some(if watching_in_call {
							WatchAction::StopInCall
						} else if watching_direct {
							WatchAction::StopDirect
						} else if in_call_with_author {
							WatchAction::StartInCall(message.author.id)
						} else {
							WatchAction::StartDirect {
								link: link.raw.clone(),
								label: format!("{author_name} · P2P"),
							}
						});
					}

					ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
						ui.vertical(|ui| {
							ui.spacing_mut().item_spacing.y = 2.0;
							ui.add(
								egui::Label::new(
									crate::design::semibold(
										ui,
										format!(
											"{} · {}",
											crate::i18n::translate("p2p-card-title"),
											author_name
										),
										14.0,
									)
									.color(colors.text_strong),
								)
								.truncate()
								.selectable(false),
							);
							ui.add(
								egui::Label::new(
									egui::RichText::new(subtitle)
										.size(12.0)
										.color(colors.muted),
								)
								.truncate()
								.selectable(false),
							);
						});
					});
				});
			});
		});
}
