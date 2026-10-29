//! What the server does with an inspection: the `[attachments]` policy
//! turned into one action per message.
//!
//! Every reason maps to an action. Dangerous content follows `mode`;
//! macros and encrypted archives follow their own setting, never above
//! `mode`, and so does `ambiguous-archive`: only a simple, consistent zip
//! is judged by its names. What could not be inspected or reads two ways
//! (`scan-limit`, `ambiguous-mime`, `unreadable-archive`,
//! `nested-archive`) is at least
//! flagged and quarantined when `mode` quarantines, but never rejected on
//! its own: a large or odd message is not proof of a disguise.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::gate::{Gate, Permit};
use super::rules::{Extensions, Reason};
use super::{Budget, Report, inspect};
use crate::config::{AttachmentMode, Attachments, ContentAction};

/// The header that carries the reason codes.
pub const WARNING_HEADER: &str = "X-Epistle-Attachment-Warning";

/// How long one inspection may run before what is left is a scan-limit.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// What happens to the message, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
	/// Deliver as is.
	Deliver,
	/// Deliver with the warning header.
	Flag,
	/// Deliver to Rejects with the warning header.
	Quarantine,
	/// Refuse during SMTP.
	Reject,
}

/// The outcome for one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
	/// The strongest action any reason asked for.
	pub action: Action,
	/// The reasons that asked for an action, sorted.
	pub reasons: Vec<Reason>,
}

impl Decision {
	/// The warning header line, CRLF-terminated, or `None` when there is
	/// nothing to say. Only reason codes go in: no file name or other text
	/// from the message.
	pub fn header(&self) -> Option<String> {
		if self.reasons.is_empty() {
			return None;
		}
		let codes: Vec<&str> = self.reasons.iter().map(|reason| reason.code()).collect();
		Some(format!("{WARNING_HEADER}: {}\r\n", codes.join(", ")))
	}

	/// Remove any warning header the sender wrote, then add ours. Whatever
	/// arrives in the message is the sender's claim; only the server's own
	/// inspection may speak in this header.
	pub fn stamp(&self, data: &mut Vec<u8>) {
		crate::smtp::trace::strip_headers_in_place(data, &[WARNING_HEADER]);
		if let Some(header) = self.header() {
			let mut stamped = Vec::with_capacity(header.len() + data.len());
			stamped.extend_from_slice(header.as_bytes());
			stamped.append(data);
			*data = stamped;
		}
	}
}

/// The configured policy.
#[derive(Clone, Debug)]
pub struct Policy {
	mode: AttachmentMode,
	macros: ContentAction,
	encrypted_archives: ContentAction,
	extensions: Extensions,
	max_decoded: usize,
	timeout: Duration,
	/// Caps on concurrent inbound inspections, total and per client.
	/// Shared by every listener that holds this policy.
	inbound: Arc<Gate>,
	/// Called at the start of every inspection, so a test can make one
	/// panic or block.
	#[cfg(test)]
	check_hook: Option<CheckHook>,
}

/// A test's hook, owned by the policy it was given to, so two tests never
/// share the state behind it.
#[cfg(test)]
#[derive(Clone)]
struct CheckHook(Arc<dyn Fn() + Send + Sync>);

#[cfg(test)]
impl std::fmt::Debug for CheckHook {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		formatter.write_str("CheckHook")
	}
}

impl Policy {
	/// The policy for `section`, or `None` when `mode = "off"`. `max_decoded`
	/// is the message size limit: no message can decode to more.
	pub fn from_config(section: &Attachments, max_decoded: usize) -> Option<Self> {
		if section.mode == AttachmentMode::Off {
			return None;
		}
		let normalise = |list: &[String]| -> Vec<String> {
			list.iter()
				.map(|value| crate::config::normalise_extension(value))
				.collect()
		};
		Some(Self {
			mode: section.mode,
			macros: section.macros,
			encrypted_archives: section.encrypted_archives,
			extensions: Extensions::new(
				&normalise(&section.block_extensions),
				&normalise(&section.allow_extensions),
			),
			max_decoded,
			timeout: DEFAULT_TIMEOUT,
			inbound: Gate::with_defaults(),
			#[cfg(test)]
			check_hook: None,
		})
	}

	/// How long one inspection may run.
	pub fn timeout(&self) -> Duration {
		self.timeout
	}

	/// Whether any finding can quarantine or refuse a message. Under
	/// `mode = "flag"` none can: every finding is a header at most.
	pub fn can_refuse(&self) -> bool {
		mode_action(self.mode) >= Action::Quarantine
	}

	/// Admit one inbound inspection for the client at `peer`, or `None`
	/// when the server or that client is at its cap. A client is its IPv4
	/// address or the /64 of its IPv6 one; mail with no known peer shares
	/// one slot count.
	pub(crate) fn admit_inbound(&self, peer: Option<IpAddr>) -> Option<Permit> {
		let client = peer
			.map(|ip| crate::smtp::per_ip::client_key(ip).to_string())
			.unwrap_or_default();
		self.inbound.try_enter(&client)
	}

	/// Replace the inbound caps.
	#[cfg(test)]
	pub(crate) fn with_inbound_caps(mut self, global: usize, per_client: usize) -> Self {
		self.inbound = Gate::new(global, per_client);
		self
	}

	/// Run `hook` at the start of every inspection.
	#[cfg(test)]
	pub(crate) fn with_check_hook(mut self, hook: impl Fn() + Send + Sync + 'static) -> Self {
		self.check_hook = Some(CheckHook(Arc::new(hook)));
		self
	}

	/// Replace the inspection deadline.
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Inspect `raw` and decide.
	pub fn check(&self, raw: &[u8]) -> (Report, Decision) {
		#[cfg(test)]
		if let Some(CheckHook(hook)) = &self.check_hook {
			hook();
		}
		let report = inspect(
			raw,
			&self.extensions,
			Budget {
				max_decoded: self.max_decoded,
				deadline: Some(Instant::now() + self.timeout),
			},
		);
		let decision = self.decide(&report);
		(report, decision)
	}

	/// The action for every reason in `report`, and the strongest of them.
	pub fn decide(&self, report: &Report) -> Decision {
		let mut action = Action::Deliver;
		let mut reasons = Vec::new();
		for reason in report.reasons() {
			let wanted = self.action_for(reason);
			if wanted > Action::Deliver {
				reasons.push(reason);
				action = action.max(wanted);
			}
		}
		Decision { action, reasons }
	}

	fn action_for(&self, reason: Reason) -> Action {
		let ceiling = mode_action(self.mode);
		match reason {
			Reason::Macro => content_action(self.macros).min(ceiling),
			Reason::EncryptedArchive => content_action(self.encrypted_archives).min(ceiling),
			// Only a simple, consistent zip is judged by its names; one that
			// reads two ways is treated as dangerous.
			Reason::AmbiguousArchive | Reason::AmbiguousImage | Reason::ActiveImage => ceiling,
			Reason::ScanLimit
			| Reason::AmbiguousMime
			| Reason::UnreadableArchive
			| Reason::NestedArchive => ceiling.min(Action::Quarantine).max(Action::Flag),
			_ => ceiling,
		}
	}
}

fn mode_action(mode: AttachmentMode) -> Action {
	match mode {
		AttachmentMode::Off => Action::Deliver,
		AttachmentMode::Flag => Action::Flag,
		AttachmentMode::Quarantine => Action::Quarantine,
		AttachmentMode::Reject => Action::Reject,
	}
}

fn content_action(action: ContentAction) -> Action {
	match action {
		ContentAction::Allow => Action::Deliver,
		ContentAction::Flag => Action::Flag,
		ContentAction::Quarantine => Action::Quarantine,
	}
}

#[cfg(test)]
mod tests;
