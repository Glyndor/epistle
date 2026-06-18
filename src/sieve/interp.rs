//! Sieve interpreter (RFC 5228 §2.10, §5): evaluate a script against a message
//! to decide where it is delivered. Unknown tests evaluate to false and unknown
//! actions are ignored, so an unsupported script fails safe.

use super::ast::{Argument, Command};

/// The delivery decision a script produces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
	/// Deliver to the inbox (explicit or implicit keep).
	pub keep: bool,
	/// Mailboxes to file into.
	pub fileinto: Vec<String>,
	/// Addresses to redirect to.
	pub redirects: Vec<String>,
	/// The message was explicitly discarded.
	pub discarded: bool,
	/// IMAP flags set on the delivered message (imap4flags, RFC 5232).
	pub flags: Vec<String>,
	/// The message was rejected (reject/ereject, RFC 5429): the reason is
	/// bounced to the sender and the message is not delivered.
	pub reject: Option<String>,
	/// A `vacation` autoresponse to send in addition to normal delivery
	/// (RFC 5230), subject to the caller's suppression and dedup rules.
	pub vacation: Option<VacationRequest>,
}

/// A parsed `vacation` action (RFC 5230). The caller decides whether to send.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VacationRequest {
	/// The reply body (`:reason`, the positional argument).
	pub reason: String,
	/// An explicit `:subject`, else derived from the original.
	pub subject: Option<String>,
	/// An explicit `:from`, else the responding user's address.
	pub from: Option<String>,
	/// At most one reply per sender per this many days (`:days`, default 7).
	pub days: u64,
}

pub use super::message::Message;

/// Run a parsed script against a message and return the delivery outcome.
pub fn evaluate(script: &[Command], message: &Message) -> Outcome {
	let mut outcome = Outcome::default();
	let mut cancel_implicit = false;
	let mut vars = std::collections::HashMap::new();
	run(
		script,
		message,
		&mut outcome,
		&mut cancel_implicit,
		&mut vars,
	);
	// Implicit keep applies unless an action cancelled it.
	if !cancel_implicit {
		outcome.keep = true;
	}
	outcome
}

use super::vars::expand;

/// Returns true if a `stop` was executed (halts further commands).
fn run(
	commands: &[Command],
	message: &Message,
	outcome: &mut Outcome,
	cancel_implicit: &mut bool,
	vars: &mut std::collections::HashMap<String, String>,
) -> bool {
	for command in commands {
		match command {
			Command::Action { name, args } => match name.as_str() {
				"keep" => outcome.keep = true,
				"discard" => {
					outcome.discarded = true;
					*cancel_implicit = true;
				}
				// reject / ereject (RFC 5429): refuse + bounce; cancels keep.
				"reject" | "ereject" => {
					if let Some(reason) = first_str(args) {
						outcome.reject = Some(expand(&reason, vars));
						*cancel_implicit = true;
					}
				}
				// set (RFC 5229): store a variable for later `${name}` expansion.
				"set" => {
					let strings = strings(args);
					if let [name, value, ..] = strings.as_slice() {
						let value = expand(value, vars);
						vars.insert(name.clone(), value);
					}
				}
				// vacation (RFC 5230): autoresponse alongside normal delivery
				// (does not cancel the implicit keep).
				"vacation" => outcome.vacation = parse_vacation(args),
				"fileinto" => {
					if let Some(target) = first_str(args) {
						outcome.fileinto.push(expand(&target, vars));
						// `:copy` (RFC 3894) leaves the implicit keep in place.
						if !has_tag(args, "copy") {
							*cancel_implicit = true;
						}
					}
				}
				"redirect" => {
					if let Some(target) = first_str(args) {
						outcome.redirects.push(expand(&target, vars));
						if !has_tag(args, "copy") {
							*cancel_implicit = true;
						}
					}
				}
				"stop" => return true,
				// imap4flags (RFC 5232): set/add/remove IMAP flags for delivery.
				"setflag" => outcome.flags = flag_list(args),
				"addflag" => {
					for flag in flag_list(args) {
						if !outcome.flags.contains(&flag) {
							outcome.flags.push(flag);
						}
					}
				}
				"removeflag" => {
					let remove = flag_list(args);
					outcome.flags.retain(|flag| !remove.contains(flag));
				}
				// `require` and any unsupported action: no-op.
				_ => {}
			},
			Command::If(conditional) => {
				let mut taken = false;
				for branch in &conditional.branches {
					if super::eval::eval_test(&branch.test, message) {
						if run(&branch.body, message, outcome, cancel_implicit, vars) {
							return true;
						}
						taken = true;
						break;
					}
				}
				if !taken
					&& let Some(body) = &conditional.otherwise
					&& run(body, message, outcome, cancel_implicit, vars)
				{
					return true;
				}
			}
		}
	}
	false
}

/// `:subject`, `:from` (others ignored) and the positional reason string.
fn parse_vacation(args: &[Argument]) -> Option<VacationRequest> {
	let mut request = VacationRequest {
		days: 7,
		..VacationRequest::default()
	};
	let mut reason = None;
	let mut iter = args.iter();
	while let Some(arg) = iter.next() {
		match arg {
			Argument::Tag(tag) => match tag.as_str() {
				"days" => {
					if let Some(Argument::Number(days)) = iter.next() {
						request.days = *days;
					}
				}
				"subject" => {
					if let Some(Argument::Str(value)) = iter.next() {
						request.subject = Some(value.clone());
					}
				}
				"from" => {
					if let Some(Argument::Str(value)) = iter.next() {
						request.from = Some(value.clone());
					}
				}
				// `:handle` / `:addresses` carry a value that is not the reason.
				"handle" | "addresses" => {
					iter.next();
				}
				_ => {}
			},
			Argument::Str(value) => reason = Some(value.clone()),
			_ => {}
		}
	}
	reason.map(|reason| VacationRequest { reason, ..request })
}

/// Flag tokens from a flag-list argument (each string may hold several flags).
fn flag_list(args: &[Argument]) -> Vec<String> {
	strings(args)
		.iter()
		.flat_map(|s| s.split_whitespace().map(str::to_string))
		.collect()
}

fn first_str(args: &[Argument]) -> Option<String> {
	args.iter().find_map(|arg| match arg {
		Argument::Str(s) => Some(s.clone()),
		_ => None,
	})
}

/// All bare strings from arguments, flattening string lists, in order.
pub(super) fn strings(args: &[Argument]) -> Vec<String> {
	let mut out = Vec::new();
	for arg in args {
		match arg {
			Argument::Str(s) => out.push(s.clone()),
			Argument::StrList(list) => out.extend(list.iter().cloned()),
			_ => {}
		}
	}
	out
}

pub(super) fn has_tag(args: &[Argument], tag: &str) -> bool {
	args.iter()
		.any(|arg| matches!(arg, Argument::Tag(t) if t == tag))
}
