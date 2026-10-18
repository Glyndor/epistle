//! Sieve interpreter (RFC 5228 §2.10, §5): evaluate a script against a message
//! to decide where it is delivered. Unknown tests evaluate to false and unknown
//! actions are ignored, so an unsupported script fails safe.

use std::collections::BTreeSet;

use super::ast::{Argument, Command};

/// The most forwards one run of a script may ask for (`maxNumberRedirects`).
pub const MAX_REDIRECTS: usize = 4;

/// The most different folders one run of a script files a message into.
pub const MAX_FILEINTO: usize = 8;

/// The delivery decision a script produces.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Outcome {
	/// Deliver to the inbox (explicit or implicit keep).
	pub keep: bool,
	/// Mailboxes to file into.
	pub fileinto: Vec<String>,
	/// Of `fileinto` targets, the ones that carried the `:create` tag
	/// (RFC 5490): the delivery side creates the folder if it does not
	/// exist before delivering.
	pub fileinto_creates: BTreeSet<String>,
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
	/// The run spent more than it may (steps, matching work, memory, see
	/// the run budget) and was abandoned: the message is only kept.
	pub aborted: bool,
	/// A test looked at less than the whole message: a body past the first
	/// mebibyte, or more headers than a lookup visits. The run went on with
	/// what it saw.
	pub inspection_truncated: bool,
	/// A `:matches` key was over the length or wildcard caps, and its test
	/// was taken as false.
	pub pattern_over_caps: bool,
	/// What an aborted run had decided to send and the server dropped: an
	/// incomplete run never originates mail.
	pub dropped: Dropped,
	/// How many different `redirect` addresses came after the limit and were
	/// not forwarded to, for the delivery to log.
	pub redirects_over_limit: usize,
	/// How many `fileinto` named a ninth or later different folder and were
	/// not carried out.
	pub fileinto_over_limit: usize,
}

/// The external effects an aborted run had asked for and did not get.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
	/// `redirect` addresses.
	pub redirects: usize,
	/// A `reject` or `ereject`.
	pub reject: bool,
	/// A `vacation`.
	pub vacation: bool,
}

impl Dropped {
	/// Whether anything outward was dropped.
	pub fn any(&self) -> bool {
		self.redirects > 0 || self.reject || self.vacation
	}
}

/// Which actions cancelled the implicit keep: a decision about where the
/// message goes (`discard`, `fileinto`), or an effect outward (`redirect`,
/// `reject`). A run that stops early keeps only the first kind.
#[derive(Default)]
struct Cancel {
	local: bool,
	external: bool,
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
///
/// A run that spends more than it may (the step and work ceilings of the
/// run's `Env`) stops where it is,
/// as a `stop` would, with this rule. What it had decided about where the
/// message goes (`discard`, `fileinto`, `keep`, flags) stays decided, so that
/// the size of a message cannot undo a user's `discard`. What it had asked to
/// send outward (`redirect`, `reject`, `vacation`) is dropped, since an
/// incomplete run never originates mail; and when anything outward was lost,
/// no `discard` stands and the message is kept, because a run cannot both
/// lose the forward and suppress the delivery. A message nothing local was
/// decided about is kept. `aborted` and `dropped` say so, for the log.
pub fn evaluate(script: &[Command], message: &Message) -> Outcome {
	let mut outcome = Outcome::default();
	let mut cancel = Cancel::default();
	let mut env = Env::default();
	run(script, message, &mut outcome, &mut cancel, &mut env);
	outcome.aborted = env.exhausted();
	outcome.inspection_truncated = env.truncated();
	outcome.pattern_over_caps = env.pattern_over_caps();
	if outcome.aborted {
		outcome.dropped = Dropped {
			redirects: outcome.redirects.len(),
			reject: outcome.reject.is_some(),
			vacation: outcome.vacation.is_some(),
		};
		if outcome.dropped.any() {
			// An incomplete run never sends, and it cannot both let the
			// forward go and suppress the delivery: with something outward
			// lost, no `discard` stands, and the message is kept.
			outcome.redirects.clear();
			outcome.reject = None;
			outcome.vacation = None;
			outcome.discarded = false;
			outcome.keep = true;
			return outcome;
		}
	}
	// Implicit keep applies unless an action cancelled it.
	if !(cancel.local || cancel.external) {
		outcome.keep = true;
	}
	outcome
}

use super::env::Env;

/// Returns true if a `stop` was executed (halts further commands).
fn run(
	commands: &[Command],
	message: &Message,
	outcome: &mut Outcome,
	cancel: &mut Cancel,
	vars: &mut Env,
) -> bool {
	for command in commands {
		if !vars.step() {
			return true;
		}
		match command {
			Command::Action { name, args } => match name.as_str() {
				"keep" => outcome.keep = true,
				"discard" => {
					// After a key over the caps made a test false, which `not`
					// or `else` can turn into the branch that loses mail, the
					// run cannot be trusted to mean what its author wrote: it
					// keeps the message instead of discarding it. What it
					// decided before that point stands.
					if vars.pattern_over_caps() {
						outcome.keep = true;
					} else {
						outcome.discarded = true;
						cancel.local = true;
					}
				}
				// reject / ereject (RFC 5429): refuse + bounce; cancels keep.
				"reject" | "ereject" => {
					if vars.pattern_over_caps() {
						// As `discard`: no bounce is sent for a message the run
						// may be wrong about, and it is kept.
						outcome.keep = true;
					} else if let Some(reason) = first_str(args) {
						let reason = vars.expand(&reason);
						if vars.exhausted() {
							return true;
						}
						outcome.reject = Some(reason);
						cancel.external = true;
					}
				}
				// set (RFC 5229): store a variable for later `${name}` expansion.
				"set" => {
					let strings = strings(args);
					if let [name, value, ..] = strings.as_slice() {
						let value = vars.expand(value);
						if vars.exhausted() {
							return true;
						}
						vars.set(name, &value);
					}
				}
				// vacation (RFC 5230): autoresponse alongside normal delivery
				// (does not cancel the implicit keep).
				"vacation" => outcome.vacation = parse_vacation(args),
				"fileinto" => {
					if let Some(target) = first_str(args) {
						let folder = vars.expand(&target);
						if vars.exhausted() {
							return true;
						}
						// A folder is filed into once however often the script
						// names it (RFC 5228 section 4.1 allows that), and into
						// at most MAX_FILEINTO different ones. Every other
						// `fileinto` is one copy more of each message stored.
						let known = outcome.fileinto.contains(&folder);
						if !known && outcome.fileinto.len() < MAX_FILEINTO {
							outcome.fileinto.push(folder.clone());
						} else if !known {
							outcome.fileinto_over_limit += 1;
						}
						// `:create` (RFC 5490): the delivery side creates the
						// folder if it does not exist before filing. Without
						// it, a missing folder is a run-time error that
						// keeps the message in INBOX (RFC 5228 §2.10.6).
						if has_tag(args, "create") && outcome.fileinto.contains(&folder) {
							outcome.fileinto_creates.insert(folder);
						}
						// `:copy` (RFC 3894) leaves the implicit keep in place.
						if !has_tag(args, "copy") {
							cancel.local = true;
						}
					}
				}
				"redirect" => {
					if let Some(target) = first_str(args) {
						// One run forwards to at most MAX_REDIRECTS addresses, and to
						// an address once (RFC 5228 section 4.2 allows both limits).
						// The action still counts as done, so the implicit keep is
						// cancelled either way.
						let target = vars.expand(&target);
						if vars.exhausted() {
							return true;
						}
						if !outcome
							.redirects
							.iter()
							.any(|t| t.eq_ignore_ascii_case(&target))
						{
							if outcome.redirects.len() < MAX_REDIRECTS {
								outcome.redirects.push(target);
							} else {
								outcome.redirects_over_limit += 1;
							}
						}
						if !has_tag(args, "copy") {
							cancel.external = true;
						}
					}
				}
				"stop" => return true,
				// imap4flags (RFC 5232): set/add/remove IMAP flags for delivery.
				"setflag" | "addflag" | "removeflag" => {
					let tokens = flag_list(args);
					// The octets of the list are read, and paid for.
					if !vars.charge(tokens.iter().map(|t| t.len() as u64 + 8).sum()) {
						return true;
					}
					match name.as_str() {
						"setflag" => {
							outcome.flags.clear();
							add_flags(&mut outcome.flags, tokens);
						}
						"addflag" => add_flags(&mut outcome.flags, tokens),
						_ => outcome
							.flags
							.retain(|flag| !tokens.iter().any(|t| t.eq_ignore_ascii_case(flag))),
					}
				}
				// `require` and any unsupported action: no-op.
				_ => {}
			},
			Command::If(conditional) => {
				let mut taken = false;
				for branch in &conditional.branches {
					if super::eval::eval_test(&branch.test, message, vars) {
						if run(&branch.body, message, outcome, cancel, vars) {
							return true;
						}
						taken = true;
						break;
					}
				}
				if !taken
					&& let Some(body) = &conditional.otherwise
					&& run(body, message, outcome, cancel, vars)
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

/// The most different IMAP flags a run puts on a message.
pub const MAX_FLAGS: usize = 32;
/// The longest a flag may be, in octets (the IMAP keyword limit).
const MAX_FLAG_BYTES: usize = 64;

/// Add `tokens` to `flags`: a flag once however it is cased, none over
/// [`MAX_FLAG_BYTES`], and at most [`MAX_FLAGS`] in all (the first ones win).
fn add_flags(flags: &mut Vec<String>, tokens: Vec<String>) {
	for token in tokens {
		if flags.len() >= MAX_FLAGS {
			break;
		}
		if token.len() <= MAX_FLAG_BYTES && !flags.iter().any(|f| f.eq_ignore_ascii_case(&token)) {
			flags.push(token);
		}
	}
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
