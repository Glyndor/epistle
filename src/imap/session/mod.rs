//! IMAP session state machine (sans-IO).

use super::command::{
	Command, FetchItem, Line, ParseError, SearchKey, StoreMode, Tagged, ThreadAlgorithm,
};
use super::mailbox;
use crate::smtp::directory::hash_gate::Verdict;

mod acl;
mod auth;
mod base_subject;
mod codes;
mod commands;
mod condstore;
mod defaults;
mod expunge;
mod fetch;
mod fetchstore;
mod helpers;
mod idle;
mod list_status;
mod literal;
mod lsub;
mod metadata;
mod notify;
mod quota;
mod search_fields;
mod search_header;
mod select;
mod sort;
mod sort_keys;
mod state;
mod sync;
mod thread;
mod thread_references;
mod utf8;

pub use state::{DEFAULT_QUOTA_BYTES, Output, PendingLiteral, SavedSearch, Session, State};

/// The size of the non-synchronizing literal a tagged APPEND or REPLACE
/// line announces (RFC 7888 §4): bytes the client has already sent, which
/// a rejection must discard.
fn sent_literal(line: &str) -> Option<usize> {
	super::command::literal_announcement_in_line(line)
		.filter(|literal| !literal.synchronizing)
		.map(|literal| literal.size)
}

impl Session {
	#[cfg(test)]
	fn rev2_enabled(&self) -> bool {
		self.imap4rev2
	}

	/// The greeting sent when the connection opens.
	pub fn greeting(&self) -> Output {
		Output::text(format!(
			"* OK [CAPABILITY {}] {} IMAP4rev2 ready\r\n",
			self.capabilities(),
			self.hostname
		))
	}

	/// Feed one command line (CRLF stripped).
	pub fn command_line(&mut self, line: &str) -> Output {
		let tagged = match super::command::parse_line(line) {
			Ok(Line::Command(tagged)) => tagged,
			Ok(Line::Login(request)) => {
				return self.login(&request.tag, request.username(), request.password());
			}
			Ok(Line::Authenticate(request)) => {
				return self.auth(&request.tag, &request.mechanism, request.initial);
			}
			Err(ParseError::Malformed) => {
				return Output::text("* BAD malformed command\r\n".to_string());
			}
			Err(ParseError::Unknown(tag)) => {
				return Output::text(format!("{tag} BAD unknown command\r\n"));
			}
			Err(ParseError::BadArguments(tag)) => {
				// RFC 7888 §4: when an APPEND/REPLACE command fails to parse
				// but the line announced a non-synchronizing literal, the
				// payload is already on the wire and must be discarded so it
				// does not arrive as the next command.
				let mut output = Output::text(format!("{tag} BAD invalid arguments\r\n"));
				output.discard_literal = sent_literal(line);
				return output;
			}
			Err(ParseError::TooBig(tag)) => {
				// A non-synchronizing literal above the limit never gets
				// here from the network layer, which closes the connection
				// instead of reading it; the drain covers direct callers.
				let mut output =
					Output::text(format!("{tag} NO [TOOBIG] message exceeds APPENDLIMIT\r\n"));
				output.discard_literal = sent_literal(line);
				return output;
			}
		};
		self.apply_enabling_condstore(tagged)
	}

	fn apply(&mut self, mut tagged: Tagged) -> Output {
		if self.utf8_names() {
			utf8::to_stored_names(&mut tagged.command);
		}
		let tag = tagged.tag;
		if self.imap4rev2 && helpers::recent_command(&tagged.command) {
			return Output::text(format!("{tag} BAD invalid arguments\r\n"));
		}
		// UIDONLY (RFC 9586): refuse commands that use message sequence numbers.
		if self.uidonly
			&& let Some(verb) = helpers::sequence_command(&tagged.command)
		{
			return Output::text(format!(
				"{tag} BAD [UIDREQUIRED] {verb} requires UID under UIDONLY\r\n"
			));
		}
		// SEARCHRES (RFC 5182): `$` outside a matching SEARCHRES-saved set is
		// a protocol error. Detect here so the consumer commands can rely on
		// `saved_search_ok` always being true when they reach their inner loop.
		if let Some((verb, uid_kind, set)) = helpers::dollar_command(&tagged.command)
			&& set.saved
			&& !self.saved_search_ok(uid_kind)
		{
			return Output::text(format!("{tag} NO [SEARCHRES] $ invalid for {verb}\r\n"));
		}
		match tagged.command {
			Command::Capability => Output::text(format!(
				"* CAPABILITY {}\r\n{tag} OK CAPABILITY completed\r\n",
				self.capabilities()
			)),
			Command::StartTls => {
				if !self.tls_available {
					return Output::text(format!("{tag} BAD TLS already active\r\n"));
				}
				let mut output = Output::text(format!("{tag} OK begin TLS now\r\n"));
				output.upgrade_tls = true;
				output
			}
			Command::Compress { algorithm } => {
				if algorithm != "DEFLATE" {
					return Output::text(format!("{tag} BAD unsupported COMPRESS algorithm\r\n"));
				}
				if self.compressing {
					// RFC 4978 §3: a second COMPRESS is NO, not BAD. The
					// command is well formed; the state is wrong.
					return Output::text(format!(
						"{tag} NO [COMPRESSIONACTIVE] compression is already active\r\n"
					));
				}
				self.compressing = true;
				let mut output = Output::text(format!("{tag} OK begin compression now\r\n"));
				output.compress = true;
				output
			}
			Command::Noop => self.noop(&tag),
			Command::Check => self.check(&tag),
			// One personal namespace rooted at "" with "/" separator (RFC 2342).
			// NAMESPACE is post-auth (RFC 9051 §6.3.5); before authentication it
			// must refuse the command without leaking the namespace layout.
			Command::Namespace => {
				if self.account().is_none() {
					return Output::text(format!("{tag} NO not authenticated\r\n"));
				}
				Output::text(format!(
					"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{tag} OK NAMESPACE completed\r\n"
				))
			}
			Command::Id => Output::text(format!("* ID NIL\r\n{tag} OK ID completed\r\n")),
			Command::Logout => Output::closing(format!(
				"* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"
			)),
			Command::List(list) => self.list(&tag, &list),
			Command::Select { mailbox, qresync } => self.select(&tag, &mailbox, false, qresync),
			Command::Examine { mailbox, qresync } => self.select(&tag, &mailbox, true, qresync),
			Command::Close => self.close(&tag),
			Command::Unselect => self.unselect(&tag),
			Command::Enable { capabilities } => self.enable(&tag, &capabilities),
			Command::GetQuotaRoot { mailbox } => self.get_quota_root(&tag, &mailbox),
			Command::GetQuota { root } => self.get_quota(&tag, &root),
			Command::Create { mailbox } => self.mailbox_op(&tag, "CREATE", |dir, account| {
				mailbox::create(dir, account, &mailbox)
			}),
			Command::Delete { mailbox } => self.mailbox_op(&tag, "DELETE", |dir, account| {
				mailbox::delete(dir, account, &mailbox)
			}),
			Command::Rename { from, to } => self.mailbox_op(&tag, "RENAME", |dir, account| {
				mailbox::rename(dir, account, &from, &to)
			}),
			Command::Expunge => self.expunge(&tag),
			Command::UidExpunge { sequence } => self.uid_expunge(&tag, &sequence),
			Command::Sort {
				keys,
				criteria,
				uid,
			} => self.sort(&tag, &keys, &criteria, uid),
			Command::Thread {
				algorithm,
				criteria,
				uid,
			} => match algorithm {
				ThreadAlgorithm::OrderedSubject => self.thread(&tag, &criteria, uid),
				ThreadAlgorithm::References => self.thread_references(&tag, &criteria, uid),
			},
			Command::Idle => {
				if self.account().is_none() {
					return Output::text(format!("{tag} NO not authenticated\r\n"));
				}
				let mut output = Output::text("+ idling\r\n".to_string());
				output.idle = true;
				self.idle_tag = Some(tag);
				output
			}
			Command::Append {
				mailbox,
				flags,
				date,
				size,
				synchronizing,
				utf8,
				binary,
			} => self.append_begin(
				&tag,
				&mailbox,
				&flags,
				date,
				(size, synchronizing),
				literal::AppendForm { utf8, binary },
			),
			Command::Replace {
				sequence,
				mailbox,
				flags,
				date,
				size,
				uid,
				synchronizing,
			} => self.replace_begin(
				&tag,
				sequence,
				&mailbox,
				&flags,
				date,
				size,
				uid,
				synchronizing,
			),
			Command::Fetch {
				sequence,
				items,
				uid,
				changed_since,
				vanished,
			} => self.fetch(&tag, &sequence, &items, uid, changed_since, vanished),
			Command::Store {
				sequence,
				mode,
				flags,
				silent,
				uid,
				unchanged_since,
			} => self.store(&tag, &sequence, mode, &flags, silent, uid, unchanged_since),
			Command::Copy {
				sequence,
				mailbox,
				uid,
				remove_source,
			} => self.copy(&tag, &sequence, &mailbox, uid, remove_source),
			Command::Search {
				criteria,
				uid,
				return_opts,
			} => self.search(&tag, &criteria, uid, return_opts.as_deref()),
			Command::Esearch {
				sources,
				criteria,
				return_opts,
			} => self.esearch(&tag, &sources, &criteria, &return_opts),
			Command::Status { mailbox, items } => self.status(&tag, &mailbox, &items),
			Command::Subscribe { mailbox } => self.subscription_op(&tag, |data_dir, account| {
				mailbox::subscribe(data_dir, account, &mailbox)
			}),
			Command::Unsubscribe { mailbox } => self.subscription_op(&tag, |data_dir, account| {
				mailbox::unsubscribe(data_dir, account, &mailbox)
			}),
			Command::Lsub { reference, pattern } => self.lsub(&tag, &reference, &pattern),
			Command::GetAcl { mailbox } => self.get_acl(&tag, &mailbox),
			Command::MyRights { mailbox } => self.my_rights(&tag, &mailbox),
			Command::ListRights {
				mailbox,
				identifier,
			} => self.list_rights(&tag, &mailbox, &identifier),
			Command::SetAcl {
				mailbox,
				identifier,
				rights,
			} => self.set_acl(&tag, &mailbox, &identifier, &rights),
			Command::DeleteAcl {
				mailbox,
				identifier,
			} => self.delete_acl(&tag, &mailbox, &identifier),
			Command::GetMetadata { mailbox, entries } => {
				self.get_metadata(&tag, &mailbox, &entries)
			}
			Command::SetMetadata { mailbox, items } => self.set_metadata(&tag, &mailbox, &items),
			Command::Notify(request) => self.notify(&tag, request),
		}
	}

	fn login(&mut self, tag: &str, username: &str, password: &str) -> Output {
		if !self.tls_active {
			return Output::text(format!("{tag} NO [PRIVACYREQUIRED] STARTTLS first\r\n"));
		}
		let State::NotAuthenticated { login_failures } = &mut self.state else {
			return Output::text(format!("{tag} BAD already authenticated\r\n"));
		};
		let verdict = self.directory.authenticate_verdict(
			username,
			password,
			self.peer_ip,
			self.auth_protocol,
		);
		match verdict {
			Verdict::Admitted { account, .. } => self.auth_success(tag, account, "LOGIN completed"),
			Verdict::Busy => Output::text(format!("{tag} NO [UNAVAILABLE] Try again later\r\n")),
			Verdict::Refused => {
				*login_failures += 1;
				let response = format!("{tag} NO LOGIN failed\r\n");
				if *login_failures >= 3 {
					Output::closing(format!("* BYE too many failures\r\n{response}"))
				} else {
					Output::text(response)
				}
			}
		}
	}

	fn account(&self) -> Option<&str> {
		match &self.state {
			State::NotAuthenticated { .. } => None,
			State::Authenticated { account } | State::Selected { account, .. } => Some(account),
		}
	}

	/// Whether a `$`-using command is acceptable: the saved set exists and
	/// its kind matches `uid_kind`. Empty after a consumed search or a
	/// missing save — the caller answers `NO` to the client.
	fn saved_search_ok(&self, uid_kind: bool) -> bool {
		matches!(self.saved_search, Some(ref s) if s.are_uids == uid_kind)
	}

	fn mailbox_op(
		&mut self,
		tag: &str,
		verb: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK {verb} completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
		}
	}

	/// ENABLE (RFC 5161): echo only the extensions we support (RFC 7162).
	fn enable(&mut self, tag: &str, capabilities: &[String]) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} BAD ENABLE only after authentication\r\n"));
		}
		// UIDONLY (RFC 9586) must be enabled before a mailbox is selected.
		if capabilities
			.iter()
			.any(|c| c.eq_ignore_ascii_case("UIDONLY"))
			&& matches!(self.state, State::Selected { .. })
		{
			return Output::text(format!("{tag} BAD UIDONLY not allowed when selected\r\n"));
		}
		let enabled: Vec<&str> = capabilities
			.iter()
			.filter_map(|cap| match cap.to_ascii_uppercase().as_str() {
				"IMAP4REV2" => {
					self.imap4rev2 = true;
					Some("IMAP4rev2")
				}
				"CONDSTORE" => Some("CONDSTORE"),
				"QRESYNC" => Some("QRESYNC"),
				"UIDONLY" => {
					self.uidonly = true;
					Some("UIDONLY")
				}
				"UTF8=ACCEPT" => {
					self.utf8_accept = true;
					Some("UTF8=ACCEPT")
				}
				_ => None,
			})
			.collect();
		Output::text(format!(
			"* ENABLED {}\r\n{tag} OK ENABLE completed\r\n",
			enabled.join(" ")
		))
	}

	/// Called by the network layer when an IDLE ends with DONE.
	pub fn idle_done(&mut self) -> Output {
		match self.idle_tag.take() {
			Some(tag) => Output::text(format!("{tag} OK IDLE terminated\r\n")),
			None => Output::text("* BAD not idling\r\n".to_string()),
		}
	}

	/// NOOP (RFC 9051 §7.1.2). The only required reply is the tagged OK,
	/// but NOOP is the client's poll: it carries every change to the
	/// SELECTed mailbox since the client last heard about it, as EXPUNGE,
	/// FETCH FLAGS and EXISTS (see [`Self::sync_selected`]).
	fn noop(&mut self, tag: &str) -> Output {
		let updates = self.sync_selected(true);
		Output::text(format!("{updates}{tag} OK NOOP completed\r\n"))
	}

	/// `(account, mailbox)` for the SELECTed state, or `None` for any
	/// other state. Cloned names release the mutable borrow on
	/// `self.state` so the caller can re-borrow as needed.
	fn selected_pair(&self) -> Option<(String, String)> {
		match &self.state {
			State::Selected {
				account, mailbox, ..
			} => Some((account.clone(), mailbox.clone())),
			_ => None,
		}
	}
}

#[cfg(test)]
#[path = "session_tests.rs"]
pub(crate) mod tests;
