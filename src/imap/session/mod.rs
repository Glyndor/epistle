//! IMAP session state machine (sans-IO).

use super::command::{Command, FetchItem, ParseError, SearchKey, StoreMode, Tagged};
use super::mailbox;

mod acl;
mod auth;
mod codes;
mod commands;
mod expunge;
mod fetchstore;
mod helpers;
mod idle;
mod list_status;
mod literal;
mod lsub;
mod metadata;
mod notify;
mod quota;
mod select;
mod sort;
mod state;
mod thread;

pub use state::{DEFAULT_QUOTA_BYTES, Output, PendingLiteral, SavedSearch, Session, State};

impl Session {
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
		let tagged = match super::command::parse(line) {
			Ok(tagged) => tagged,
			Err(ParseError::Malformed) => {
				return Output::text("* BAD malformed command\r\n".to_string());
			}
			Err(ParseError::Unknown(tag)) => {
				return Output::text(format!("{tag} BAD unknown command\r\n"));
			}
			Err(ParseError::BadArguments(tag)) => {
				return Output::text(format!("{tag} BAD invalid arguments\r\n"));
			}
		};
		self.apply(tagged)
	}

	fn apply(&mut self, tagged: Tagged) -> Output {
		let tag = tagged.tag;
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
			Command::Noop => Output::text(format!("{tag} OK NOOP completed\r\n")),
			// One personal namespace rooted at "" with "/" separator (RFC 2342).
			Command::Namespace => Output::text(format!(
				"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n{tag} OK NAMESPACE completed\r\n"
			)),
			Command::Id => Output::text(format!(
				"* ID (\"name\" \"Glyndor\" \"version\" \"{}\")\r\n{tag} OK ID completed\r\n",
				env!("CARGO_PKG_VERSION"),
			)),
			Command::Logout => Output::closing(format!(
				"* BYE logging out\r\n{tag} OK LOGOUT completed\r\n"
			)),
			Command::Login { username, password } => self.login(&tag, &username, &password),
			Command::Authenticate { mechanism, initial } => self.auth(&tag, &mechanism, initial),
			Command::List {
				pattern,
				return_status,
				select_subscribed,
				..
			} => self.list(&tag, &pattern, &return_status, select_subscribed),
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
			Command::Thread { criteria, uid } => self.thread(&tag, &criteria, uid),
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
				size,
			} => self.append_begin(&tag, &mailbox, &flags, size),
			Command::Replace {
				sequence,
				mailbox,
				flags,
				size,
				uid,
			} => self.replace_begin(&tag, sequence, &mailbox, &flags, size, uid),
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
			Command::Lsub { pattern, .. } => self.lsub(&tag, &pattern),
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
		let verified = self.directory.authenticate(username, password);
		match verified {
			Some(account) => {
				self.state = State::Authenticated { account };
				Output::text(format!("{tag} OK LOGIN completed\r\n"))
			}
			None => {
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

	/// Resolve the SEARCHRES `$` placeholder against this session's saved set.
	/// Returns `None` when `$` is not in use, `Some(values)` when it is — the
	/// caller already knows whether a `$` was used (because it parsed the
	/// SequenceSet), so `None` here means "no saved set to read". The caller
	/// should reject the command with NO before doing any matching when
	/// `saved_search_ok` is false.
	fn saved_seqnos_for(&self, uid_kind: bool) -> Vec<u32> {
		match &self.saved_search {
			Some(saved) if saved.are_uids == uid_kind => saved.values.clone(),
			_ => Vec::new(),
		}
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
				"IMAP4REV2" => Some("IMAP4rev2"),
				"CONDSTORE" => Some("CONDSTORE"),
				"QRESYNC" => Some("QRESYNC"),
				"UIDONLY" => {
					self.uidonly = true;
					Some("UIDONLY")
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
}

#[cfg(test)]
#[path = "session_tests.rs"]
pub(crate) mod tests;
