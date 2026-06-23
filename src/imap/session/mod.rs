//! IMAP session state machine (sans-IO).

use std::path::PathBuf;
use std::sync::Arc;

use crate::smtp::directory::Directory;

use super::command::{
	Command, FetchItem, NotifyEvent, ParseError, SearchKey, StatusItem, StoreMode, Tagged,
};
use super::mailbox::{self, Flag, Snapshot};

mod acl;
mod auth;
mod codes;
mod commands;
mod fetchstore;
mod helpers;
mod literal;
mod metadata;
mod sort;
mod thread;

/// Server output produced by one step: complete response lines/literals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
	pub bytes: Vec<u8>,
	pub close: bool,
	pub collect_literal: Option<usize>,
	pub idle: bool,
	pub upgrade_tls: bool,
	pub collect_auth: bool,
}

impl Output {
	fn text(text: String) -> Self {
		Output {
			bytes: text.into_bytes(),
			close: false,
			collect_literal: None,
			idle: false,
			upgrade_tls: false,
			collect_auth: false,
		}
	}

	fn closing(text: String) -> Self {
		Output {
			close: true,
			..Output::text(text)
		}
	}
}

/// A literal-bearing command (APPEND or REPLACE) awaiting its payload.
struct PendingLiteral {
	tag: String,
	mailbox: String,
	flags: Vec<Flag>,
	/// For REPLACE only: the selected mailbox to expunge from and the source
	/// message sequence number, resolved when the command was received.
	replace: Option<(String, u32)>,
}

enum State {
	NotAuthenticated {
		login_failures: u8,
	},
	Authenticated {
		account: String,
	},
	Selected {
		account: String,
		mailbox: String,
		snapshot: Snapshot,
		read_only: bool,
	},
}

/// One IMAP connection's protocol state.
pub struct Session {
	hostname: String,
	data_dir: PathBuf,
	directory: Arc<Directory>,
	state: State,
	pending_append: Option<PendingLiteral>,
	/// UIDONLY (RFC 9586) enabled: sequence-number commands are refused and
	/// responses use UID forms (UIDFETCH, VANISHED).
	uidonly: bool,
	idle_tag: Option<String>,
	/// NOTIFY (RFC 5465) events requested for the selected mailbox. `None` means
	/// NOTIFY is not active; an empty set means notifications are explicitly off.
	notify_selected: Option<Vec<NotifyEvent>>,
	/// Whether the connection is inside TLS (LOGIN refused outside).
	tls_active: bool,
	tls_available: bool,
	quota_limit_bytes: u64,
	pending_auth: Option<auth::PendingAuth>,
	scram_nonce: Option<String>,
	oauth: Option<Arc<crate::oauth::OauthVerifier>>,
	/// `tls-server-end-point` channel-binding data (server certificate hash)
	/// when known; enables AUTH=SCRAM-SHA-256-PLUS.
	cbind_data: Option<Vec<u8>>,
	/// Verified TLS client-certificate identity (email SAN), enabling SASL
	/// EXTERNAL. Set by the network layer after a client-cert handshake.
	client_identity: Option<String>,
}

/// Default per-account storage quota in bytes (5 GiB).
pub const DEFAULT_QUOTA_BYTES: u64 = 5 * 1024 * 1024 * 1024;

impl Session {
	/// New session over an established TLS connection.
	pub fn new(hostname: &str, data_dir: PathBuf, directory: Arc<Directory>) -> Self {
		Session {
			hostname: hostname.to_string(),
			data_dir,
			directory,
			state: State::NotAuthenticated { login_failures: 0 },
			pending_append: None,
			uidonly: false,
			idle_tag: None,
			notify_selected: None,
			tls_active: true,
			tls_available: false,
			quota_limit_bytes: DEFAULT_QUOTA_BYTES,
			pending_auth: None,
			scram_nonce: None,
			oauth: None,
			cbind_data: None,
			client_identity: None,
		}
	}

	/// Set the verified TLS client-certificate identity (email), enabling SASL
	/// EXTERNAL for this connection.
	pub fn set_client_identity(&mut self, identity: Option<String>) {
		self.client_identity = identity;
	}

	/// Set the default storage quota (bytes) used when an account has no
	/// per-account or per-domain quota of its own.
	pub fn with_quota_limit(mut self, bytes: u64) -> Self {
		self.quota_limit_bytes = bytes;
		self
	}

	/// The storage quota in force for the authenticated account: its own /
	/// domain quota from the directory, else the server default.
	fn effective_quota(&self) -> u64 {
		self.account()
			.and_then(|account| self.directory.quota_for(account))
			.unwrap_or(self.quota_limit_bytes)
	}

	/// Provide the `tls-server-end-point` channel-binding data (server
	/// certificate hash), enabling AUTH=SCRAM-SHA-256-PLUS.
	pub fn with_channel_binding(mut self, cert_hash: Vec<u8>) -> Self {
		self.cbind_data = Some(cert_hash);
		self
	}

	/// Mark this session as starting in plaintext with STARTTLS available.
	pub fn with_starttls(mut self) -> Self {
		self.tls_active = false;
		self.tls_available = true;
		self
	}

	pub fn tls_started(&mut self) {
		self.tls_active = true;
		self.tls_available = false;
		self.state = State::NotAuthenticated { login_failures: 0 };
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
			&& let Some(verb) = sequence_command(&tagged.command)
		{
			return Output::text(format!(
				"{tag} BAD [UIDREQUIRED] {verb} requires UID under UIDONLY\r\n"
			));
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

	fn select(
		&mut self,
		tag: &str,
		mailbox: &str,
		read_only: bool,
		qresync: Option<(u32, u64)>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot = match Snapshot::open(&self.data_dir, &account, mailbox) {
			Ok(snapshot) => snapshot,
			Err(_) => return Output::text(format!("{tag} NO cannot open mailbox\r\n")),
		};
		// QRESYNC: report vanished UIDs, but only if UIDVALIDITY still matches.
		let vanished = match qresync {
			Some((uid_validity, modseq)) if uid_validity == snapshot.uid_validity() => {
				let uids = snapshot.vanished_since(modseq);
				if uids.is_empty() {
					String::new()
				} else {
					format!("* VANISHED (EARLIER) {}\r\n", codes::uid_set(&uids))
				}
			}
			_ => String::new(),
		};
		let response = format!(
			"* {count} EXISTS\r\n\
* OK [UIDVALIDITY {validity}] UIDs valid\r\n\
* OK [UIDNEXT {next}] predicted next UID\r\n\
* OK [MAILBOXID (M{validity})] mailbox object id\r\n\
* OK [HIGHESTMODSEQ {modseq}] highest mod-sequence\r\n\
* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n\
* OK [PERMANENTFLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)] limits\r\n\
{vanished}{tag} OK [{mode}] {verb} completed\r\n",
			count = snapshot.len(),
			validity = snapshot.uid_validity(),
			next = snapshot.uid_next(),
			modseq = snapshot.highest_modseq(),
			mode = if read_only { "READ-ONLY" } else { "READ-WRITE" },
			verb = if read_only { "EXAMINE" } else { "SELECT" },
		);
		self.state = State::Selected {
			account,
			mailbox: mailbox.to_string(),
			snapshot,
			read_only,
		};
		Output::text(response)
	}

	fn close(&mut self, tag: &str) -> Output {
		match &self.state {
			State::Selected { account, .. } => {
				self.state = State::Authenticated {
					account: account.clone(),
				};
				Output::text(format!("{tag} OK CLOSE completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		}
	}

	/// UNSELECT (RFC 3691): leave the mailbox without expunging \Deleted.
	fn unselect(&mut self, tag: &str) -> Output {
		match &self.state {
			State::Selected { account, .. } => {
				self.state = State::Authenticated {
					account: account.clone(),
				};
				Output::text(format!("{tag} OK UNSELECT completed\r\n"))
			}
			_ => Output::text(format!("{tag} BAD no mailbox selected\r\n")),
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

	fn lsub(&mut self, tag: &str, pattern: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let mut response = String::new();
		for name in mailbox::list_subscribed(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			if matches {
				response.push_str(&format!("* LSUB () \"/\" \"{name}\"\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LSUB completed\r\n"));
		Output::text(response)
	}

	fn subscription_op(
		&mut self,
		tag: &str,
		operation: impl FnOnce(&std::path::Path, &str) -> std::io::Result<()>,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match operation(&self.data_dir, &account) {
			Ok(()) => Output::text(format!("{tag} OK completed\r\n")),
			Err(error) => Output::text(format!("{tag} NO {error}\r\n")),
		}
	}
}

/// The command verb when it relies on message sequence numbers (and so is
/// refused under UIDONLY), or `None` for UID-based and non-sequence commands.
fn sequence_command(command: &Command) -> Option<&'static str> {
	match command {
		Command::Fetch { uid: false, .. } => Some("FETCH"),
		Command::Store { uid: false, .. } => Some("STORE"),
		Command::Search { uid: false, .. } => Some("SEARCH"),
		Command::Sort { uid: false, .. } => Some("SORT"),
		Command::Thread { uid: false, .. } => Some("THREAD"),
		Command::Copy {
			uid: false,
			remove_source,
			..
		} => Some(if *remove_source { "MOVE" } else { "COPY" }),
		_ => None,
	}
}

#[cfg(test)]
#[path = "session_tests.rs"]
mod tests;
