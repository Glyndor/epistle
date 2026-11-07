//! Dispatch of a parsed command to the handler that owns it.
//!
//! The command vocabulary lives in [`crate::imap::command`]; each arm below
//! names the method that answers it. The handlers live in the folders beside
//! this one: [`super::commands`] for the ones that read messages and
//! [`super::mailboxes`] for the ones that act on a mailbox.

use super::super::command::{Command, ThreadAlgorithm};
use super::{Output, Session};

impl Session {
	/// Answer one command with the tag it arrived under.
	pub(in crate::imap::session) fn apply(&mut self, mut tagged: super::Tagged) -> Output {
		if self.utf8_names() {
			super::commands::utf8::to_stored_names(&mut tagged.command);
		}
		let tag = tagged.tag;
		if self.imap4rev2 && super::helpers::recent_command(&tagged.command) {
			return Output::text(format!("{tag} BAD invalid arguments\r\n"));
		}
		// UIDONLY (RFC 9586): refuse commands that use message sequence numbers.
		if self.uidonly
			&& let Some(verb) = super::helpers::sequence_command(&tagged.command)
		{
			return Output::text(format!(
				"{tag} BAD [UIDREQUIRED] {verb} requires UID under UIDONLY\r\n"
			));
		}
		// SEARCHRES (RFC 5182): `$` outside a matching SEARCHRES-saved set is
		// a protocol error. Detect here so the consumer commands can rely on
		// `saved_search_ok` always being true when they reach their inner loop.
		if let Some((verb, uid_kind, set)) = super::helpers::dollar_command(&tagged.command)
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
				super::mailbox::create(dir, account, &mailbox)
			}),
			Command::Delete { mailbox } => self.mailbox_op(&tag, "DELETE", |dir, account| {
				super::mailbox::delete(dir, account, &mailbox)
			}),
			Command::Rename { from, to } => self.mailbox_op(&tag, "RENAME", |dir, account| {
				super::mailbox::rename(dir, account, &from, &to)
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
				super::commands::literal::AppendForm { utf8, binary },
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
				super::mailbox::subscribe(data_dir, account, &mailbox)
			}),
			Command::Unsubscribe { mailbox } => self.subscription_op(&tag, |data_dir, account| {
				super::mailbox::unsubscribe(data_dir, account, &mailbox)
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
}
