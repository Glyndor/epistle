use super::super::command::{NotifyEvent, NotifyRequest, ReturnOpt, SearchScope, SequenceSet};
use super::codes::{copyuid_code, esearch_line, esearch_multi_line};
use super::helpers::search_matches;
use super::mailbox::{self, Flag, Snapshot};
use super::{Output, SearchKey, Session, State, StatusItem};

impl Session {
	pub(super) fn copy(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		target: &str,
		uid: bool,
		remove_source: bool,
	) -> Output {
		let uidonly = self.uidonly;
		let data_dir = self.data_dir.clone();
		let State::Selected {
			account,
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if remove_source && *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let account = account.clone();
		if !mailbox::exists(&data_dir, &account, target) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut matched = Vec::new();
		let mut source_uids = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if sequence.contains(selector, total) {
				matched.push(sequence_number);
				source_uids.push(message.uid);
			}
		}

		// Copy all before removing any: a failed copy must not lose mail.
		let mut dest_ids = Vec::new();
		for sequence_number in &matched {
			let Some(message) = snapshot.by_sequence(*sequence_number) else {
				return Output::text(format!("{tag} NO message vanished\r\n"));
			};
			let data = match snapshot.read(message) {
				Ok(data) => data,
				Err(_) => return Output::text(format!("{tag} NO message unavailable\r\n")),
			};
			match mailbox::append(&data_dir, &account, target, &message.flags, &data) {
				Ok(id) => dest_ids.push(id),
				Err(_) => return Output::text(format!("{tag} NO copy failed\r\n")),
			}
		}

		// UIDPLUS: the source and destination UID sets (RFC 4315).
		let copyuid = copyuid_code(&data_dir, &account, target, &source_uids, &dest_ids);

		let mut response = String::new();
		if remove_source {
			// Remove bottom-up so earlier sequence numbers stay valid, but
			// emit EXPUNGE top-down with renumber-correct values.
			for (offset, sequence_number) in matched.iter().enumerate() {
				let current = sequence_number - u32::try_from(offset).unwrap_or(0);
				if snapshot.remove_at(current).is_err() {
					return Output::text(format!("{tag} NO move failed\r\n"));
				}
				if !uidonly {
					response.push_str(&format!("* {current} EXPUNGE\r\n"));
				}
			}
			// UIDONLY: report removals as a single VANISHED with UIDs.
			if uidonly && !source_uids.is_empty() {
				response.push_str(&format!(
					"* VANISHED {}\r\n",
					super::codes::uid_set(&source_uids)
				));
			}
		}
		let verb = if remove_source { "MOVE" } else { "COPY" };
		response.push_str(&format!("{tag} OK {copyuid}{verb} completed\r\n"));
		Output::text(response)
	}

	pub(super) fn search(
		&mut self,
		tag: &str,
		criteria: &[SearchKey],
		uid: bool,
		return_opts: Option<&[ReturnOpt]>,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut hits = Vec::new();
		for seqno in 1..=total {
			let Some(message) = snapshot.by_sequence(seqno) else {
				continue;
			};
			let mut content: Option<String> = None;
			let matches = criteria
				.iter()
				.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content));
			if matches {
				hits.push(if uid { message.uid } else { seqno });
			}
		}

		let body = match return_opts {
			Some(opts) => esearch_line(tag, uid, &hits, opts),
			None => {
				let mut line = String::from("* SEARCH");
				for hit in &hits {
					line.push_str(&format!(" {hit}"));
				}
				line.push_str("\r\n");
				line
			}
		};
		Output::text(format!("{body}{tag} OK SEARCH completed\r\n"))
	}

	/// MULTISEARCH (RFC 7377): search every resolved mailbox and emit one
	/// `* ESEARCH` line per mailbox that produced output. Results are always
	/// UIDs, correlated by `MAILBOX`/`UIDVALIDITY`.
	pub(super) fn esearch(
		&mut self,
		tag: &str,
		sources: &[SearchScope],
		criteria: &[SearchKey],
		return_opts: &[ReturnOpt],
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} BAD not authenticated\r\n"));
		};

		let mut mailboxes = match self.resolve_scopes(sources, &account) {
			Some(mailboxes) => mailboxes,
			None => return Output::text(format!("{tag} BAD no mailbox selected\r\n")),
		};
		mailboxes.dedup();

		let mut body = String::new();
		for name in &mailboxes {
			let Ok(snapshot) = Snapshot::open(&self.data_dir, &account, name) else {
				continue;
			};
			let hits = matching_uids(&snapshot, criteria);
			body.push_str(&esearch_multi_line(
				tag,
				name,
				snapshot.uid_validity(),
				&hits,
				return_opts,
			));
		}
		Output::text(format!("{body}{tag} OK SEARCH completed\r\n"))
	}

	/// Resolve MULTISEARCH source scopes to a concrete, ordered mailbox list.
	/// Returns `None` only when `selected` is requested without a selected
	/// mailbox (a protocol error).
	fn resolve_scopes(&self, sources: &[SearchScope], account: &str) -> Option<Vec<String>> {
		let mut names = Vec::new();
		for source in sources {
			match source {
				SearchScope::Selected => match &self.state {
					State::Selected { mailbox, .. } => names.push(mailbox.clone()),
					_ => return None,
				},
				SearchScope::Inboxes => names.push("INBOX".to_string()),
				SearchScope::Personal => {
					names.extend(mailbox::list(&self.data_dir, account));
				}
				SearchScope::Subscribed => {
					names.extend(mailbox::list_subscribed(&self.data_dir, account));
				}
				SearchScope::Subtree(roots) => {
					names.extend(subtree(&self.data_dir, account, roots, false));
				}
				SearchScope::SubtreeOne(roots) => {
					names.extend(subtree(&self.data_dir, account, roots, true));
				}
				SearchScope::Mailboxes(list) => names.extend(list.iter().cloned()),
			}
		}
		Some(names)
	}

	pub(super) fn expunge(&mut self, tag: &str) -> Output {
		let uidonly = self.uidonly;
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		// UIDONLY reports VANISHED with UIDs, captured before they are removed.
		let deleted_uids: Vec<u32> = snapshot
			.messages()
			.filter(|m| m.flags.contains(&Flag::Deleted))
			.map(|m| m.uid)
			.collect();
		match snapshot.expunge() {
			Ok(expunged) => {
				let response = expunge_response(uidonly, &expunged, &deleted_uids);
				Output::text(format!("{response}{tag} OK EXPUNGE completed\r\n"))
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}

	/// GETQUOTAROOT: report the quota root of a mailbox and its quota.
	pub(super) fn get_quota_root(&self, tag: &str, mailbox: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let quota = self.quota_line(&account);
		Output::text(format!(
			"* QUOTAROOT {mailbox} \"\"\r\n{quota}{tag} OK GETQUOTAROOT completed\r\n"
		))
	}

	/// GETQUOTA: report the quota for a root (only the empty root exists).
	pub(super) fn get_quota(&self, tag: &str, root: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !root.is_empty() {
			return Output::text(format!("{tag} NO unknown quota root\r\n"));
		}
		let quota = self.quota_line(&account);
		Output::text(format!("{quota}{tag} OK GETQUOTA completed\r\n"))
	}

	/// The `* QUOTA` line for an account: STORAGE used/limit in 1024-octet units.
	fn quota_line(&self, account: &str) -> String {
		let used_kib = mailbox::account_usage(&self.data_dir, account).div_ceil(1024);
		let limit_kib = self.effective_quota().div_ceil(1024);
		format!("* QUOTA \"\" (STORAGE {used_kib} {limit_kib})\r\n")
	}

	pub(super) fn uid_expunge(&mut self, tag: &str, sequence: &SequenceSet) -> Output {
		let uidonly = self.uidonly;
		let State::Selected {
			snapshot,
			read_only,
			..
		} = &mut self.state
		else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};
		if *read_only {
			return Output::text(format!("{tag} NO mailbox is read-only\r\n"));
		}
		let max_uid = snapshot.messages().map(|m| m.uid).max().unwrap_or(0);
		let uids: Vec<u32> = snapshot
			.messages()
			.map(|m| m.uid)
			.filter(|uid| sequence.contains(*uid, max_uid))
			.collect();
		// The UIDs actually removed are the in-set ones flagged \Deleted.
		let deleted_uids: Vec<u32> = snapshot
			.messages()
			.filter(|m| m.flags.contains(&Flag::Deleted) && uids.contains(&m.uid))
			.map(|m| m.uid)
			.collect();
		match snapshot.expunge_uids(&uids) {
			Ok(expunged) => {
				let response = expunge_response(uidonly, &expunged, &deleted_uids);
				Output::text(format!("{response}{tag} OK EXPUNGE completed\r\n"))
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}

	/// Poll for mailbox changes during IDLE. Refreshes the snapshot and emits
	/// untagged EXISTS/FLAGS responses if the message count changed. Returns
	/// `None` when not in IDLE or no mailbox is selected.
	pub fn check_idle(&mut self) -> Option<Output> {
		self.idle_tag.as_ref()?;
		let State::Selected {
			account,
			mailbox,
			snapshot,
			..
		} = &mut self.state
		else {
			return None;
		};
		let fresh = match Snapshot::open(&self.data_dir, account, mailbox) {
			Ok(s) => s,
			Err(_) => return None,
		};
		if fresh.uid_validity() != snapshot.uid_validity() || fresh.len() != snapshot.len() {
			let exists = fresh.len();
			*snapshot = fresh;
			Some(Output::text(format!("* {exists} EXISTS\r\n")))
		} else {
			None
		}
	}

	/// NOTIFY (RFC 5465): record which selected-mailbox events the client wants
	/// pushed unsolicited. Other mailbox specifiers were accepted-and-ignored at
	/// parse time. Requires authentication.
	pub(super) fn notify(&mut self, tag: &str, request: NotifyRequest) -> Output {
		if self.account().is_none() {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		}
		match request {
			NotifyRequest::None => self.notify_selected = None,
			NotifyRequest::Set { selected, .. } => self.notify_selected = Some(selected),
		}
		Output::text(format!("{tag} OK NOTIFY completed\r\n"))
	}

	/// Poll for mailbox changes for a NOTIFY-enabled session, mirroring
	/// [`Self::check_idle`] but gated on active NOTIFY `selected` events rather
	/// than IDLE. Returns an unsolicited `* <n> EXISTS` when the selected mailbox
	/// gained or lost messages and the client asked for
	/// MessageNew/MessageExpunge.
	pub fn check_notify(&mut self) -> Option<Output> {
		if !self.notify_active() {
			return None;
		}
		let State::Selected {
			account,
			mailbox,
			snapshot,
			..
		} = &mut self.state
		else {
			return None;
		};
		let fresh = Snapshot::open(&self.data_dir, account, mailbox).ok()?;
		if fresh.uid_validity() != snapshot.uid_validity() || fresh.len() != snapshot.len() {
			let exists = fresh.len();
			*snapshot = fresh;
			Some(Output::text(format!("* {exists} EXISTS\r\n")))
		} else {
			None
		}
	}

	/// Whether this session has NOTIFY enabled with selected-mailbox message
	/// events, so the server loop should poll between commands.
	pub fn notify_active(&self) -> bool {
		self.notify_selected.as_ref().is_some_and(|events| {
			events
				.iter()
				.any(|e| matches!(e, NotifyEvent::MessageNew | NotifyEvent::MessageExpunge))
		})
	}

	pub(super) fn list(
		&mut self,
		tag: &str,
		pattern: &str,
		return_status: &[StatusItem],
		select_subscribed: bool,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		let subscribed: std::collections::HashSet<String> =
			mailbox::list_subscribed(&self.data_dir, &account)
				.into_iter()
				.collect();
		let mut response = String::new();
		for name in mailbox::list(&self.data_dir, &account) {
			let matches = pattern == "*" || pattern == "%" || pattern.eq_ignore_ascii_case(&name);
			// LIST-EXTENDED (RFC 5258): `(SUBSCRIBED)` lists only subscribed boxes.
			if !matches || (select_subscribed && !subscribed.contains(&name)) {
				continue;
			}
			let mut attributes = super::helpers::special_use_attribute(&name).to_string();
			if subscribed.contains(&name) {
				if !attributes.is_empty() {
					attributes.push(' ');
				}
				attributes.push_str("\\Subscribed");
			}
			response.push_str(&format!("* LIST ({attributes}) \"/\" \"{name}\"\r\n"));
			// LIST-STATUS (RFC 5819): report the requested STATUS inline.
			if !return_status.is_empty()
				&& let Some(parts) = self.status_parts(&account, &name, return_status)
			{
				response.push_str(&format!("* STATUS \"{name}\" ({parts})\r\n"));
			}
		}
		response.push_str(&format!("{tag} OK LIST completed\r\n"));
		Output::text(response)
	}

	pub(super) fn status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let Some(parts) = self.status_parts(&account, mailbox, items) else {
			return Output::text(format!("{tag} NO cannot open mailbox\r\n"));
		};
		Output::text(format!(
			"* STATUS \"{mailbox}\" ({parts})\r\n{tag} OK STATUS completed\r\n"
		))
	}

	/// The `ITEM value ...` body of a STATUS response, or `None` if the mailbox
	/// cannot be opened. Shared by STATUS and LIST ... RETURN (STATUS ...).
	pub(super) fn status_parts(
		&self,
		account: &str,
		mailbox: &str,
		items: &[StatusItem],
	) -> Option<String> {
		let snapshot = Snapshot::open(&self.data_dir, account, mailbox).ok()?;
		let count_flag = |flag: Flag| {
			snapshot
				.messages()
				.filter(|m| m.flags.contains(&flag))
				.count()
		};
		let mut parts = String::new();
		for (i, item) in items.iter().enumerate() {
			if i > 0 {
				parts.push(' ');
			}
			let rendered = match item {
				StatusItem::Messages => format!("MESSAGES {}", snapshot.len()),
				StatusItem::Recent => "RECENT 0".to_string(),
				StatusItem::Uidnext => format!("UIDNEXT {}", snapshot.uid_next()),
				StatusItem::Uidvalidity => format!("UIDVALIDITY {}", snapshot.uid_validity()),
				StatusItem::Unseen => {
					format!("UNSEEN {}", snapshot.len() - count_flag(Flag::Seen))
				}
				StatusItem::Size => {
					format!("SIZE {}", snapshot.messages().map(|m| m.size).sum::<u64>())
				}
				StatusItem::Deleted => format!("DELETED {}", count_flag(Flag::Deleted)),
				StatusItem::MailboxId => format!("MAILBOXID (M{})", snapshot.uid_validity()),
			};
			parts.push_str(&rendered);
		}
		Some(parts)
	}
}

/// Build the untagged expunge output: per-message `EXPUNGE` lines normally, or
/// a single `VANISHED` with the removed UIDs under UIDONLY (RFC 9586).
fn expunge_response(uidonly: bool, expunged: &[u32], deleted_uids: &[u32]) -> String {
	if uidonly {
		if deleted_uids.is_empty() {
			return String::new();
		}
		return format!("* VANISHED {}\r\n", super::codes::uid_set(deleted_uids));
	}
	expunged
		.iter()
		.map(|seq| format!("* {seq} EXPUNGE\r\n"))
		.collect()
}

/// UIDs of every message in `snapshot` matching all search keys.
fn matching_uids(snapshot: &Snapshot, criteria: &[SearchKey]) -> Vec<u32> {
	let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
	let mut hits = Vec::new();
	for seqno in 1..=total {
		let Some(message) = snapshot.by_sequence(seqno) else {
			continue;
		};
		let mut content: Option<String> = None;
		if criteria
			.iter()
			.all(|key| search_matches(key, message, seqno, total, snapshot, &mut content))
		{
			hits.push(message.uid);
		}
	}
	hits
}

/// Expand SUBTREE / SUBTREE-ONE roots into matching mailbox names. With
/// `one_level`, only the root and its immediate children are included;
/// otherwise the whole subtree (the hierarchy separator is `/`).
fn subtree(
	data_dir: &std::path::Path,
	account: &str,
	roots: &[String],
	one_level: bool,
) -> Vec<String> {
	let all = mailbox::list(data_dir, account);
	let mut out = Vec::new();
	for root in roots {
		let prefix = format!("{root}/");
		for name in &all {
			if name == root {
				out.push(name.clone());
			} else if let Some(rest) = name.strip_prefix(&prefix)
				&& (!one_level || !rest.contains('/'))
			{
				out.push(name.clone());
			}
		}
	}
	out
}
