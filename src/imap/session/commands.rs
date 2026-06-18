use super::super::command::{ReturnOpt, SequenceSet};
use super::codes::{copyuid_code, esearch_line};
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
				response.push_str(&format!("* {current} EXPUNGE\r\n"));
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

	pub(super) fn expunge(&mut self, tag: &str) -> Output {
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
		match snapshot.expunge() {
			Ok(expunged) => {
				let mut response = String::new();
				for sequence_number in expunged {
					response.push_str(&format!("* {sequence_number} EXPUNGE\r\n"));
				}
				response.push_str(&format!("{tag} OK EXPUNGE completed\r\n"));
				Output::text(response)
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
		let limit_kib = self.quota_limit_bytes.div_ceil(1024);
		format!("* QUOTA \"\" (STORAGE {used_kib} {limit_kib})\r\n")
	}

	pub(super) fn uid_expunge(&mut self, tag: &str, sequence: &SequenceSet) -> Output {
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
		match snapshot.expunge_uids(&uids) {
			Ok(expunged) => {
				let mut response = String::new();
				for sequence_number in expunged {
					response.push_str(&format!("* {sequence_number} EXPUNGE\r\n"));
				}
				response.push_str(&format!("{tag} OK EXPUNGE completed\r\n"));
				Output::text(response)
			}
			Err(_) => Output::text(format!("{tag} NO EXPUNGE failed\r\n")),
		}
	}

	pub(super) fn append_begin(
		&mut self,
		tag: &str,
		mailbox: &str,
		flag_tokens: &[String],
		size: usize,
	) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO [TRYCREATE] no such mailbox\r\n"));
		}
		// Quota enforcement (RFC 9208): refuse before reading the literal.
		let projected = mailbox::account_usage(&self.data_dir, &account) + size as u64;
		if projected > self.quota_limit_bytes {
			return Output::text(format!("{tag} NO [OVERQUOTA] storage quota exceeded\r\n"));
		}
		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}
		self.pending_append = Some((tag.to_string(), mailbox.to_string(), flags));
		let mut output = Output::text("+ ready for literal data\r\n".to_string());
		output.collect_literal = Some(size);
		output
	}

	/// Called by the network layer with the complete APPEND literal.
	pub fn literal_done(&mut self, data: &[u8]) -> Output {
		let Some((tag, mailbox, flags)) = self.pending_append.take() else {
			return Output::text("* BAD unexpected literal\r\n".to_string());
		};
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		match mailbox::append(&self.data_dir, &account, &mailbox, &flags, data) {
			Ok(id) => {
				// UIDPLUS: report the UIDVALIDITY and UID assigned (RFC 4315).
				let code = match mailbox::appenduid(&self.data_dir, &account, &mailbox, id) {
					Some((validity, uid)) => format!("[APPENDUID {validity} {uid}] "),
					None => String::new(),
				};
				Output::text(format!("{tag} OK {code}APPEND completed\r\n"))
			}
			Err(_) => Output::text(format!("{tag} NO APPEND failed\r\n")),
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

	pub(super) fn status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let snapshot = match Snapshot::open(&self.data_dir, &account, mailbox) {
			Ok(s) => s,
			Err(_) => return Output::text(format!("{tag} NO cannot open mailbox\r\n")),
		};
		let mut parts = String::new();
		for (i, item) in items.iter().enumerate() {
			if i > 0 {
				parts.push(' ');
			}
			let value: u64 = match item {
				StatusItem::Messages => snapshot.len() as u64,
				StatusItem::Recent => 0,
				StatusItem::Uidnext => u64::from(snapshot.uid_next()),
				StatusItem::Uidvalidity => u64::from(snapshot.uid_validity()),
				StatusItem::Unseen => snapshot
					.messages()
					.filter(|m| !m.flags.contains(&Flag::Seen))
					.count() as u64,
				StatusItem::Size => snapshot.messages().map(|m| m.size).sum(),
			};
			let name = match item {
				StatusItem::Messages => "MESSAGES",
				StatusItem::Recent => "RECENT",
				StatusItem::Uidnext => "UIDNEXT",
				StatusItem::Uidvalidity => "UIDVALIDITY",
				StatusItem::Unseen => "UNSEEN",
				StatusItem::Size => "SIZE",
			};
			parts.push_str(&format!("{name} {value}"));
		}
		Output::text(format!(
			"* STATUS \"{mailbox}\" ({parts})\r\n{tag} OK STATUS completed\r\n"
		))
	}
}
