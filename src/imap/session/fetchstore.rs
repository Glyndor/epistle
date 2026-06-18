//! IMAP FETCH and STORE handlers, including CONDSTORE conditional
//! operations (RFC 7162).

use super::super::command::SequenceSet;
use super::helpers::format_internaldate;
use super::mailbox::{Flag, render_flags};
use super::{FetchItem, Output, Session, State, StoreMode};

impl Session {
	// CONDSTORE adds the seventh data argument; a params struct would not read
	// any clearer than the flat command shape here.
	#[allow(clippy::too_many_arguments)]
	pub(super) fn store(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		mode: StoreMode,
		flag_tokens: &[String],
		silent: bool,
		uid: bool,
		unchanged_since: Option<u64>,
	) -> Output {
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

		let mut flags = Vec::with_capacity(flag_tokens.len());
		for token in flag_tokens {
			match Flag::parse(token) {
				Some(flag) => flags.push(flag),
				None => return Output::text(format!("{tag} BAD unsupported flag\r\n")),
			}
		}

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut response = String::new();
		let mut modified: Vec<u32> = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, total) {
				continue;
			}
			// CONDSTORE UNCHANGEDSINCE: a concurrently-changed message is not
			// updated; its UID is reported in the MODIFIED response code.
			if unchanged_since.is_some_and(|since| message.modseq > since) {
				modified.push(message.uid);
				continue;
			}
			let message_uid = message.uid;
			let mut updated: Vec<Flag> = match mode {
				StoreMode::Set => flags.clone(),
				StoreMode::Add => {
					let mut existing = message.flags.clone();
					for flag in &flags {
						if !existing.contains(flag) {
							existing.push(*flag);
						}
					}
					existing
				}
				StoreMode::Remove => message
					.flags
					.iter()
					.copied()
					.filter(|flag| !flags.contains(flag))
					.collect(),
			};
			updated.dedup();
			let stored = match snapshot.store_flags(sequence_number, updated) {
				Ok(stored) => render_flags(stored),
				Err(_) => {
					return Output::text(format!("{tag} NO cannot store flags\r\n"));
				}
			};
			if !silent {
				// CONDSTORE: a conditional STORE reports the new mod-sequence.
				let modseq = snapshot.by_sequence(sequence_number).map(|m| m.modseq);
				let modseq = match (unchanged_since, modseq) {
					(Some(_), Some(value)) => format!("MODSEQ ({value}) "),
					_ => String::new(),
				};
				let uid_part = if uid {
					format!("UID {message_uid} ")
				} else {
					String::new()
				};
				response.push_str(&format!(
					"* {sequence_number} FETCH ({uid_part}{modseq}FLAGS {stored})\r\n"
				));
			}
		}
		let code = if modified.is_empty() {
			String::new()
		} else {
			format!("[MODIFIED {}] ", super::codes::uid_set(&modified))
		};
		response.push_str(&format!("{tag} OK {code}STORE completed\r\n"));
		Output::text(response)
	}

	pub(super) fn fetch(
		&mut self,
		tag: &str,
		sequence: &SequenceSet,
		items: &[FetchItem],
		uid: bool,
		changed_since: Option<u64>,
	) -> Output {
		let State::Selected { snapshot, .. } = &self.state else {
			return Output::text(format!("{tag} BAD no mailbox selected\r\n"));
		};

		let total = u32::try_from(snapshot.len()).unwrap_or(u32::MAX);
		let mut bytes = Vec::new();
		for sequence_number in 1..=total {
			let Some(message) = snapshot.by_sequence(sequence_number) else {
				continue;
			};
			let selector = if uid { message.uid } else { sequence_number };
			if !sequence.contains(selector, total) {
				continue;
			}
			// CONDSTORE CHANGEDSINCE: skip messages not changed since `n`.
			if changed_since.is_some_and(|since| message.modseq <= since) {
				continue;
			}

			let mut parts: Vec<Vec<u8>> = Vec::new();
			for item in items {
				match item {
					FetchItem::Flags => {
						parts.push(format!("FLAGS {}", render_flags(&message.flags)).into_bytes());
					}
					FetchItem::Uid => {
						parts.push(format!("UID {}", message.uid).into_bytes());
					}
					FetchItem::Rfc822Size => {
						parts.push(format!("RFC822.SIZE {}", message.size).into_bytes());
					}
					FetchItem::InternalDate => {
						let dt = format_internaldate(message.internal_date);
						parts.push(format!("INTERNALDATE \"{dt}\"").into_bytes());
					}
					FetchItem::ModSeq => {
						parts.push(format!("MODSEQ ({})", message.modseq).into_bytes());
					}
					FetchItem::Body => match snapshot.read(message) {
						Ok(data) => {
							let mut part = format!("BODY[] {{{}}}\r\n", data.len()).into_bytes();
							part.extend_from_slice(&data);
							parts.push(part);
						}
						Err(_) => {
							return Output::text(format!("{tag} NO message unavailable\r\n"));
						}
					},
				}
			}

			bytes.extend_from_slice(format!("* {sequence_number} FETCH (").as_bytes());
			for (index, part) in parts.iter().enumerate() {
				if index > 0 {
					bytes.push(b' ');
				}
				bytes.extend_from_slice(part);
			}
			bytes.extend_from_slice(b")\r\n");
		}
		bytes.extend_from_slice(format!("{tag} OK FETCH completed\r\n").as_bytes());
		Output {
			bytes,
			close: false,
			collect_literal: None,
			idle: false,
			upgrade_tls: false,
			collect_auth: false,
		}
	}
}
