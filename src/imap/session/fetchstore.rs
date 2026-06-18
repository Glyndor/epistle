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
					FetchItem::Binary => match snapshot.read(message) {
						Ok(data) => {
							let decoded = decode_binary(&data);
							let mut part =
								format!("BINARY[] {{{}}}\r\n", decoded.len()).into_bytes();
							part.extend_from_slice(&decoded);
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

/// Decode a message body per its top-level Content-Transfer-Encoding (RFC 3516
/// `BINARY[]`). Unknown or identity encodings return the body unchanged; a
/// malformed base64/quoted-printable body falls back to the raw bytes.
fn decode_binary(raw: &[u8]) -> Vec<u8> {
	let text = String::from_utf8_lossy(raw);
	let (headers, body) = text.split_once("\r\n\r\n").unwrap_or(("", &text));
	let encoding = headers.lines().find_map(|line| {
		let lower = line.to_ascii_lowercase();
		lower
			.strip_prefix("content-transfer-encoding:")
			.map(|value| value.trim().to_string())
	});
	match encoding.as_deref() {
		Some("base64") => {
			use base64::Engine;
			let stripped: String = body.split_whitespace().collect();
			base64::engine::general_purpose::STANDARD
				.decode(stripped.as_bytes())
				.unwrap_or_else(|_| body.as_bytes().to_vec())
		}
		Some("quoted-printable") => decode_quoted_printable(body),
		_ => body.as_bytes().to_vec(),
	}
}

/// Decode a quoted-printable body (RFC 2045 §6.7): `=XX` hex escapes and `=`
/// soft line breaks.
fn decode_quoted_printable(body: &str) -> Vec<u8> {
	let bytes = body.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'=' && i + 2 < bytes.len() {
			if bytes[i + 1] == b'\r' && bytes[i + 2] == b'\n' {
				i += 3; // soft line break
				continue;
			}
			let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
			if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
				out.push(byte);
				i += 3;
				continue;
			}
		}
		out.push(bytes[i]);
		i += 1;
	}
	out
}
