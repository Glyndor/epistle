//! IMAP response-code and reply-line builders.

use super::super::command::ReturnOpt;
use super::mailbox;

/// Build the ESEARCH reply line (RFC 4731) for the requested return options.
pub(super) fn esearch_line(tag: &str, uid: bool, hits: &[u32], opts: &[ReturnOpt]) -> String {
	let mut line = format!("* ESEARCH (TAG \"{tag}\")");
	if uid {
		line.push_str(" UID");
	}
	for opt in opts {
		match opt {
			ReturnOpt::Count => line.push_str(&format!(" COUNT {}", hits.len())),
			ReturnOpt::Min => {
				if let Some(min) = hits.iter().min() {
					line.push_str(&format!(" MIN {min}"));
				}
			}
			ReturnOpt::Max => {
				if let Some(max) = hits.iter().max() {
					line.push_str(&format!(" MAX {max}"));
				}
			}
			ReturnOpt::All => {
				if !hits.is_empty() {
					line.push_str(&format!(" ALL {}", uid_set(hits)));
				}
			}
		}
	}
	line.push_str("\r\n");
	line
}

/// Build the UIDPLUS `[COPYUID validity src dst] ` response code, or an empty
/// string if the destination UIDs cannot be resolved. The destination
/// UIDVALIDITY comes from the target mailbox.
pub(super) fn copyuid_code(
	data_dir: &std::path::Path,
	account: &str,
	target: &str,
	source_uids: &[u32],
	dest_ids: &[uuid::Uuid],
) -> String {
	if dest_ids.is_empty() {
		return String::new();
	}
	let mut validity = 0;
	let mut dest_uids = Vec::with_capacity(dest_ids.len());
	for id in dest_ids {
		match mailbox::appenduid(data_dir, account, target, *id) {
			Some((uid_validity, uid)) => {
				validity = uid_validity;
				dest_uids.push(uid);
			}
			None => return String::new(),
		}
	}
	if dest_uids.len() != source_uids.len() {
		return String::new();
	}
	format!(
		"[COPYUID {validity} {} {}] ",
		uid_set(source_uids),
		uid_set(&dest_uids),
	)
}

/// Format a UID list as a comma-separated set (no range coalescing).
pub(super) fn uid_set(uids: &[u32]) -> String {
	uids.iter()
		.map(u32::to_string)
		.collect::<Vec<_>>()
		.join(",")
}
