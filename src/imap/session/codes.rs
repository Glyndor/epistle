//! IMAP response-code and reply-line builders.

use super::super::command::ReturnOpt;
use super::mailbox;

/// Build the ESEARCH reply line (RFC 4731) for the requested return options.
/// `modseq` is the CONDSTORE MODSEQ result (RFC 7162 §3.1.5), written last.
pub(super) fn esearch_line(
	tag: &str,
	uid: bool,
	hits: &[u32],
	opts: &[ReturnOpt],
	modseq: Option<u64>,
) -> String {
	let mut line = format!("* ESEARCH (TAG \"{tag}\")");
	if uid {
		line.push_str(" UID");
	}
	line.push_str(&esearch_results(hits, opts));
	if let Some(modseq) = modseq {
		line.push_str(&format!(" MODSEQ {modseq}"));
	}
	line.push_str("\r\n");
	line
}

/// Build one MULTISEARCH (RFC 7377) ESEARCH reply line. The correlator carries
/// the mailbox name (`mailbox`, already written as an astring) and its
/// UIDVALIDITY so the client can attribute results across mailboxes; results
/// are always UIDs. Returns an empty string when the
/// requested options produce no output for this mailbox (e.g. only `ALL` was
/// asked for and nothing matched), so empty per-mailbox lines are omitted.
pub(super) fn esearch_multi_line(
	tag: &str,
	mailbox: &str,
	uid_validity: u32,
	hits: &[u32],
	opts: &[ReturnOpt],
) -> String {
	let results = esearch_results(hits, opts);
	if results.is_empty() {
		return String::new();
	}
	format!(
		"* ESEARCH (TAG \"{tag}\" MAILBOX {mailbox} UIDVALIDITY {uid_validity}) UID{results}\r\n"
	)
}

/// Format the return-option portion (` COUNT n`, ` MIN n`, ` MAX n`, ` ALL set`)
/// shared by the single-mailbox and MULTISEARCH ESEARCH replies.
fn esearch_results(hits: &[u32], opts: &[ReturnOpt]) -> String {
	let mut out = String::new();
	for opt in opts {
		match opt {
			ReturnOpt::Count => out.push_str(&format!(" COUNT {}", hits.len())),
			ReturnOpt::Min => {
				if let Some(min) = hits.iter().min() {
					out.push_str(&format!(" MIN {min}"));
				}
			}
			ReturnOpt::Max => {
				if let Some(max) = hits.iter().max() {
					out.push_str(&format!(" MAX {max}"));
				}
			}
			ReturnOpt::All => {
				if !hits.is_empty() {
					out.push_str(&format!(" ALL {}", sequence_set(hits)));
				}
			}
			// SEARCHRES (RFC 5182): SAVE writes to the session's reservation
			// but produces no reply text.
			ReturnOpt::Save => {}
		}
	}
	out
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
/// Write ascending `numbers` as a sequence-set, joining each run of
/// consecutive values into a `first:last` range (`1,2,3,5` becomes `1:3,5`).
pub(super) fn sequence_set(numbers: &[u32]) -> String {
	let mut out = String::new();
	let mut i = 0;
	while i < numbers.len() {
		let first = numbers[i];
		let mut last = first;
		while numbers.get(i + 1) == last.checked_add(1).as_ref() {
			last += 1;
			i += 1;
		}
		if !out.is_empty() {
			out.push(',');
		}
		if first == last {
			out.push_str(&first.to_string());
		} else {
			out.push_str(&format!("{first}:{last}"));
		}
		i += 1;
	}
	out
}

pub(super) fn uid_set(uids: &[u32]) -> String {
	uids.iter()
		.map(u32::to_string)
		.collect::<Vec<_>>()
		.join(",")
}
