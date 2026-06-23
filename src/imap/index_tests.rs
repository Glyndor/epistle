use std::path::Path;

use uuid::Uuid;

use super::*;
use crate::imap::mailbox::Snapshot;
use crate::storage::MessageCrypto;

/// Deliver a raw message into an account's INBOX `new/` directory.
fn deliver(dir: &Path, account: &str, body: &[u8]) -> Uuid {
	let new_dir = dir.join("accounts").join(account).join("new");
	std::fs::create_dir_all(&new_dir).expect("create dirs");
	let id = Uuid::now_v7();
	std::fs::write(new_dir.join(format!("{id}.eml")), body).expect("write");
	id
}

/// The INBOX `new/` directory for an account.
fn inbox(dir: &Path, account: &str) -> std::path::PathBuf {
	dir.join("accounts").join(account).join("new")
}

#[test]
fn first_open_scans_and_writes_index() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let snapshot =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	// The first open is the authoritative scan, not the index.
	assert!(!snapshot.loaded_from_index());
	// It leaves a fresh index behind for the next open.
	assert!(inbox(dir.path(), "alice").join(".index").is_file());
}

#[test]
fn second_open_loads_from_index() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let first =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!first.loaded_from_index());
	let second =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(second.loaded_from_index());
	assert_eq!(second.len(), 1);
}

#[test]
fn index_load_skips_sidecar_reads() {
	// Proof the fast path does not re-read the per-message sidecars: after the
	// first open, delete the `.flags` and `.uid` sidecars. A scan would now see
	// no flags and reassign UIDs; an index load returns the cached values.
	let dir = tempfile::tempdir().expect("tempdir");
	let id = deliver(dir.path(), "alice", b"hello\r\n");
	let mut first =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	first.store_flags(1, vec![Flag::Seen]).expect("store");
	// store_flags bumped the modseq, so this open rebuilds and re-stamps.
	let rebuilt =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!rebuilt.loaded_from_index());
	let uid = rebuilt.by_sequence(1).expect("seq 1").uid;

	// Now corrupt the sidecars; the index must still serve correct data.
	let new_dir = inbox(dir.path(), "alice");
	std::fs::remove_file(new_dir.join(format!("{id}.flags"))).expect("rm flags");
	std::fs::remove_file(new_dir.join(format!("{id}.uid"))).expect("rm uid");

	let cached =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(cached.loaded_from_index());
	let message = cached.by_sequence(1).expect("seq 1");
	assert_eq!(message.uid, uid);
	assert_eq!(message.flags, vec![Flag::Seen]);
}

#[test]
fn flag_change_rebuilds_with_new_flags() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let _ = Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	let mut second =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(second.loaded_from_index());
	second.store_flags(1, vec![Flag::Flagged]).expect("store");

	// The flag change bumped the mailbox modseq, so the stamp no longer matches
	// the (now stale) index: the next open rebuilds and returns the new flags.
	let third =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!third.loaded_from_index());
	assert_eq!(
		third.by_sequence(1).expect("seq 1").flags,
		vec![Flag::Flagged]
	);
}

#[test]
fn append_invalidates_index_by_count() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"first\r\n");
	let _ = Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	// A new message changes the `.eml` count, so the stamp mismatches.
	deliver(dir.path(), "alice", b"second\r\n");
	let grown =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!grown.loaded_from_index());
	assert_eq!(grown.len(), 2);
}

#[test]
fn corrupt_index_falls_back_to_scan() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let _ = Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	// Overwrite the index with garbage; open must still return correct contents.
	std::fs::write(
		inbox(dir.path(), "alice").join(".index"),
		b"@@@garbage@@@\n!!!\n",
	)
	.expect("corrupt");
	let snapshot =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!snapshot.loaded_from_index());
	assert_eq!(snapshot.len(), 1);
	assert_eq!(
		snapshot.read(snapshot.by_sequence(1).unwrap()).unwrap(),
		b"hello\r\n"
	);
}

#[test]
fn old_version_index_is_ignored() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let _ = Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	let path = inbox(dir.path(), "alice").join(".index");
	let text = std::fs::read_to_string(&path).expect("read");
	// Bump the format version in the header to a future, unknown value.
	let bumped = text.replacen(&format!("{MAGIC} {VERSION}"), &format!("{MAGIC} 999"), 1);
	std::fs::write(&path, bumped).expect("write");
	let snapshot =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!snapshot.loaded_from_index());
	assert_eq!(snapshot.len(), 1);
}

#[test]
fn truncated_record_is_rejected() {
	let dir = tempfile::tempdir().expect("tempdir");
	deliver(dir.path(), "alice", b"hello\r\n");
	let _ = Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	let path = inbox(dir.path(), "alice").join(".index");
	let text = std::fs::read_to_string(&path).expect("read");
	// Drop the last record line, leaving a stamp that promises one message.
	let mut lines: Vec<&str> = text.lines().collect();
	lines.pop();
	std::fs::write(&path, lines.join("\n")).expect("write");
	let snapshot =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!snapshot.loaded_from_index());
	assert_eq!(snapshot.len(), 1);
}

#[test]
fn empty_mailbox_round_trips_through_index() {
	let dir = tempfile::tempdir().expect("tempdir");
	// Create the empty mailbox directory so the index can be written.
	std::fs::create_dir_all(inbox(dir.path(), "alice")).expect("mkdir");
	let first =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(!first.loaded_from_index());
	let second =
		Snapshot::open(dir.path(), "alice", "INBOX", &MessageCrypto::disabled()).expect("open");
	assert!(second.loaded_from_index());
	assert!(second.is_empty());
}

#[test]
fn parse_record_round_trips() {
	// Direct unit coverage of the record encoder/decoder for all flag shapes.
	let id = Uuid::now_v7();
	let original = MessageRef::from_index(
		7,
		id,
		1234,
		Vec::new(),
		std::time::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 42),
		9,
	);
	let mut buf = String::new();
	write_record(&mut buf, &original);
	// Strip only the record terminator, not the trailing empty-flags field.
	let line = buf.trim_end_matches('\n');
	let parsed = parse_record(line).expect("parse");
	assert_eq!(parsed.uid, 7);
	assert_eq!(parsed.id(), id);
	assert_eq!(parsed.size, 1234);
	assert_eq!(parsed.modseq, 9);
	assert!(parsed.flags.is_empty());

	// With a multi-flag set.
	let with_flags = MessageRef::from_index(
		1,
		id,
		1,
		vec![Flag::Seen, Flag::Deleted],
		std::time::UNIX_EPOCH,
		1,
	);
	let mut buf2 = String::new();
	write_record(&mut buf2, &with_flags);
	let parsed2 = parse_record(buf2.trim_end_matches('\n')).expect("parse");
	assert_eq!(parsed2.flags, vec![Flag::Seen, Flag::Deleted]);
}

#[test]
fn malformed_records_are_rejected() {
	// Each of these must fail closed (return None) rather than mis-parse.
	assert!(parse_record("not-a-uuid 1 2 3.0 4 ").is_none());
	let id = Uuid::now_v7();
	// Missing flags column.
	assert!(parse_record(&format!("{id} 1 2 3.0 4")).is_none());
	// Extra trailing column.
	assert!(parse_record(&format!("{id} 1 2 3.0 4 seen extra")).is_none());
	// Bad time (no dot).
	assert!(parse_record(&format!("{id} 1 2 30 4 ")).is_none());
	// Unknown flag token.
	assert!(parse_record(&format!("{id} 1 2 3.0 4 bogus")).is_none());
	// Out-of-range nanos.
	assert!(parse_record(&format!("{id} 1 2 3.9999999999 4 ")).is_none());
}

#[test]
fn missing_index_is_treated_as_absent() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(inbox(dir.path(), "alice")).expect("mkdir");
	let generation = current_generation(&inbox(dir.path(), "alice"));
	assert!(load(&inbox(dir.path(), "alice"), generation).is_none());
}
