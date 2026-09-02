//! Restore-roundtrip tests for `epistle backup` and the externally-referenced
//! path warning it emits.
//!
//! Kept in a sibling file to [`backup_tests`] so neither crosses the 500-line
//! per-file code limit. The two test modules share [`super::helpers`] for the
//! in-process tar/gzip reader and the archive extractor.

use super::helpers::*;
use super::*;
use crate::imap::mailbox::{self, Flag, Snapshot};
use crate::storage::MessageCrypto;

/// Build a TOML config string that references every external path we want the
/// warning to enumerate. The `[storage]` block enables at-rest encryption with
/// a key file outside `data_dir`; the other sections add a TLS cert/key, a
/// DKIM key, an ARC key and a DNS token file. Each path points inside the test
/// tempdir so the warning has something concrete to render.
fn config_with_external_paths(data_dir: &std::path::Path, key_path: &std::path::Path) -> String {
	format!(
		"hostname = \"mail.example.org\"\n\
data_dir = \"{data}\"\n\
\n\
[tls]\n\
cert_file = \"{data}/../cert.pem\"\n\
key_file = \"{data}/../key.pem\"\n\
client_ca = \"{data}/../client-ca.pem\"\n\
\n\
[dkim]\n\
selector = \"mail\"\n\
key_file = \"{data}/../dkim.pem\"\n\
rsa_selector = \"mail-rsa\"\n\
rsa_key_file = \"{data}/../dkim-rsa.pem\"\n\
\n\
[arc]\n\
selector = \"arc\"\n\
key_file = \"{data}/../arc.pem\"\n\
\n\
[storage]\n\
encrypt_at_rest = true\n\
encryption_key_file = \"{key}\"\n\
encryption_key_env = \"EPISTLE_MAIL_KEY\"\n\
\n\
[storage.blobs]\n\
backend = \"s3\"\n\
endpoint = \"https://s3.us-east-1.amazonaws.com\"\n\
bucket = \"mail-blobs\"\n\
region = \"us-east-1\"\n\
access_key_id = \"AKIA-EXAMPLE\"\n\
secret_access_key_env = \"EPISTLE_S3_SECRET\"\n\
secret_access_key_file = \"{data}/../s3.secret\"\n\
\n\
[dns]\n\
provider = \"cloudflare\"\n\
zone = \"example.org\"\n\
token_file = \"{data}/../cf.token\"\n\
credentials_file = \"{data}/../gcloud.json\"\n",
		data = data_dir.display(),
		key = key_path.display(),
	)
}

/// `backup` must enumerate every path the configuration references outside
/// `data_dir` so an operator knows what to back up separately. It must also
/// call out the at-rest encryption key in a separate, prominent block, because
/// losing the key makes the mail content in the archive permanently unreadable.
#[test]
fn run_warns_about_every_externally_referenced_path() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("mail.key");
	std::fs::write(&key_path, b"faked-key").expect("key file");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");

	let config: Config =
		toml::from_str(&config_with_external_paths(&data_dir, &key_path)).expect("config");

	let mut out = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(run(&config, &mut out, &mut warnings), ExitCode::SUCCESS);
	let text = String::from_utf8(warnings).expect("utf-8 warnings");

	// Every path referenced in the config shows up.
	assert!(text.contains("[tls] cert_file ="), "tls cert_file: {text}");
	assert!(text.contains("[tls] key_file ="), "tls key_file: {text}");
	assert!(text.contains("[tls] client_ca ="), "tls client_ca: {text}");
	assert!(text.contains("[dkim] key_file ="), "dkim key_file: {text}");
	assert!(
		text.contains("[dkim] rsa_key_file ="),
		"dkim rsa_key_file: {text}"
	);
	assert!(text.contains("[arc] key_file ="), "arc key_file: {text}");
	assert!(
		text.contains("[storage.blobs] secret_access_key_file ="),
		"s3 secret_access_key_file: {text}"
	);
	assert!(
		text.contains("[dns] token_file ="),
		"dns token_file: {text}"
	);
	assert!(
		text.contains("[dns] credentials_file ="),
		"dns credentials_file: {text}"
	);

	// The encryption key gets its own block and is called out explicitly.
	assert!(
		text.contains("encrypted at rest"),
		"encryption key block missing: {text}"
	);
	assert!(
		text.contains("[storage] encryption_key_file ="),
		"encryption_key_file missing from key block: {text}"
	);
	assert!(
		text.contains("[storage] encryption_key_env = $EPISTLE_MAIL_KEY"),
		"encryption_key_env missing from key block: {text}"
	);
}

/// A config with no external paths and no encryption produces no warning —
/// there is nothing to call out, and the silent case is the common one
/// (self-contained deployments with a plaintext store).
#[test]
fn run_is_silent_for_minimal_config() {
	let dir = tempfile::tempdir().expect("tempdir");
	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut out = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(run(&config, &mut out, &mut warnings), ExitCode::SUCCESS);
	assert!(
		warnings.is_empty(),
		"no warning expected for a self-contained config, got: {}",
		String::from_utf8_lossy(&warnings)
	);
}

/// Backup writes the tar.gz to stdout, so any byte that leaks onto the stream
/// from a logging mistake corrupts the archive. The encryption-key warning
/// must therefore go to the warnings sink (stderr in production), never to the
/// archive writer. We pin this here by capturing both ends in-process and
/// asserting the warning text never appears on the archive stream.
#[test]
fn encryption_key_warning_does_not_leak_into_archive_stream() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key_path = dir.path().join("mail.key");
	std::fs::write(&key_path, b"faked-key").expect("key file");
	let data_dir = dir.path().join("data");
	std::fs::create_dir_all(&data_dir).expect("data dir");
	std::fs::write(data_dir.join("seed.eml"), b"seed").expect("seed");

	let toml = format!(
		"hostname = \"mail.example.org\"\n\
data_dir = \"{data}\"\n\
\n\
[storage]\n\
encrypt_at_rest = true\n\
encryption_key_file = \"{key}\"\n",
		data = data_dir.display(),
		key = key_path.display(),
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut archive_bytes = Vec::new();
	let mut warning_bytes = Vec::new();
	assert_eq!(
		run(&config, &mut archive_bytes, &mut warning_bytes),
		ExitCode::SUCCESS
	);

	// The archive stream is a gzip blob: the magic must be there and the
	// warning text must NOT be.
	assert!(
		archive_bytes.starts_with(&[0x1f, 0x8b]),
		"archive stream is not gzip"
	);
	let warnings = String::from_utf8_lossy(&warning_bytes);
	assert!(
		warnings.contains("encrypted at rest"),
		"warning missing from warnings sink: {warnings}"
	);
	let archive_text = String::from_utf8_lossy(&archive_bytes);
	assert!(
		!archive_text.contains("encrypted at rest"),
		"warning text leaked into archive stream — archive is corrupted"
	);
	assert!(
		!archive_text.contains("encryption_key_file"),
		"key path leaked into archive stream"
	);
	// And the archive still parses cleanly: no spurious header bytes.
	let files = read_tar(&gunzip(&archive_bytes));
	assert!(
		files.iter().any(|(name, _)| name.ends_with("seed.eml")),
		"seed.eml missing from restored archive"
	);
}

/// A backup is only as good as the restore. This round-trips a realistic
/// encrypted data_dir through `backup` and back, comparing the restored
/// content — not the on-disk bytes (which are ciphertext) — message by message
/// against the originals. It exercises:
///
/// - multiple mailboxes per account (INBOX + a folder)
/// - multiple accounts
/// - IMAP flags round-tripped through `.flags` sidecars
/// - a multipart message with an attachment (the `.eml` bytes are the whole
///   MIME tree; if the archive flips a single byte the test fails)
/// - a spool entry (separate at-rest path from the mailbox)
/// - a private key file written 0o600 (the archive preserves the mode)
#[test]
fn round_trip_restores_encrypted_mailbox_content() {
	let source = tempfile::tempdir().expect("source");
	let data_dir = source.path();
	let crypto = MessageCrypto::for_test(b"0123456789abcdef0123456789abcdef");

	// Build a non-trivial mailbox tree: two accounts, INBOX plus a Sent
	// folder, several messages with different flag sets and a multipart body
	// that includes a base64 attachment.
	let multipart = b"From: alice@example.org\r\n\
To: bob@example.org\r\n\
Subject: quarterly report with attachment\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
\r\n\
--BOUND\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
report body, secret enough to fail loudly if tampered\r\n\
--BOUND\r\n\
Content-Type: application/octet-stream; name=\"report.bin\"\r\n\
Content-Transfer-Encoding: base64\r\n\
Content-Disposition: attachment; filename=\"report.bin\"\r\n\
\r\n\
VGhpcyBpcyB0aGUgYXR0YWNobWVudC4=\r\n\
--BOUND--\r\n";
	let plain_seen = b"Subject: hi\r\n\r\nalice second message, this one is seen\r\n";
	let plain_flagged = b"Subject: priority\r\n\r\nflagged important message from alice to bob\r\n";
	let bob_message = b"Subject: hello alice\r\n\r\nbob's reply, nothing flagged\r\n";

	let alice_inbox_id =
		mailbox::append(data_dir, "alice", "INBOX", &[], plain_seen, &crypto).expect("alice inbox");
	let alice_sent_id =
		mailbox::append(data_dir, "alice", "Sent", &[Flag::Seen], multipart, &crypto)
			.expect("alice sent");
	let alice_flagged_id = mailbox::append(
		data_dir,
		"alice",
		"INBOX",
		&[Flag::Seen, Flag::Flagged],
		plain_flagged,
		&crypto,
	)
	.expect("alice flagged");
	let bob_inbox_id =
		mailbox::append(data_dir, "bob", "INBOX", &[], bob_message, &crypto).expect("bob inbox");
	let _ = bob_inbox_id;

	// Add a private DKIM key under data_dir/dkim with mode 0o600 — the
	// archive preserves the mode and the round-trip reads it back exactly.
	let dkim_dir = data_dir.join("dkim");
	std::fs::create_dir_all(&dkim_dir).expect("dkim dir");
	let dkim_path = dkim_dir.join("private.pem");
	std::fs::write(
		&dkim_path,
		b"-----BEGIN PRIVATE KEY-----\nfaked\n-----END\n",
	)
	.expect("dkim key");
	std::fs::set_permissions(&dkim_path, std::fs::Permissions::from_mode(0o600))
		.expect("chmod 0600");

	// Spool a queued message so the round-trip also covers the outbound path.
	let spool =
		crate::storage::FsSpool::open_with_crypto(data_dir, crypto.clone()).expect("spool open");
	let accepted = crate::smtp::session::AcceptedMessage {
		reverse_path: "alice@example.org".to_string(),
		recipients: vec!["bob@example.org".to_string()],
		data: b"Subject: queued\r\n\r\npending outbound body\r\n".to_vec(),
		require_tls: false,
		mailbox: None,
		no_dsn: Vec::new(),
	};
	let spool_id = spool.store(&accepted).expect("spool store");

	// Build a config that turns encryption on, pointing the key file at a
	// path outside the data_dir (the way an operator would) so the warning
	// has a real, archived-but-not-archived path to enumerate.
	let key_file = source.path().join("mail.key");
	std::fs::write(&key_file, b"anywhere-but-data-dir").expect("key file");
	let toml = format!(
		"hostname = \"mail.example.org\"\n\
data_dir = \"{data}\"\n\
\n\
[storage]\n\
encrypt_at_rest = true\n\
encryption_key_file = \"{key}\"\n",
		data = data_dir.display(),
		key = key_file.display(),
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut archive = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(run(&config, &mut archive, &mut warnings), ExitCode::SUCCESS);
	assert!(
		!warnings.is_empty(),
		"encryption is on, the warning must fire so the operator knows the key is outside the archive"
	);

	// Extract to a fresh, clean directory — the whole point of the test is
	// that restore does not touch the source.
	let restored = tempfile::tempdir().expect("restored");
	extract_to(&archive, restored.path());

	// Decrypt through the same key and read every message back. The content
	// must match byte-for-byte: if a single byte changed in the archive, the
	// attachment or the message body fails to compare equal.
	let alice_inbox =
		Snapshot::open(restored.path(), "alice", "INBOX", &crypto).expect("alice inbox");
	let alice_inbox_msgs: Vec<_> = alice_inbox.messages().collect();
	assert_eq!(alice_inbox_msgs.len(), 2, "alice INBOX has both messages");
	let alice_inbox_bodies: std::collections::HashMap<_, _> = alice_inbox_msgs
		.iter()
		.map(|m| (m.id(), alice_inbox.read(m).expect("read")))
		.collect();
	assert_eq!(
		alice_inbox_bodies[&alice_inbox_id], plain_seen,
		"alice's plain message survives byte-for-byte"
	);
	assert_eq!(
		alice_inbox_bodies[&alice_flagged_id], plain_flagged,
		"alice's flagged message survives byte-for-byte"
	);

	let alice_sent = Snapshot::open(restored.path(), "alice", "Sent", &crypto).expect("alice Sent");
	let alice_sent_msgs: Vec<_> = alice_sent.messages().collect();
	assert_eq!(alice_sent_msgs.len(), 1, "alice Sent has one message");
	let sent_msg = alice_sent_msgs[0];
	assert_eq!(sent_msg.id(), alice_sent_id);
	let sent_body = alice_sent.read(sent_msg).expect("read sent");
	assert_eq!(
		sent_body, multipart,
		"multipart body survives byte-for-byte"
	);
	// And the attachment bytes round-trip — the test would also catch a
	// silent base64 mangle or a CRLF/LF swap.
	assert!(
		sent_body
			.windows(b"VGhpcyBpcyB0aGUgYXR0YWNobWVudC4=".len())
			.any(|w| w == b"VGhpcyBpcyB0aGUgYXR0YWNobWVudC4="),
		"attachment base64 payload is preserved"
	);

	let bob_inbox = Snapshot::open(restored.path(), "bob", "INBOX", &crypto).expect("bob inbox");
	let bob_msgs: Vec<_> = bob_inbox.messages().collect();
	assert_eq!(bob_msgs.len(), 1);
	let bob_body = bob_inbox.read(bob_msgs[0]).expect("read bob");
	assert_eq!(bob_body, bob_message);

	// Flags round-trip: the flagged message comes back with both flags.
	let flagged = alice_inbox
		.messages()
		.find(|m| m.id() == alice_flagged_id)
		.expect("flagged message present");
	assert!(flagged.flags.contains(&Flag::Seen));
	assert!(flagged.flags.contains(&Flag::Flagged));

	// DKIM private key restored with its 0o600 mode (operators rely on this
	// bit — the next server start would refuse to load a world-readable key).
	let restored_dkim = restored.path().join("dkim/private.pem");
	assert!(restored_dkim.exists(), "dkim key restored");
	let mode = std::fs::metadata(&restored_dkim)
		.expect("dkim stat")
		.permissions()
		.mode();
	assert_eq!(
		mode & 0o7777,
		0o600,
		"dkim key restored as 0o600 (got {:o})",
		mode
	);

	// Spool message restored: the ciphertext is back under data_dir/spool/new/
	// and decrypts to the original body.
	let restored_spool = crate::storage::FsSpool::open_with_crypto(restored.path(), crypto.clone())
		.expect("spool reopen");
	let entry = restored_spool.load(spool_id).expect("spool load");
	assert_eq!(
		entry.envelope.reverse_path, accepted.reverse_path,
		"spool envelope survives"
	);
	assert_eq!(entry.data, accepted.data, "spool body survives");
}
