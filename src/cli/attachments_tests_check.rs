//! `epistle attachments check <file>`: each part, the verdict the policy in
//! effect would give, and nothing a message could do to the terminal.

use std::io::Write;
use std::process::ExitCode;

use super::check;

const EXE_AS_PDF: &str = "From: x@example.net\r\nTo: alice@example.org\r\nSubject: invoice\r\n\
	MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
	Content-Type: text/plain\r\n\r\nsee attached\r\n--b\r\n\
	Content-Type: application/pdf; name=invoice.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n\
	TVqQAAMAAAAEAAAA\r\n--b--\r\n";

/// A configuration in a temporary directory, and a message file next to it.
fn fixture(
	settings: &str,
	message: &[u8],
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let config = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&config).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n{settings}",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
	let eml = dir.path().join("message.eml");
	std::fs::write(&eml, message).unwrap();
	(dir, config, eml)
}

fn run(
	config: &std::path::Path,
	eml: &std::path::Path,
	json: bool,
) -> (Result<ExitCode, String>, String) {
	let mut out = Vec::new();
	let result = check::execute(config, eml, json, &mut out).map_err(|error| error.to_string());
	(result, String::from_utf8(out).expect("output is UTF-8"))
}

#[test]
fn a_disguised_executable_is_listed_with_the_verdict() {
	let (_dir, config, eml) = fixture(
		"[attachments]\nmode = \"quarantine\"\n",
		EXE_AS_PDF.as_bytes(),
	);
	let (result, out) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(
		out,
		"part 1\n\
		 \x20 names: invoice.pdf\n\
		 \x20 declared types: application/pdf\n\
		 \x20 real type: pe\n\
		 \x20 reasons: executable-content, type-mismatch\n\
		 verdict: quarantine (executable-content, type-mismatch)\n\
		 a submission would be refused\n"
	);
}

#[test]
fn json_carries_the_same_facts() {
	let (_dir, config, eml) = fixture("[attachments]\nmode = \"reject\"\n", EXE_AS_PDF.as_bytes());
	let (result, out) = run(&config, &eml, true);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let value: serde_json::Value = serde_json::from_str(&out).expect("one JSON value");
	assert_eq!(
		value,
		serde_json::json!({
			"mode": "reject",
			"verdict": "reject",
			"reasons": ["executable-content", "type-mismatch"],
			"submission": "refused",
			"parts": [{
				"names": ["invoice.pdf"],
				"declared-types": ["application/pdf"],
				"real-type": "pe",
				"reasons": ["executable-content", "type-mismatch"],
			}],
			"stopped": null,
			"ambiguous-mime": false,
		})
	);
}

#[test]
fn a_clean_message_is_delivered() {
	let (_dir, config, eml) = fixture("", b"From: x@example.net\r\nSubject: hi\r\n\r\nhello\r\n");
	let (result, out) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert_eq!(
		out,
		"no attachments\nverdict: deliver\na submission would be accepted\n"
	);
}

#[test]
fn with_the_policy_off_the_parts_are_shown_and_nothing_is_done() {
	let (_dir, config, eml) = fixture("[attachments]\nmode = \"off\"\n", EXE_AS_PDF.as_bytes());
	let (result, out) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert!(
		out.contains("  reasons: executable-content, type-mismatch\n"),
		"{out}"
	);
	assert!(
		out.ends_with(
			"verdict: deliver (mode = \"off\" inspects nothing)\na submission would be accepted\n"
		),
		"{out}"
	);
}

#[test]
fn names_cannot_drive_the_terminal() {
	// A right-to-left override that shows `invoice.exe` as `invoiceexe.pdf`,
	// and an escape sequence that would clear the screen.
	let message = "From: x@example.net\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
		Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\
		Content-Type: application/octet-stream\r\n\
		Content-Disposition: attachment; filename*=utf-8''invoice%E2%80%AEfdp.exe\r\n\r\nx\r\n--b\r\n\
		Content-Type: application/octet-stream; name=\"a\x1b[2Jb.txt\"\r\n\
		Content-Disposition: attachment\r\n\r\ny\r\n--b--\r\n";
	let (_dir, config, eml) = fixture("", message.as_bytes());
	let (result, text) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	let (_, json) = run(&config, &eml, true);
	for (form, out) in [("text", &text), ("json", &json)] {
		assert!(
			!out.chars().any(|c| c == '\u{1b}' || c == '\u{202e}'),
			"{form} output carries a raw control or bidi character"
		);
		assert!(out.is_ascii(), "{form} output is plain ASCII");
	}
	assert!(
		text.contains("  names: invoice\\u{202e}fdp.exe\n"),
		"{text}"
	);
	assert!(text.contains("  names: a\\u{1b}[2Jb.txt\n"), "{text}");
	let value: serde_json::Value = serde_json::from_str(&json).expect("JSON");
	assert_eq!(value["parts"][0]["names"][0], "invoice\u{202e}fdp.exe");
	assert_eq!(value["parts"][1]["names"][0], "a\u{1b}[2Jb.txt");
}

#[test]
fn a_file_over_the_message_size_limit_is_refused_before_reading_it_all() {
	let (_dir, config, eml) = fixture(
		"max_message_size = 1024\nmessage_memory_budget = 0\n",
		&vec![b'a'; 1025],
	);
	let (result, out) = run(&config, &eml, false);
	assert_eq!(
		result,
		Err(format!(
			"{} is larger than the message size limit (1024 bytes)",
			eml.display()
		))
	);
	assert_eq!(out, "");
}

#[test]
fn only_a_regular_file_is_read() {
	let (dir, config, _) = fixture("", b"");
	let (result, _) = run(&config, dir.path(), false);
	assert_eq!(
		result,
		Err(format!("{} is not a regular file", dir.path().display()))
	);
}

#[test]
fn a_message_past_the_part_cap_stops_and_is_never_called_clean() {
	let mut message = String::from(
		"From: x@example.net\r\nSubject: s\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=b\r\n\r\n",
	);
	for _ in 0..crate::antispam::attachments::MAX_PARTS + 50 {
		message.push_str("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n");
	}
	message.push_str("--b--\r\n");
	let (_dir, config, eml) = fixture("[attachments]\nmode = \"quarantine\"\n", message.as_bytes());
	let started = std::time::Instant::now();
	let (result, out) = run(&config, &eml, false);
	assert_eq!(result, Ok(ExitCode::SUCCESS));
	assert!(
		started.elapsed() < std::time::Duration::from_secs(10),
		"bounded by the inspection's own caps"
	);
	assert_eq!(
		out,
		"no attachments\ninspection stopped early: too-many-parts\n\
		 verdict: quarantine (scan-limit)\na submission would be refused\n"
	);
}
