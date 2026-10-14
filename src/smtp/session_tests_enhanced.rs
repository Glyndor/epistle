//! Every failure reply the SMTP server sends carries an RFC 3463 enhanced
//! status code (RFC 2034 §3) whose class matches the reply code, so a
//! client can tell a full mailbox from a bad address without parsing text.

use super::tests_basic::greeted;
use super::*;

fn reply_text(action: &Action) -> String {
	match action {
		Action::Continue(r)
		| Action::CollectData(r)
		| Action::UpgradeTls(r)
		| Action::CollectAuthResponse(r)
		| Action::Close(r)
		| Action::Deliver(r, _) => r.to_string(),
		Action::CollectChunk { .. } => String::new(),
	}
}

#[test]
fn an_oversized_message_is_refused_as_too_big() {
	let mut session = greeted();
	session.command_line("MAIL FROM:<a@example.org>");
	session.command_line("RCPT TO:<b@example.org>");
	session.command_line("DATA");
	let chunk = "x".repeat(1024);
	for _ in 0..MAX_MESSAGE_SIZE / chunk.len() + 1 {
		assert_eq!(session.data_line(chunk.as_bytes()), None);
	}
	let action = session.data_line(b".").expect("final action");
	assert_eq!(
		reply_text(&action),
		"552 5.3.4 message exceeds maximum size\r\n"
	);
}

/// Text of a string literal starting at `rest` (just after its opening
/// quote), up to the closing quote.
fn literal(rest: &str) -> &str {
	&rest[..rest.find('"').unwrap_or(rest.len())]
}

/// Whether `text` starts with an enhanced status code of `class`.
fn has_enhanced(class: char, text: &str) -> bool {
	let token = text.split(' ').next().unwrap_or_default();
	let parts: Vec<&str> = token.split('.').collect();
	parts.len() == 3
		&& parts[0] == class.to_string()
		&& parts[1..]
			.iter()
			.all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Constructions whose text is not a literal here, checked elsewhere: the
/// DNSBL details are literals starting with 5.7.1 in that file; the
/// tenant aggregate reply text is composed at runtime from the
/// configured tenant label.
const NOT_LITERAL_ALLOWED: &[&str] = &[
	"src/smtp/server/dnsbl_check.rs",
	"src/smtp/session/mod.rs",
	"src/smtp/session/finalise.rs",
];

/// Every 4xx/5xx `Reply::single`/`Reply::new` in `source`, and in SMTP code
/// every string literal that is a raw reply line, without an enhanced code.
fn offenders(path: &str, source: &str, raw_lines: bool) -> Vec<String> {
	let mut found = Vec::new();
	let code_at = |s: &str| -> Option<char> {
		let s = s.trim_start();
		let bytes = s.as_bytes();
		(bytes.len() >= 3
			&& matches!(bytes[0], b'4' | b'5')
			&& bytes[..3].iter().all(u8::is_ascii_digit)
			&& !bytes.get(3).is_some_and(u8::is_ascii_digit))
		.then(|| bytes[0] as char)
	};
	for constructor in ["Reply::single(", "Reply::new("] {
		for (at, _) in source.match_indices(constructor) {
			let args = &source[at + constructor.len()..];
			let Some(class) = code_at(args) else { continue };
			let line = source[..at].matches('\n').count() + 1;
			let second = args[args.find(',').unwrap_or(0) + 1..].trim_start();
			let second = second
				.strip_prefix("&format!(")
				.unwrap_or(second)
				.trim_start();
			match second.strip_prefix('"') {
				Some(rest) if constructor == "Reply::single(" => {
					if !has_enhanced(class, literal(rest)) {
						found.push(format!("{path}:{line}: {}", literal(rest)));
					}
				}
				_ if NOT_LITERAL_ALLOWED.contains(&path) => {}
				_ => found.push(format!("{path}:{line}: text is not a literal")),
			}
		}
	}
	if raw_lines {
		for (at, _) in source.match_indices('"') {
			let rest = &source[at + 1..];
			if let Some(class) = code_at(rest).filter(|_| matches!(rest.as_bytes()[3], b' ' | b'-'))
				&& !rest.starts_with(char::is_whitespace)
				&& !has_enhanced(class, &rest[4..])
			{
				let line = source[..at].matches('\n').count() + 1;
				found.push(format!("{path}:{line}: {}", literal(rest)));
			}
		}
	}
	found
}

/// Non-test Rust sources under `dir`, with inline test modules cut off.
fn sources(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
	for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
		let path = entry.path();
		if path.is_dir() {
			sources(&path, out);
			continue;
		}
		let name = path
			.file_name()
			.and_then(|n| n.to_str())
			.unwrap_or_default();
		if !name.ends_with(".rs") || name.contains("test") {
			continue;
		}
		let text = std::fs::read_to_string(&path).expect("read source");
		let text = match text.find("#[cfg(test)]\nmod tests") {
			Some(cut) => text[..cut].to_string(),
			None => text,
		};
		let root = env!("CARGO_MANIFEST_DIR");
		let relative = path.strip_prefix(root).unwrap_or(&path);
		out.push((relative.display().to_string(), text));
	}
}

#[test]
fn every_failure_reply_carries_an_enhanced_status_code() {
	let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
	let mut files = Vec::new();
	sources(&root, &mut files);
	assert!(files.len() > 100, "the walk found the sources");
	let mut found = Vec::new();
	for (path, source) in &files {
		found.extend(offenders(path, source, path.starts_with("src/smtp/")));
	}
	assert!(
		found.is_empty(),
		"failure replies without an enhanced status code:\n{}",
		found.join("\n")
	);
}

#[test]
fn the_scan_catches_a_reply_without_an_enhanced_code() {
	let source = r#"Reply::single(552, "message too big") Reply::single(450, "4.7.1 ok")
		Reply::single(550, "4.1.1 wrong class") Reply::single(250, "fine") "421 bye\r\n""#;
	assert_eq!(
		offenders("src/smtp/x.rs", source, true),
		[
			"src/smtp/x.rs:1: message too big",
			"src/smtp/x.rs:2: 4.1.1 wrong class",
			"src/smtp/x.rs:2: 421 bye\\r\\n",
		]
	);
}
