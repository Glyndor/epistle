//! Scripted interaction tests, with no terminal or process environment changes.

use super::*;

fn policy() -> Policy {
	Policy::new(true, true, false, &Env::default())
}

#[test]
fn validated_input_retries_and_checkpoints_only_the_accepted_value() {
	let mut input = &b"wrong\n42\n"[..];
	let mut out = Vec::new();
	let mut saved = Answers::new();
	let mut checkpoint = |answers: &Answers| {
		saved = answers.clone();
		Ok(())
	};
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: policy(),
		answers: Answers::new(),
		checkpoint: &mut checkpoint,
	};
	let value = ui
		.validated("count", "Choose the count", "", "42", |raw| {
			raw.parse::<u32>()
				.map_err(|_| "must be a whole number".into())
		})
		.unwrap();
	assert_eq!(value, 42);
	assert_eq!(saved.get("count").map(String::as_str), Some("42"));
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("wrong: must be a whole number; valid example: 42"));
	assert!(!text.contains("\"wrong\""));
}

#[test]
fn numbered_lists_and_enter_defaults_work() {
	let mut input = &b"9\n2\n\nyes\n"[..];
	let mut out = Vec::new();
	let mut checkpoint = |_: &Answers| Ok(());
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: policy(),
		answers: Answers::new(),
		checkpoint: &mut checkpoint,
	};
	ui.step(2, 7, "Identity").unwrap();
	assert_eq!(
		ui.choice("mode", "Choose mode", &["manual", "automatic"], 0)
			.unwrap(),
		1
	);
	assert!(ui.boolean("IMAP", "Read mail", true).unwrap());
	assert!(ui.confirm("Apply?").unwrap());
	assert!(!ui.answers.contains_key("Apply?"));
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("Step 2 of 7"));
	assert!(text.contains("1. manual\n  2. automatic"));
}

#[test]
fn interrupted_read_preserves_accepted_answers() {
	let mut input = &b"mail.example.org\n\x03\n"[..];
	let mut out = Vec::new();
	let mut saved = Answers::new();
	let mut checkpoint = |answers: &Answers| {
		saved = answers.clone();
		Ok(())
	};
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: policy(),
		answers: Answers::new(),
		checkpoint: &mut checkpoint,
	};
	ui.validated("hostname", "Server name", "", "mail.example.org", |raw| {
		Ok(raw.to_string())
	})
	.unwrap();
	assert_eq!(
		ui.line("Next?").unwrap_err().kind(),
		io::ErrorKind::Interrupted
	);
	assert_eq!(saved["hostname"], "mail.example.org");
}

/// The guided steps need both streams on a terminal and no `--json`. Any other
/// shape belongs to the piped assistant, so this reader must stay unread and
/// nothing may reach the stream.
#[test]
fn neither_a_plain_pipe_nor_json_reads_or_prints_questions() {
	for policy in [
		Policy::new(false, true, false, &Env::default()),
		Policy::new(true, false, false, &Env::default()),
		Policy::new(true, true, true, &Env::default()),
	] {
		let mut input = &b"yes\n"[..];
		let mut out = Vec::new();
		let mut checkpoint = |_: &Answers| Ok(());
		let mut ui = Prompt {
			reader: &mut input,
			out: &mut out,
			policy,
			answers: Answers::new(),
			checkpoint: &mut checkpoint,
		};
		assert!(ui.line("Apply?").is_err());
		assert_eq!(input, b"yes\n");
		assert!(out.is_empty());
	}
}

#[test]
fn no_color_and_dumb_terminal_keep_questions_plain() {
	for env in [
		Env {
			no_color: Some(std::ffi::OsStr::new("1")),
			..Env::default()
		},
		Env {
			term: Some(std::ffi::OsStr::new("dumb")),
			..Env::default()
		},
	] {
		let policy = Policy::new(true, true, false, &env);
		assert!(policy.interactive);
		assert!(!policy.colour);
		let mut input = &b"yes\n"[..];
		let mut out = Vec::new();
		let mut checkpoint = |_: &Answers| Ok(());
		let mut ui = Prompt {
			reader: &mut input,
			out: &mut out,
			policy,
			answers: Answers::new(),
			checkpoint: &mut checkpoint,
		};
		ui.step(1, 7, "Mode").unwrap();
		assert!(ui.confirm("Apply?").unwrap());
		assert!(!out.contains(&0x1b));
	}
}

#[test]
fn confirmation_requires_an_explicit_yes_even_after_resume() {
	for answer in ["\n", "no\n", "maybe\n"] {
		let mut input = answer.as_bytes();
		let mut out = Vec::new();
		let mut checkpoint = |_: &Answers| Ok(());
		let mut ui = Prompt {
			reader: &mut input,
			out: &mut out,
			policy: policy(),
			answers: Answers::from([("Apply?".into(), "yes".into())]),
			checkpoint: &mut checkpoint,
		};
		assert!(!ui.confirm("Apply?").unwrap());
	}
}

#[test]
fn terminal_input_is_coloured() {
	let mut input = &b"yes\n"[..];
	let mut out = Vec::new();
	let mut checkpoint = |_: &Answers| Ok(());
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: policy(),
		answers: Answers::new(),
		checkpoint: &mut checkpoint,
	};
	assert!(ui.confirm("Apply?").unwrap());
	assert!(out.contains(&0x1b));
}
