//! Complete guided transcripts and canonical-validator retry regressions.

use super::*;
use crate::cli::ui::prompt::{Answers as Draft, Policy};

fn drive(input: &str, saved: Draft) -> (io::Result<Answers>, String, Draft) {
	let mut input = input.as_bytes();
	let mut out = Vec::new();
	let mut checkpointed = Draft::new();
	let mut checkpoint = |answers: &Draft| {
		checkpointed = answers.clone();
		Ok(())
	};
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: Policy {
			interactive: true,
			colour: false,
			input_tty: false,
		},
		answers: saved,
		checkpoint: &mut checkpoint,
	};
	let result = run(
		&mut ui,
		&super::super::detect::tests::Scripted::found(None, None),
	);
	(result, String::from_utf8(out).unwrap(), checkpointed)
}

fn valid_input() -> String {
	// Mode, hostname, domains, mailbox skip, two addresses, two paths,
	// seven service choices, and image.
	format!("\nmail.example.org\nexample.org\n{}", "\n".repeat(13))
}

#[test]
fn guided_defaults_finish_all_seven_steps() {
	let (result, text, saved) = drive(&valid_input(), Draft::new());
	let answers = result.unwrap_or_else(|error| panic!("{error}: {text}"));
	assert_eq!(
		answers.data_dir,
		PathBuf::from("/var/lib/glyndor/epistle/data")
	);
	assert_eq!(answers.config_path, PathBuf::from("/etc/epistle/mail.toml"));
	assert!(answers.services.imap && answers.services.submission);
	assert!(!answers.services.api);
	assert!(
		answers.image.is_none(),
		"Enter must preserve the package host-binary mode"
	);
	assert_eq!(saved["image"], super::super::images::mail_base());
	assert!(text.contains("Step 7 of 7"));
	assert!(text.contains("publishing is not implemented"));
	assert!(saved.contains_key("image"));
}

#[test]
fn guided_retries_hostname_domains_paths_api_and_image_in_place() {
	let input = concat!(
		"manual\nbad hostname\nmail.example.org\nmail.example.org\nexample.org, example.org\nexample.org\n\n",
		"127.0.0.1\nnone\nnone\nrelative\n/var/lib/glyndor/epistle/data\n/var/lib/glyndor/epistle/data/config.toml\n/etc/epistle/mail.toml\n",
		"\n\n\n\n\nyes\nno\n\nepistle:latest\nepistle:dev\n"
	);
	let (result, text, saved) = drive(input, Draft::new());
	let answers = result.unwrap_or_else(|error| panic!("{error}: {text}"));
	for value in [
		"bad hostname",
		"mail.example.org: must not equal",
		"example.org, example.org",
		"127.0.0.1",
		"relative",
		"configuration and data directories must not overlap",
		"init cannot mint API credentials",
		"epistle:latest",
	] {
		assert!(text.contains(value), "missing {value}: {text}");
	}
	assert_eq!(answers.image.as_deref(), Some("epistle:dev"));
	assert_eq!(saved["API"], "no");
}

#[test]
fn resume_revalidates_without_reusing_confirmation_or_secrets() {
	let (result, _, saved) = drive(&valid_input(), Draft::new());
	assert!(result.is_ok());
	let (resumed, text, _) = drive("", saved);
	assert!(resumed.is_ok(), "{text}");
	assert!(!text.contains("Apply this setup"));
}

#[test]
fn interruption_checkpoint_can_resume_the_remaining_questions() {
	let (result, _, saved) = drive("manual\nmail.example.org\n\x03\n", Draft::new());
	assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
	assert_eq!(saved["hostname"], "mail.example.org");
	let (result, text, _) = drive(&format!("example.org\n{}", "\n".repeat(13)), saved);
	assert!(result.is_ok(), "{text}");
}

#[test]
fn automatic_mode_retries_dns_and_keeps_credential_references_only() {
	let input = format!(
		"2\nmail.example.org\nexample.org\n\n\n\n\n\nwrong\ncloudflare\nelsewhere.org\nexample.org\n2\nEPISTLE_DNS_TOKEN\n{}",
		"\n".repeat(8)
	);
	let (result, text, saved) = drive(&input, Draft::new());
	let answers = result.unwrap_or_else(|error| panic!("{error}: {text}"));
	let dns = answers.dns.unwrap();
	assert_eq!(dns.token_env.as_deref(), Some("EPISTLE_DNS_TOKEN"));
	assert!(dns.token.is_none());
	assert!(text.contains("wrong: choose a number"));
	assert!(text.contains("elsewhere.org: use a valid DNS zone"));
	assert!(!saved.contains_key("password"));
	assert!(!saved.contains_key("token"));
	assert!(!saved.contains_key("DNS credential reference"));
}

#[test]
fn credential_references_retry_without_echoing_or_checkpointing_pasted_values() {
	let mut input = &b"TOKEN=private-value\ninvalid name\nEPISTLE_DNS_TOKEN\n"[..];
	let mut out = Vec::new();
	let mut checkpoint = |_: &Draft| panic!("credential references must not be checkpointed");
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: Policy {
			interactive: true,
			colour: false,
			input_tty: false,
		},
		answers: Draft::new(),
		checkpoint: &mut checkpoint,
	};
	assert_eq!(
		credential_reference(&mut ui, false).unwrap(),
		"EPISTLE_DNS_TOKEN"
	);
	assert!(ui.answers.is_empty());
	let text = String::from_utf8(out).unwrap();
	assert!(!text.contains("private-value"));
	assert!(!text.contains("invalid name"));
	assert_eq!(text.matches("Invalid credential reference").count(), 2);
}

/// A file reference with a `$` would be interpolated by compose and expanded by
/// the loader of `mail.toml`, and stop the run after the keys were written when
/// the variable is unset, so the question asks again instead of taking it.
#[test]
fn a_file_credential_reference_with_an_environment_reference_is_asked_again() {
	let mut input = &b"/run/${AUDIT_DNS_FILE}\n/run/secrets/epistle-dns\n"[..];
	let mut out = Vec::new();
	let mut checkpoint = |_: &Draft| panic!("credential references must not be checkpointed");
	let mut ui = Prompt {
		reader: &mut input,
		out: &mut out,
		policy: Policy {
			interactive: true,
			colour: false,
			input_tty: false,
		},
		answers: Draft::new(),
		checkpoint: &mut checkpoint,
	};
	assert_eq!(
		credential_reference(&mut ui, true).unwrap(),
		"/run/secrets/epistle-dns"
	);
	let text = String::from_utf8(out).unwrap();
	assert_eq!(text.matches("Invalid credential reference").count(), 1);
}

#[test]
fn first_mailbox_retries_address_and_display_name_and_derives_the_account() {
	let input = format!(
		"alice+tag@example.org\ntorre.control@example.org\n{}\nAlice Liddell\nno\n",
		"x".repeat(129)
	);
	let mut reader = input.as_bytes();
	let mut out = Vec::new();
	let mut checkpoint = |_: &Draft| Ok(());
	let mut ui = Prompt {
		reader: &mut reader,
		out: &mut out,
		policy: Policy {
			interactive: true,
			colour: false,
			input_tty: false,
		},
		answers: Draft::new(),
		checkpoint: &mut checkpoint,
	};
	let mut answers: Answers = toml::from_str(&Answers::template()).unwrap();
	first_account(&mut ui, &mut answers).unwrap();
	assert!(!ui.answers.contains_key("password"));
	let first = answers.first_account.unwrap();
	assert_eq!(first.name(), "torre-control");
	assert_eq!(first.display_name.as_deref(), Some("Alice Liddell"));
	assert!(!first.role_aliases);
	let text = String::from_utf8(out).unwrap();
	assert!(text.contains("cannot give an account name"));
	assert!(text.contains("the maximum is 128"));
}

#[test]
fn an_invalid_resumed_hostname_is_asked_again() {
	let (_, _, mut saved) = drive(&valid_input(), Draft::new());
	saved.insert("hostname".into(), "bad hostname".into());
	let (result, text, _) = drive("mail.example.org\n", saved);
	assert_eq!(result.unwrap().hostname, "mail.example.org");
	assert!(text.contains("bad hostname: must be a valid FQDN"));
}

/// A draft written by another process can carry an escape sequence in a
/// path. Resuming revalidates the saved answer, refuses it and asks the
/// question again instead of carrying the sequence into the plan.
#[test]
fn a_resumed_path_with_a_control_sequence_is_asked_again() {
	let (_, _, mut saved) = drive(&valid_input(), Draft::new());
	saved.insert(
		"config_path".into(),
		"/etc/epistle/\u{1b}[2Jmail.toml".into(),
	);
	let (result, text, _) = drive("/tmp/guided/etc/mail.toml\n", saved);
	let answers = result.unwrap_or_else(|error| panic!("{error}: {text}"));
	assert_eq!(
		answers.config_path,
		PathBuf::from("/tmp/guided/etc/mail.toml")
	);
	assert!(
		text.contains("must not contain control characters"),
		"{text}"
	);
	assert!(!text.contains('\u{1b}'), "{text}");
}
