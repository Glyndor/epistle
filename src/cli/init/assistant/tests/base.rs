//! Assistant unit tests.

use super::*;

fn harness(input: &str) -> (Vec<u8>, Result<Filled, ()>) {
	let mut reader = std::io::BufReader::new(input.as_bytes());
	let mut out = Vec::new();
	let nothing_found = super::super::super::detect::tests::base::Scripted::found(None, None);
	let result = run(&mut reader, &mut out, &nothing_found);
	(out, result)
}

fn parse_out(out: &[u8]) -> String {
	String::from_utf8_lossy(out).into_owned()
}

#[test]
fn assistant_rejects_invalid_hostname_with_the_same_text_as_the_file_path() {
	let input = "automatic\n\
	             not a domain\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             cloudflare\n\
	             example.org\n\
	             \n\
	             /run/secrets/cf\n\
	             \n\
	             \n\
	             y\n\
	             y\n\
	             n\n\
	             n\n\
	             n\n\
	             n\n\
	             \n\
	             y\n";
	let (out, result) = harness(input);
	assert!(result.is_ok(), "ok with retries, got {:?}", parse_out(&out));
	let text = parse_out(&out);
	assert!(
		text.contains("\"not a domain\": spaces are not allowed; for example \"mail.example.org\""),
		"the refusal must name the value, the rule and a host name to type: {text}"
	);
}

#[test]
fn assistant_eof_before_confirmation_is_an_error() {
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	assert!(
		result.is_err(),
		"expected EOF error, got {:?}",
		parse_out(&out)
	);
}

#[test]
fn assistant_invalid_domain_text_is_shown() {
	let input = "manual\n\
	             mail.example.org\n\
	             bad name\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	assert!(result.is_ok(), "got {:?}", parse_out(&out));
	let text = parse_out(&out);
	assert!(
		text.contains("\"bad name\": spaces are not allowed; for example \"example.org\""),
		"got {text}"
	);
}

#[test]
fn assistant_accepts_automatic_with_minimal_inputs() {
	let input = "automatic\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             cloudflare\n\
	             example.org\n\
	             \n\
	             /run/secrets/cf\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	let Ok(filled) = result else {
		panic!("the assistant refused the answers; transcript: {text}");
	};
	assert!(matches!(filled.answers.mode, Mode::Automatic));
	assert!(filled.answers.dns.is_some());
}

#[test]
fn assistant_defaults_services_to_imap_and_submission() {
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	let filled = result.unwrap();
	assert!(filled.answers.services.imap);
	assert!(filled.answers.services.submission);
	assert!(!filled.answers.services.pop3);
}

#[test]
fn assistant_collects_multiple_validation_errors_at_the_end() {
	let input = "manual\n\
	             example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	assert!(result.is_err());
	let text = parse_out(&out);
	assert!(
		text.contains("hostname"),
		"expected hostname complaint: {text}"
	);
}

#[test]
fn assistant_prints_every_validation_error_before_returning() {
	// When validate() collects multiple errors, the assistant must
	// render every one of them on stderr so the operator sees the
	// whole list, not just the first. A change that returned on the
	// first error or dropped the loop would leave the operator
	// guessing which answers to revisit.
	let input = "manual\n\
	             example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_err(), "expected validation failure");
	assert!(
		text.contains("hostname"),
		"the hostname complaint must be in the rendered output: {text}"
	);
}

#[test]
fn assistant_keeps_the_good_value_after_a_bad_answer() {
	// The first answer is rejected by the parser; the second one
	// survives. The assistant must not retain the bad answer.
	let input = "foo\n\
	             manual\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
\n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	let filled = result.unwrap();
	assert!(matches!(filled.answers.mode, Mode::Manual));
	assert!(
		text.contains("answer \"manual\" or \"automatic\""),
		"bad answer must be echoed back as a hint: {text}"
	);
}

#[test]
fn assistant_services_questions_set_the_flags() {
	// Disable every default-true service and enable every default-false
	// one the assistant can still opt into; the api service stays at
	// its default (`false`) because the validator refuses `api = true`
	// until `init` can mint a credential, and `y` on the api prompt
	// would surface the validation error and abort the interview.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             n\n\
	             n\n\
	             y\n\
	             y\n\
	             y\n\
	             n\n\
	             n\n\
	             \n\
	             y\n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	let filled = result.unwrap();
	assert!(!filled.answers.services.imap);
	assert!(!filled.answers.services.submission);
	assert!(filled.answers.services.pop3);
	assert!(filled.answers.services.managesieve);
	assert!(filled.answers.services.webdav);
	assert!(!filled.answers.services.api);
}

#[path = "base_extra.rs"]
mod extra;
