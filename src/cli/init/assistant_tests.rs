//! Assistant unit tests.

use super::*;

fn harness(input: &str) -> (Vec<u8>, Result<Filled, ()>) {
	let mut reader = std::io::BufReader::new(input.as_bytes());
	let mut out = Vec::new();
	let result = run(&mut reader, &mut out);
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
	             example.org\n\n\
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
	             n\n";
	let (out, result) = harness(input);
	assert!(result.is_ok(), "ok with retries, got {:?}", parse_out(&out));
	let text = parse_out(&out);
	assert!(
		text.contains("not a valid FQDN"),
		"missing the same rejection string the file path reports: {text}"
	);
}

#[test]
fn assistant_eof_before_confirmation_is_an_error() {
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
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
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	assert!(result.is_ok(), "got {:?}", parse_out(&out));
	let text = parse_out(&out);
	assert!(text.contains("not a valid FQDN"), "got {text}");
}

#[test]
fn assistant_accepts_automatic_with_minimal_inputs() {
	let input = "automatic\n\
	             mail.example.org\n\
	             example.org\n\n\
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
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "expected ok: got {text}, err={:?}", result);
	let filled = result.unwrap();
	assert!(matches!(filled.answers.mode, Mode::Automatic));
	assert!(filled.answers.dns.is_some());
}

#[test]
fn assistant_defaults_services_to_imap_and_submission() {
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
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
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
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
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
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
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
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
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             n\n\
	             n\n\
	             y\n\
	             y\n\
	             y\n\
	             \n";
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

#[test]
fn assistant_rejects_api_service_at_final_validation() {
	// The api service is refused by the shared validator, which the
	// assistant runs as a backstop after the questions. An operator
	// who answers `y` to the api prompt gets the validation error
	// printed and the interview aborts before any plan is produced.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             y\n\
	             y\n\
	             n\n\
	             n\n\
	             n\n\
	             y\n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(
		result.is_err(),
		"api=true must abort the interview; out: {text}"
	);
	assert!(
		text.contains("services.api") && text.contains("[api]"),
		"the abort message must tell the operator to edit [api] by hand: {text}"
	);
}

#[test]
fn assistant_automatic_mode_asks_dns_questions_and_does_not_echo_token() {
	// Two behaviours are pinned on the automatic-mode flow:
	// the assistant must walk through every [dns] question, and the
	// rendered prompts must never carry the token value back to the
	// operator.
	let token = "super-secret-dns-token";
	let input = format!(
		"automatic\n\
		 mail.example.org\n\
		 example.org\n\n\
		 \n\
		 \n\
		 /var/lib/epistle\n\
		 /etc/epistle/mail.toml\n\
		 cloudflare\n\
		 example.org\n\
		 {token}\n\
		 \n\
		 \n\
		 \n\
		 \n\
		 \n\
		 \n\
		 \n\
		 \n",
	);
	let (out, result) = harness(&input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	let filled = result.unwrap();
	let dns = filled
		.answers
		.dns
		.as_ref()
		.expect("automatic mode must populate [dns]");
	assert_eq!(dns.token.as_deref(), Some(token));
	assert_eq!(dns.provider, "cloudflare");
	assert_eq!(dns.zone, "example.org");
	assert!(
		text.contains("dns provider") && text.contains("dns zone") && text.contains("dns token"),
		"every dns prompt must be rendered: {text}"
	);
	assert!(
		!text.contains(token),
		"the token value must not appear in the rendered prompts: {text}"
	);
}

#[test]
fn assistant_empty_line_on_first_domain_is_rejected_with_a_hint() {
	// The first \"domain> \" line is empty: the assistant must reject
	// it with a hint that says \"at least one domain required\" and
	// re-prompt, not EOF out. The next non-empty domain is accepted.
	let input = "manual\n\
	             mail.example.org\n\
	             \n\
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	assert!(
		text.contains("at least one domain required"),
		"the hint must tell the operator why the empty line was rejected: {text}"
	);
	let filled = result.unwrap();
	assert_eq!(filled.answers.domains, vec!["example.org".to_string()]);
}

#[test]
fn assistant_invalid_bool_answer_is_echoed_as_a_hint() {
	// The default for the IMAP prompt is true (\"Y/n\"); the operator
	// types \"maybe\" which is neither an empty default nor a recognised
	// yes/no value. The assistant must echo a hint and re-prompt.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             maybe\n\
	             y\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	assert!(
		text.contains("answer y or n"),
		"the hint must tell the operator which answers are valid: {text}"
	);
}

#[test]
fn assistant_invalid_ipv4_answer_is_echoed_as_a_hint() {
	// The first IP question is for an IPv4 address. The operator types
	// a hostname; the assistant must echo \"not a valid IP address\"
	// and re-prompt.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             not.an.ip\n\
	             8.8.8.8\n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(result.is_ok(), "got {text}");
	assert!(
		text.contains("not a valid IP address"),
		"the hint must tell the operator what failed: {text}"
	);
}

#[test]
fn assistant_ipv6_answer_in_ipv4_question_is_rejected() {
	// The first IP question is for an IPv4 address. The operator
	// types an IPv6 address; the assistant must reject it with the
	// IPv4 hint, re-prompt, and accept the second answer.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             2001:db8::1\n\
	             8.8.8.8\n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(
		result.is_ok(),
		"the assistant must reprompt and complete: got {text}"
	);
	assert!(
		text.contains("expected an IPv4 address"),
		"the IPv4 hint must surface when the operator answered IPv6: {text}"
	);
}

#[test]
fn assistant_ipv4_answer_in_ipv6_question_is_rejected() {
	// The second IP question is for an IPv6 address. The operator
	// types an IPv4 address; the assistant must reject it with the
	// IPv6 hint, re-prompt, and accept the second answer.
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\
	             \n\
	             8.8.8.8\n\
	             2606:4700:4700::1111\n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n\
	             \n";
	let (out, result) = harness(input);
	let text = parse_out(&out);
	assert!(
		result.is_ok(),
		"the assistant must reprompt and complete: got {text}"
	);
	assert!(
		text.contains("expected an IPv6 address"),
		"the IPv6 hint must surface when the operator answered IPv4: {text}"
	);
}
