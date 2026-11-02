//! Additional module regressions.

use super::*;

#[test]
fn assistant_accepts_api_service_without_asking_for_a_token() {
	let input = "manual\n\
	             mail.example.org\n\
	             example.org\n\n\n\
	             \n\
	             \n\
	             /var/lib/epistle\n\
	             /etc/epistle/mail.toml\n\
	             y\n\
	             y\n\
	             n\n\
	             n\n\
	             n\n\
	             y\n\
	             n\n\
	             \n";
	let (out, result) = harness(input);
	let filled = result.expect("API service needs no static token");
	assert!(filled.answers.services.api);
	assert!(!parse_out(&out).contains("API token"));
}

#[test]
fn assistant_automatic_mode_asks_dns_questions_and_does_not_echo_token() {
	// Two behaviours are pinned on the automatic-mode flow:
	// the assistant must walk through every [dns] question, and the
	// rendered prompts must never carry the token value back to the
	// operator. The token is minted at run time so no literal ever
	// reaches the `dns.token` slot, the same shape the previous PRs
	// settled for credential-shaped parameters.
	let token: String = uuid::Uuid::now_v7().simple().to_string();
	let input = format!(
		"automatic\n\
		 mail.example.org\n\
		 example.org\n\n\n\
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
		 \n\
\n\
		 \n",
	);
	let (out, result) = harness(&input);
	let text = parse_out(&out);
	// The captured `text` is operator-visible prompts; if the test
	// fails it carries the token, so the message must name the
	// condition without echoing the prompts.
	assert!(result.is_ok(), "automatic mode must succeed");
	let filled = result.unwrap();
	let dns = filled
		.answers
		.dns
		.as_ref()
		.expect("automatic mode must populate [dns]");
	assert!(
		dns.token.as_deref() == Some(token.as_str()),
		"the [dns] token must round-trip through automatic mode"
	);
	assert_eq!(dns.provider, "cloudflare");
	assert_eq!(dns.zone, "example.org");
	// The captured `text` is operator-visible prompts; if the test
	// fails it carries the token, so the message must name the
	// condition without echoing the prompts.
	assert!(
		text.contains("dns provider") && text.contains("dns zone") && text.contains("dns token"),
		"every dns prompt must be rendered"
	);
	// The captured `text` is operator-visible prompts; if the test
	// fails it carries the token, so the message must name the
	// condition without echoing the prompts.
	assert!(
		!text.contains(&token),
		"the token value must not appear in the rendered prompts"
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
	             example.org\n\n\n\
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
	             example.org\n\n\n\
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
	             example.org\n\n\n\
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
	             example.org\n\n\n\
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

#[test]
fn the_assistant_echoes_a_refused_value_escaped_and_cut() {
	let long = "x".repeat(500);
	let input = format!("manual\na\u{202e}b\u{9b}\n{long}\nmail.example.org\nexample.org\n\n");
	let (out, _) = harness(&input);
	let text = parse_out(&out);
	assert!(text.contains("a\\u{202e}b\\u{9b}"), "{text}");
	assert!(
		!text.contains('\u{202e}') && !text.contains('\u{9b}'),
		"{text:?}"
	);
	assert!(!text.contains(&long), "a pasted value is cut");
}
