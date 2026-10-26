//! Review is an allowlist and does not serialize credentials.

use super::*;

#[test]
fn review_lists_ordinary_choices_without_credentials() {
	let mut answers: Answers = toml::from_str(&Answers::template()).unwrap();
	let secret = uuid::Uuid::now_v7().to_string();
	answers.dns = Some(super::super::answers::DnsAnswers {
		provider: "cloudflare".into(),
		zone: "example.org".into(),
		token: Some(secret.clone()),
		..Default::default()
	});
	let mut out = Vec::new();
	render(&answers, &mut out).unwrap();
	let text = String::from_utf8(out).unwrap();
	for value in [
		"Mode:",
		"Hostname:",
		"Domains:",
		"Public IPv4:",
		"Public IPv6:",
		"Data directory:",
		"Configuration:",
		"First mailbox:",
		"DNS provider:",
		"IMAP:",
		"submission:",
		"POP3:",
		"ManageSieve:",
		"WebDAV:",
		"API:",
		"PostgreSQL:",
		"Image:",
	] {
		assert!(text.contains(value), "missing {value}");
	}
	assert!(text.contains(super::super::images::mail_base()));
	assert!(text.contains("Mail binary: installed host binary"));
	assert!(!text.contains(&secret));
}
