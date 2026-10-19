//! Wire format regressions for complete DKIM fields, without network access.

use super::*;

fn short_lines(signature: &str) {
	for line in signature.split("\r\n").filter(|line| !line.is_empty()) {
		assert!(line.len() <= 998, "DKIM line has {} octets", line.len());
	}
}

#[tokio::test]
async fn repeated_fields_fit_wire_limit_and_both_signatures_verify() {
	let (signer, dns) = fixture(true);
	let mut raw = "Resent-Date: Sun, 18 Oct 2026 12:00:00 +0000\r\nResent-From: relay@example.org\r\nResent-To: bob@example.net\r\n".repeat(60);
	raw.push_str(&message());
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, &raw, DkimOutcome::Pass).await;
	short_lines(&signature);
	let expected: Vec<_> = raw
		.split("\r\n\r\n")
		.next()
		.expect("headers")
		.lines()
		.rev()
		.map(|line| line.split_once(':').expect("field").0.to_ascii_lowercase())
		.chain(OVERSIGNED_HEADERS.iter().map(|name| (*name).to_string()))
		.collect();
	for field in signature_headers(signature.as_bytes()) {
		assert_eq!(
			names(&field),
			expected,
			"folding must preserve complete names and order"
		);
	}
}

#[tokio::test]
async fn rsa4096_and_long_domain_and_selectors_fit_wire_limit() {
	let (mut signer, _) = fixture(false);
	let domain = format!("{}.{}.org", "d".repeat(63), "e".repeat(63));
	signer.selector = "s".repeat(63);
	let rsa_selector = "r".repeat(63);
	let dir = tempfile::tempdir().expect("tempdir");
	let key = dir.path().join("rsa.pem");
	std::fs::write(&key, include_str!("test_rsa4096_key.pem")).expect("RSA key");
	let signer = signer.with_rsa(&rsa_selector, &key).expect("load RSA4096");
	let dns = KeyDns(HashMap::from([
		(
			format!("{}._domainkey.{domain}", signer.selector),
			vec![signer.dns_record_value()],
		),
		(
			format!("{rsa_selector}._domainkey.{domain}"),
			vec![signer.rsa_dns_record_value().expect("RSA record")],
		),
	]));
	let raw = message();
	let signature = signer.sign(&domain, raw.as_bytes()).expect("sign");
	check(&dns, &signature, &raw, DkimOutcome::Pass).await;
	short_lines(&signature);
}

#[tokio::test]
async fn unsafe_resent_names_are_excluded_without_malformed_signatures() {
	let (signer, dns) = fixture(true);
	for name in [
		"Resent-X;flag",
		"Resent-X;h=from",
		"Resent-X space",
		"Resent-X\ttab",
		"Resent-X\u{1}",
		"Resent-X\u{7f}",
		"Resent-Xé",
		"Resent-X ",
	] {
		let raw = format!("{name}: value\r\nFrom: alice@example.org\r\n\r\nbody\r\n");
		let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
		check(&dns, &signature, &raw, DkimOutcome::Pass).await;
		for field in signature_headers(signature.as_bytes()) {
			assert!(
				!names(&field).iter().any(|name| name.starts_with("resent-")),
				"{name:?}"
			);
		}
	}
}

#[tokio::test]
async fn a_folded_continuation_is_not_read_as_a_field_name() {
	let (signer, dns) = fixture(true);
	for fold in [" ", "\t"] {
		let raw = format!(
			"Resent-Date: Mon, 1 Jan 2024 00:00:00 +0000\r\n{fold}Resent-X;flag: more\r\nFrom: alice@example.org\r\n\r\nbody\r\n"
		);
		let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
		check(&dns, &signature, &raw, DkimOutcome::Pass).await;
		for field in signature_headers(signature.as_bytes()) {
			let listed = names(&field);
			assert!(listed.iter().any(|name| name == "resent-date"), "{fold:?}");
			assert!(!listed.iter().any(|name| name.contains(';')), "{fold:?}");
		}
	}
}

#[tokio::test]
async fn safe_resent_punctuation_and_colons_in_values_are_signed() {
	let (signer, dns) = fixture(true);
	let raw =
		"Resent-X!#$%&'*+-.^_`|~=?[]: before:after\r\nFrom: alice@example.org\r\n\r\nbody\r\n";
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, raw, DkimOutcome::Pass).await;
	check(
		&dns,
		&signature,
		&raw.replace("before:after", "changed"),
		DkimOutcome::Fail,
	)
	.await;
}

#[test]
fn delivery_tradeoffs_are_documented() {
	let page = include_str!("../../docs/headers.md")
		.split_whitespace()
		.collect::<Vec<_>>()
		.join(" ");
	for warning in [
		"Rewriting `Content-Type`",
		"adding an absent oversigned field",
		"does not tolerate changes to field values",
		"SPF is no longer aligned",
		"Transit fields are excluded because relays change them",
	] {
		assert!(
			page.contains(warning),
			"missing delivery warning: {warning}"
		);
	}
}

#[tokio::test]
async fn rewriting_content_type_breaks_each_algorithm_even_with_ascii_body() {
	let (signer, dns) = fixture(true);
	let raw =
		"From: alice@example.org\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nASCII body\r\n";
	let signature = signer.sign("example.org", raw.as_bytes()).expect("sign");
	check(&dns, &signature, raw, DkimOutcome::Pass).await;
	let rewritten = raw.replace("charset=utf-8", "charset=us-ascii");
	check(&dns, &signature, &rewritten, DkimOutcome::Fail).await;
}
