//! Tests for the DNS provider abstraction and scoped secrets.

use super::*;
use std::sync::Mutex;

/// An in-memory provider, proving the trait is test-injectable.
#[derive(Default)]
struct FakeProvider {
	records: Mutex<Vec<DnsRecord>>,
}

impl DnsProvider for FakeProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			let mut records = self.records.lock().unwrap();
			records.retain(|r| !(r.name == record.name && r.kind == record.kind));
			records.push(record);
			Ok(())
		})
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.records
				.lock()
				.unwrap()
				.retain(|r| !(r.name == record.name && r.kind == record.kind));
			Ok(())
		})
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async move { Ok(self.records.lock().unwrap().clone()) })
	}
}

fn record() -> DnsRecord {
	DnsRecord {
		name: "_dmarc.example.org".to_string(),
		kind: RecordKind::Txt,
		value: "v=DMARC1; p=reject".to_string(),
		ttl: 3600,
		proxied: None,
	}
}

#[tokio::test]
async fn fake_provider_upsert_list_delete() {
	let provider = FakeProvider::default();
	provider
		.upsert("example.org", record())
		.await
		.expect("upsert");
	// Upsert is idempotent (replaces, not duplicates).
	provider
		.upsert("example.org", record())
		.await
		.expect("upsert");
	assert_eq!(provider.list("example.org").await.unwrap().len(), 1);
	provider
		.delete("example.org", record())
		.await
		.expect("delete");
	assert!(provider.list("example.org").await.unwrap().is_empty());
}

#[tokio::test]
async fn manual_provider_refuses_writes_but_lists_empty() {
	let provider = ManualProvider;
	assert_eq!(
		provider.upsert("example.org", record()).await,
		Err(ProviderError::Unsupported)
	);
	assert_eq!(
		provider.delete("example.org", record()).await,
		Err(ProviderError::Unsupported)
	);
	assert!(provider.list("example.org").await.unwrap().is_empty());
}

#[test]
fn record_kind_tokens() {
	assert_eq!(RecordKind::Aaaa.as_str(), "AAAA");
	assert_eq!(RecordKind::Tlsa.as_str(), "TLSA");
}

/// A type token is read in any letter case, and a type with no variant
/// keeps its name. A provider that returned `ns` and was read as an
/// `Other` would hide a delegation from the lockdown.
#[test]
fn a_type_token_is_read_in_any_letter_case() {
	assert_eq!(RecordKind::from_token("NS"), RecordKind::Ns);
	assert_eq!(RecordKind::from_token("ns"), RecordKind::Ns);
	assert_eq!(RecordKind::from_token("Https"), RecordKind::Https);
	assert_eq!(RecordKind::from_token("svcb"), RecordKind::Svcb);
	assert_eq!(RecordKind::from_token("txt"), RecordKind::Txt);
	assert_eq!(
		RecordKind::from_token("naptr"),
		RecordKind::Other("NAPTR".to_string())
	);
	assert_eq!(
		RecordKind::from_token("TYPE65280"),
		RecordKind::Other("TYPE65280".to_string())
	);
}

/// A token that cannot be a record type becomes `UNKNOWN`: a terminal
/// escape, a line break, an empty string, a token past the length cap and
/// a token of the cap's length plus one all fail the shape test, and the
/// cap's own length passes.
#[test]
fn a_type_token_that_is_not_a_record_type_becomes_unknown() {
	let unknown = RecordKind::Other(UNKNOWN_KIND.to_string());
	for hostile in ["", "NAPTR\u{1b}[2J", "A\r\nB", "NA PTR", "\u{e9}", "A;B"] {
		assert_eq!(RecordKind::from_token(hostile), unknown, "{hostile:?}");
	}
	let longest = "X".repeat(MAX_OTHER_KIND_LEN);
	assert_eq!(
		RecordKind::from_token(&longest),
		RecordKind::Other(longest.clone())
	);
	let too_long = "X".repeat(MAX_OTHER_KIND_LEN + 1);
	assert_eq!(RecordKind::from_token(&too_long), unknown);
	let enormous = "X".repeat(10 * 1024 * 1024);
	assert_eq!(RecordKind::from_token(&enormous), unknown);
}

/// One pair of quotes that wraps the whole value goes; a quote that is part
/// of the data stays, so a CAA or HTTPS target is not cut.
#[test]
fn unwrap_quotes_only_removes_a_pair_around_the_whole_value() {
	assert_eq!(unwrap_quotes("\"v=spf1 -all\""), "v=spf1 -all");
	assert_eq!(
		unwrap_quotes("0 issue \"ca.example\""),
		"0 issue \"ca.example\""
	);
	assert_eq!(unwrap_quotes("1 . alpn=\"h2\""), "1 . alpn=\"h2\"");
	assert_eq!(unwrap_quotes("\""), "\"");
	assert_eq!(unwrap_quotes("\"\""), "");
	assert_eq!(unwrap_quotes(""), "");
}

#[test]
fn scoped_secret_authorizes_only_its_zone() {
	let secret = ScopedSecret::new("example.org", "tok");
	assert!(secret.authorizes("example.org"));
	assert!(secret.authorizes("_dmarc.example.org"));
	assert!(secret.authorizes("MAIL.Example.ORG"));
	assert!(!secret.authorizes("other.example"));
	assert!(!secret.authorizes("notexample.org"));
}

#[test]
fn scoped_secret_debug_redacts_token() {
	let secret = ScopedSecret::new("example.org", "super-secret-token");
	let rendered = format!("{secret:?}");
	assert!(
		rendered.contains("example.org"),
		"the debug form must name the zone"
	);
	assert!(
		!rendered.contains("super-secret-token"),
		"the debug form must not carry the token"
	);
	assert!(
		rendered.contains("***"),
		"the debug form must show the redaction marker"
	);
}

#[test]
fn scoped_secret_from_env_reads_and_rejects_empty() {
	// Vary the var name per case to avoid cross-test env races.
	unsafe { std::env::set_var("EPISTLE_TEST_DNS_TOKEN_A", "  abc  ") };
	let secret =
		ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_A").expect("present");
	// `assert_eq!` on `secret.token()` would Debug-print the
	// token on a mismatch, dumping the credential into the
	// CI log. The boolean form names the contract without
	// echoing the payload.
	assert!(
		secret.token() == "abc",
		"the env var must be trimmed and loaded"
	);
	unsafe { std::env::set_var("EPISTLE_TEST_DNS_TOKEN_B", "   ") };
	assert!(ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_B").is_none());
	assert!(ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_UNSET").is_none());
}

#[cfg(unix)]
#[test]
fn scoped_secret_from_file_enforces_permissions() {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("token");
	let mut file = std::fs::File::create(&path).expect("create");
	writeln!(file, "secret-token").expect("write");

	// World/group-accessible: rejected.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	assert!(ScopedSecret::from_file("example.org", &path).is_err());

	// Owner-only: accepted and trimmed.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let secret = ScopedSecret::from_file("example.org", &path).expect("load");
	// `assert_eq!` on `secret.token()` would Debug-print the
	// token on a mismatch, dumping the credential into the
	// CI log. The boolean form names the contract without
	// echoing the payload.
	assert!(
		secret.token() == "secret-token",
		"the file must be loaded and trimmed"
	);
	assert_eq!(secret.zone(), "example.org");
}

#[cfg(unix)]
#[test]
fn scoped_secret_from_file_rejects_empty() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("empty");
	std::fs::write(&path, "   \n").expect("write");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	assert!(ScopedSecret::from_file("example.org", &path).is_err());
}

/// `txt_purpose` returns the canonical spec form for every tag epistle
/// publishes. The canonical form is the literal version string the
/// relevant RFC uses, so a match in [`same_txt_purpose`] is a literal
/// string compare.
#[test]
fn txt_purpose_recognises_every_known_tag() {
	assert_eq!(txt_purpose("v=spf1 mx -all"), Some("v=spf1"));
	assert_eq!(txt_purpose("v=DMARC1; p=reject"), Some("v=DMARC1"));
	assert_eq!(txt_purpose("v=DKIM1; k=rsa; p=ABCD"), Some("v=DKIM1"));
	assert_eq!(txt_purpose("v=STSv1; 1"), Some("v=STSv1"));
	assert_eq!(
		txt_purpose("v=TLSRPTv1; rua=mailto:rp@example.org"),
		Some("v=TLSRPTv1")
	);
}

/// The tag is the substring before the first whitespace or `;`. The
/// comparison is case-insensitive, the leading and trailing whitespace
/// is ignored, and one pair of surrounding double quotes (the wire
/// form some providers use) is tolerated.
#[test]
fn txt_purpose_is_case_insensitive_and_tolerates_quotes_and_whitespace() {
	assert_eq!(txt_purpose("V=SPF1 -all"), Some("v=spf1"));
	assert_eq!(txt_purpose("  v=spf1 mx -all  "), Some("v=spf1"));
	assert_eq!(txt_purpose("\"v=spf1 mx -all\""), Some("v=spf1"));
	assert_eq!(txt_purpose("v=DMARC1;p=reject"), Some("v=DMARC1"));
	assert_eq!(txt_purpose("\"V=DKIM1;k=ed25519\""), Some("v=DKIM1"));
}

/// An empty or whitespace-only value, a bare pair of quotes, and a
/// value without a recognised tag all return `None`. The DNS-01
/// challenge (`token-aaaa`) and the domain-verification token
/// (`google-site-verification=abc`) are the canonical untagged TXT
/// records.
#[test]
fn txt_purpose_returns_none_for_untagged_and_empty_values() {
	assert_eq!(txt_purpose("google-site-verification=abc123"), None);
	assert_eq!(txt_purpose("token-aaaa"), None);
	assert_eq!(txt_purpose(""), None);
	assert_eq!(txt_purpose("   "), None);
	assert_eq!(txt_purpose("\""), None);
}

/// Two values with the same tag match under the contract, regardless
/// of the part of the value that follows the tag. The matching is
/// case-insensitive on the tag itself.
#[test]
fn same_txt_purpose_matches_when_tags_match() {
	// SPF vs SPF
	assert!(same_txt_purpose("v=spf1 -all", "v=spf1 mx -all"));
	// DMARC vs DMARC with different policy
	assert!(same_txt_purpose("v=DMARC1; p=none", "v=DMARC1; p=reject"));
	// DKIM vs DKIM with different key and signature
	assert!(same_txt_purpose(
		"v=DKIM1; k=rsa; p=AAA",
		"v=DKIM1; k=ed25519; p=BBB"
	));
	// case-insensitive
	assert!(same_txt_purpose("V=SPF1 -all", "v=spf1 mx -all"));
	assert!(same_txt_purpose("V=dmarc1; p=none", "v=DMARC1; p=reject"));
}

/// Two values with different tags do not match. The contract is strict
/// on this: a re-upsert that should replace an SPF must not match a
/// DMARC at the same name, and vice versa.
#[test]
fn same_txt_purpose_does_not_match_different_tags() {
	assert!(!same_txt_purpose("v=spf1 -all", "v=DMARC1; p=none"));
	assert!(!same_txt_purpose("v=spf1 -all", "v=DKIM1; k=rsa"));
	assert!(!same_txt_purpose("v=DMARC1; p=reject", "v=DKIM1; k=rsa"));
	assert!(!same_txt_purpose("v=STSv1; 1", "v=TLSRPTv1; rua=mailto:a"));
}

/// Untagged values match only when they are identical (after the same
/// whitespace and surrounding-quote stripping). Two distinct DNS-01
/// challenge values at the same owner must not collide.
#[test]
fn same_txt_purpose_matches_untagged_only_when_identical() {
	// identical ACME tokens match
	assert!(same_txt_purpose("token-aaaa", "token-aaaa"));
	// identical with surrounding quotes still match
	assert!(same_txt_purpose("\"token-aaaa\"", "token-aaaa"));
	assert!(same_txt_purpose("\"token-aaaa\"", "\"token-aaaa\""));
	// different ACME tokens do not match
	assert!(!same_txt_purpose("token-aaaa", "token-bbbb"));
	// different untagged verification tokens do not match
	assert!(!same_txt_purpose(
		"google-site-verification=abc",
		"google-site-verification=xyz"
	));
	// leading/trailing whitespace is ignored on the compare
	assert!(same_txt_purpose("  token-aaaa  ", "token-aaaa"));
}

/// A tagged value never matches an untagged one. The contract is
/// strict on this: an SPF upsert must not be confused with a DNS-01
/// cleanup, even if the operator mistyped a value.
#[test]
fn same_txt_purpose_does_not_mix_tagged_and_untagged() {
	assert!(!same_txt_purpose("v=spf1 -all", "token-aaaa"));
	assert!(!same_txt_purpose(
		"v=DMARC1; p=reject",
		"google-site-verification=abc"
	));
	assert!(!same_txt_purpose(
		"google-site-verification=abc",
		"v=spf1 -all"
	));
}

/// An empty value is its own bucket. Two empty values match (the
/// DKIM rotator's retire-an-entire-selector delete passes an empty
/// value, and a delete with an empty value of an empty record is
/// vacuously a no-op). An empty value never matches a tagged or
/// untagged non-empty value.
#[test]
fn same_txt_purpose_with_an_empty_value() {
	assert!(same_txt_purpose("", ""));
	assert!(same_txt_purpose("   ", ""));
	assert!(same_txt_purpose("\"\"", ""));
	assert!(!same_txt_purpose("", "v=spf1 -all"));
	assert!(!same_txt_purpose("", "token-aaaa"));
	assert!(!same_txt_purpose("v=spf1 -all", ""));
	assert!(!same_txt_purpose("token-aaaa", ""));
}

#[test]
fn an_mx_target_loses_its_root_dot_except_the_null_mx() {
	assert_eq!(mx_target_for_api("mail.example.org."), "mail.example.org");
	assert_eq!(mx_target_for_api("mail.example.org"), "mail.example.org");
	assert_eq!(mx_target_for_api("."), ".");
}
