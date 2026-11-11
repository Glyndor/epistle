//! The role of a domain decides which records `verify-dns` expects: a
//! `send-only` domain is not reported as missing the record of a group its
//! role leaves out, and a `full` one still is.

use super::base::FakeDns;
use crate::cli::verify::dns::tests::*;

/// The zone of a domain that answers the core records and nothing else: the
/// MX, the SPF and the DMARC, with the mail host resolving and confirmed.
fn core_only() -> FakeDns {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt
		.insert("example.org".into(), vec!["v=spf1 -all".into()]);
	dns.txt
		.insert("_dmarc.example.org".into(), vec!["v=DMARC1; p=none".into()]);
	dns.addresses.insert(
		"mail.example.org".into(),
		vec!["203.0.113.10".parse().unwrap()],
	);
	dns.ptr.insert(
		"203.0.113.10".parse().unwrap(),
		vec!["mail.example.org".into()],
	);
	dns
}

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = '/var/lib/mail'\ndomains = ['example.org']\n{extra}"
	))
	.expect("config")
}

async fn verify(config: &Config) -> (ExitCode, String) {
	let mut out = Vec::new();
	let code = report(
		&["example.org".to_string()],
		"mail.example.org",
		None,
		None,
		&core_only(),
		config,
		(false, &mut out),
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	(code, String::from_utf8(out).expect("utf8"))
}

#[tokio::test]
async fn a_send_only_domain_is_not_missing_the_mta_sts_record() {
	let (code, text) = verify(&config("send_only_domains = ['example.org']\n")).await;
	assert_eq!(code, ExitCode::SUCCESS, "{text}");
	assert!(!text.contains("MISS"), "{text}");
	assert!(text.contains("skip"), "{text}");
}

#[tokio::test]
async fn a_full_domain_without_the_mta_sts_record_is_still_missing_it() {
	let (code, text) = verify(&config("")).await;
	assert_eq!(code, ExitCode::FAILURE, "{text}");
	assert!(text.contains("MISS"), "{text}");
}

#[tokio::test]
async fn changing_the_role_changes_what_verify_dns_expects() {
	let (full, _) = verify(&config("")).await;
	let (send_only, _) = verify(&config("send_only_domains = ['example.org']\n")).await;
	assert_ne!(full, send_only);
}
