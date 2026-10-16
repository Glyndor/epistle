//! Per-domain DKIM selectors in `verify-dns`: a domain with a
//! `[dkim.domain]` override is checked against its own selector only.

use super::*;
use crate::config::Config;
use crate::spf::DnsFailure;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

#[derive(Default)]
struct StubDns {
	txt: HashMap<String, Vec<String>>,
	mx: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	ptr: HashMap<IpAddr, Vec<String>>,
}

impl DnsLookup for StubDns {
	fn txt(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let v = self.txt.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(v) })
	}
	fn addresses(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<IpAddr>, DnsFailure>> + Send + '_>> {
		let v = self.addresses.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(v) })
	}
	fn mx(
		&self,
		name: &str,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let v = self.mx.get(name).cloned().unwrap_or_default();
		Box::pin(async move { Ok(v) })
	}
	fn ptr(
		&self,
		ip: IpAddr,
	) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
		let v = self.ptr.get(&ip).cloned().unwrap_or_default();
		Box::pin(async move { Ok(v) })
	}
}

fn config_with_override(default_sel: &str, override_domain: &str, override_sel: &str) -> Config {
	let toml = format!(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
domains = ["example.org", "example.net"]

[dkim]
selector = "{default_sel}"
key_file = "/etc/mail/dkim.pem"

[[dkim.domain]]
name = "{override_domain}"
selector = "{override_sel}"
key_file = "/etc/mail/override.pem"
"#,
	);
	toml::from_str(&toml).expect("config")
}

#[tokio::test]
async fn per_domain_override_uses_its_own_selector() {
	let mut dns = StubDns::default();
	// The hostname and every domain have published records; only the
	// DKIM selectors differ per domain to exercise the override.
	dns.addresses.insert(
		"mail.example.org".into(),
		vec!["203.0.113.10".parse().unwrap()],
	);
	dns.ptr.insert(
		"203.0.113.10".parse().unwrap(),
		vec!["mail.example.org".into()],
	);
	dns.txt.insert(
		"per-sel._domainkey.example.org".into(),
		vec!["v=DKIM1; k=ed25519; p=AAAA".into()],
	);
	dns.txt.insert(
		"default-sel._domainkey.example.net".into(),
		vec!["v=DKIM1; k=ed25519; p=BBBB".into()],
	);
	dns.txt
		.insert("example.org".into(), vec!["v=spf1 mx -all".into()]);
	dns.txt
		.insert("example.net".into(), vec!["v=spf1 mx -all".into()]);
	dns.txt
		.insert("_dmarc.example.org".into(), vec!["v=DMARC1; p=none".into()]);
	dns.txt
		.insert("_mta-sts.example.org".into(), vec!["v=STSv1; id=x".into()]);
	dns.txt.insert(
		"_smtp._tls.example.org".into(),
		vec!["v=TLSRPTv1; rua=mailto:postmaster@example.org".into()],
	);
	dns.txt
		.insert("_dmarc.example.net".into(), vec!["v=DMARC1; p=none".into()]);
	dns.txt
		.insert("_mta-sts.example.net".into(), vec!["v=STSv1; id=x".into()]);
	dns.txt.insert(
		"_smtp._tls.example.net".into(),
		vec!["v=TLSRPTv1; rua=mailto:postmaster@example.net".into()],
	);
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.mx
		.insert("example.net".into(), vec!["mail.example.org".into()]);
	let config = config_with_override("default-sel", "example.org", "per-sel");
	let mut out = Vec::new();
	let code = report(
		&config.domains,
		&config.hostname,
		config.public_ipv4,
		config.public_ipv6,
		&dns,
		&config,
		(false, &mut out),
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	let text = String::from_utf8_lossy(&out);
	// The per-domain override at example.org means the report
	// must NOT mention the default selector for that domain.
	assert!(
		!text.contains("DKIM default-sel \u{2014} v=DKIM1; k=ed25519; p=AAAA"),
		"example.org must not be checked against the default selector, got: {text}"
	);
	// And it must mention the override selector for that domain.
	assert!(
		text.contains("DKIM per-sel \u{2014} v=DKIM1; k=ed25519; p=AAAA"),
		"example.org must be checked against the override selector, got: {text}"
	);
	// The other domain keeps the default.
	assert!(
		text.contains("DKIM default-sel \u{2014} v=DKIM1; k=ed25519; p=BBBB"),
		"example.net keeps the default selector, got: {text}"
	);
	assert!(
		!text.contains("DKIM per-sel \u{2014} v=DKIM1; k=ed25519; p=BBBB"),
		"example.net must not see the override selector, got: {text}"
	);
	assert_eq!(
		code,
		ExitCode::SUCCESS,
		"every record is published, the run must succeed, output was: {text}"
	);
}
