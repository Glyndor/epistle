//! Tests for `verify_dns`: the report loop and the single-signature DKIM
//! startup warning.
//!
//! In a sibling file (not inline) so `verify_dns.rs` can grow with the
//! report loop without dragging the test fixtures with it.

use super::*;
use crate::dns::Check;
use crate::spf::DnsFailure;
use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;

#[derive(Default)]
struct FakeDns {
	txt: HashMap<String, Vec<String>>,
	mx: HashMap<String, Vec<String>>,
	addresses: HashMap<String, Vec<IpAddr>>,
	ptr: HashMap<IpAddr, Vec<String>>,
}

impl DnsLookup for FakeDns {
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

#[tokio::test]
async fn report_fails_and_prints_on_missing_records() {
	let dns = FakeDns::default();
	let mut out = Vec::new();
	let code = report(
		&["example.org".to_string()],
		"mail.example.org",
		None,
		None,
		&[],
		&dns,
		&mut out,
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	assert_eq!(code, ExitCode::FAILURE);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("example.org:"), "{text}");
	assert!(text.contains("MISS"), "{text}");
}

#[tokio::test]
async fn report_succeeds_when_records_present() {
	let mut dns = FakeDns::default();
	dns.mx
		.insert("example.org".into(), vec!["mail.example.org".into()]);
	dns.txt
		.insert("example.org".into(), vec!["v=spf1 -all".into()]);
	dns.txt
		.insert("_dmarc.example.org".into(), vec!["v=DMARC1; p=none".into()]);
	dns.txt
		.insert("_mta-sts.example.org".into(), vec!["v=STSv1; id=1".into()]);
	// The hostname resolves, the PTR confirms the round trip, and the
	// configured addresses are None so the host check falls back to the
	// resolver's answer.
	dns.addresses.insert(
		"mail.example.org".into(),
		vec!["203.0.113.10".parse().unwrap()],
	);
	dns.ptr.insert(
		"203.0.113.10".parse().unwrap(),
		vec!["mail.example.org".into()],
	);
	let mut out = Vec::new();
	let code = report(
		&["example.org".to_string()],
		"mail.example.org",
		None,
		None,
		&[],
		&dns,
		&mut out,
		crate::cli::style::Progress::start("checking"),
	)
	.await;
	assert_eq!(code, ExitCode::SUCCESS);
}

fn check(status: Status) -> Check {
	Check {
		kind: "X".into(),
		name: "n".into(),
		status,
		detail: "d".into(),
	}
}

#[test]
fn symbols_cover_every_status() {
	assert_eq!(symbol(&check(Status::Ok).status), "ok  ");
	assert_eq!(symbol(&check(Status::Missing).status), "MISS");
	assert_eq!(symbol(&check(Status::LookupError).status), "err ");
}

#[test]
fn emit_single_signature_warning_writes_when_dkim_has_no_rsa() {
	// The warning the operator sees is exactly what the helper produces.
	// Captured through an in-memory writer so the assertion does not
	// race with anything else writing to stderr.
	let config: Config = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	)
	.expect("config");
	let mut err = Vec::new();
	emit_single_signature_warning(&config, &mut err);
	let text = String::from_utf8(err).expect("utf8");
	assert!(
		text.contains("warning:"),
		"emission must use the `warning:` prefix: {text}"
	);
	assert!(
		text.contains("signs with one key only"),
		"emission must reuse the shared helper text: {text}"
	);
}

#[test]
fn emit_single_signature_warning_is_silent_when_both_rsa_fields_are_set() {
	// Symmetric to the previous test: a fully-configured DKIM section
	// must not produce a warning through this call site either.
	let config: Config = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
rsa_key_file = "/etc/mail/rsa.pem"
"#,
	)
	.expect("config");
	let mut err = Vec::new();
	emit_single_signature_warning(&config, &mut err);
	assert!(
		err.is_empty(),
		"both RSA fields set: warning must not be written, got {err:?}"
	);
}

#[test]
fn emit_single_signature_warning_is_silent_without_a_dkim_section() {
	// The unsigned-server case is a separate finding (no [dkim] at
	// all); this call site must not surface it.
	let config: Config = toml::from_str(
		r#"
hostname = "mail.example.org"
data_dir = "/var/lib/mail"
"#,
	)
	.expect("config");
	let mut err = Vec::new();
	emit_single_signature_warning(&config, &mut err);
	assert!(
		err.is_empty(),
		"absent [dkim] must stay silent, got {err:?}"
	);
}

#[test]
fn run_with_writers_writes_the_warning_before_dns_lookups() {
	// `verify_dns::run_with_writers` is the entry point the dispatcher
	// calls; the warning must land in the caller-supplied `err`
	// writer before the function touches DNS. The hostname used here
	// (`example.invalid`) is reserved by RFC 2606 to never resolve,
	// so the test does not depend on the host's real DNS state and
	// always finishes quickly with FAILURE (lookup error).
	let config: Config = toml::from_str(
		r#"
hostname = "example.invalid"
data_dir = "/var/lib/mail"
domains = ["example.invalid"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
"#,
	)
	.expect("config");
	let mut out = Vec::new();
	let mut err = Vec::new();
	let _ = run_with_writers(&config, &mut out, &mut err);
	let err_text = String::from_utf8_lossy(&err);
	assert!(
		err_text.contains("warning:"),
		"`verify-dns` call site must write the warning to err before DNS: {err_text}"
	);
	assert!(
		err_text.contains("signs with one key only"),
		"`verify-dns` call site must reuse the shared helper text: {err_text}"
	);
}

#[test]
fn run_with_writers_is_silent_when_both_rsa_fields_are_set() {
	// Symmetric to the previous test: a fully-configured DKIM section
	// must not surface a warning through `verify-dns` either.
	let config: Config = toml::from_str(
		r#"
hostname = "example.invalid"
data_dir = "/var/lib/mail"
domains = ["example.invalid"]

[dkim]
selector = "mail"
key_file = "/etc/mail/dkim.pem"
rsa_selector = "rsa1"
rsa_key_file = "/etc/mail/rsa.pem"
"#,
	)
	.expect("config");
	let mut out = Vec::new();
	let mut err = Vec::new();
	let _ = run_with_writers(&config, &mut out, &mut err);
	let err_text = String::from_utf8_lossy(&err);
	assert!(
		!err_text.contains("signs with one key only"),
		"both RSA fields set: verify-dns must not emit the warning: {err_text}"
	);
}
