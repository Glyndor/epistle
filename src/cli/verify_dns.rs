//! `epistle verify-dns`: query the live DNS for each configured domain and
//! report drift from the records epistle expects. Read-only.

use std::process::ExitCode;

use crate::config::Config;
use crate::dns::{self, Status};
use crate::spf::{DnsLookup, SystemDns};

/// Run the DNS check against the system resolver.
pub(super) fn run(config: &Config, out: &mut impl std::io::Write) -> ExitCode {
	let dns = match SystemDns::from_system() {
		Ok(dns) => dns,
		Err(error) => {
			eprintln!("error: cannot start resolver: {error}");
			return ExitCode::FAILURE;
		}
	};
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("error: cannot start async runtime: {error}");
			return ExitCode::FAILURE;
		}
	};
	let selectors = dkim_selectors(config);
	runtime.block_on(report(
		&config.domains,
		&config.hostname,
		&selectors,
		&dns,
		out,
	))
}

/// The DKIM selectors epistle publishes (the Ed25519 selector plus an optional
/// RSA selector), used to locate the `_domainkey` records.
fn dkim_selectors(config: &Config) -> Vec<String> {
	let Some(dkim) = &config.dkim else {
		return Vec::new();
	};
	let mut selectors = vec![dkim.selector.clone()];
	if let Some(rsa) = &dkim.rsa_selector {
		selectors.push(rsa.clone());
	}
	selectors
}

/// Check every domain and write a report; the exit code is failure if any
/// expected record is missing (lookup errors are inconclusive, not failures).
async fn report(
	domains: &[String],
	hostname: &str,
	selectors: &[String],
	dns: &dyn DnsLookup,
	out: &mut impl std::io::Write,
) -> ExitCode {
	let mut all_ok = true;
	for domain in domains {
		let _ = writeln!(out, "{domain}:");
		let checks = dns::check_domain(domain, hostname, selectors, dns).await;
		for check in &checks {
			let _ = writeln!(
				out,
				"  {} {} — {}",
				symbol(&check.status),
				check.kind,
				check.detail
			);
		}
		if !dns::all_ok(&checks) {
			all_ok = false;
		}
	}
	if all_ok {
		ExitCode::SUCCESS
	} else {
		ExitCode::FAILURE
	}
}

/// A status glyph for the report line.
fn symbol(status: &Status) -> &'static str {
	match status {
		Status::Ok => "ok  ",
		Status::Missing => "MISS",
		Status::LookupError => "err ",
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::dns::Check;
	use crate::spf::DnsFailure;
	use std::collections::HashMap;
	use std::pin::Pin;

	#[derive(Default)]
	struct FakeDns {
		txt: HashMap<String, Vec<String>>,
		mx: HashMap<String, Vec<String>>,
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
			_name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<std::net::IpAddr>, DnsFailure>> + Send + '_>>
		{
			Box::pin(async move { Ok(Vec::new()) })
		}
		fn mx(
			&self,
			name: &str,
		) -> Pin<Box<dyn Future<Output = Result<Vec<String>, DnsFailure>> + Send + '_>> {
			let v = self.mx.get(name).cloned().unwrap_or_default();
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
			&[],
			&dns,
			&mut out,
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
		let mut out = Vec::new();
		let code = report(
			&["example.org".to_string()],
			"mail.example.org",
			&[],
			&dns,
			&mut out,
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
}
