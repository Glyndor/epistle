//! MTA-STS discovery outcomes without a cached policy (RFC 8461 section
//! 3.3): when the TXT lookup or the policy fetch fails, delivery goes on
//! as though the domain published no policy, rather than waiting on a
//! policy that may not exist. A cached policy is covered by the store's
//! own tests.

use super::tests_policy_matrix::{Mx, MxDns, Seen, attempt_with, attempt_with_tlsrpt};
use super::*;
use crate::config::OutboundTls;
use crate::dane::rrset::TlsaRrset;
use crate::spf::{DnsFailure, DnsLookup};

type Lookup<'a, T> = std::pin::Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// Discovery TXT that fails, is published, or is malformed-policy backed.
struct Discovery {
	txt_fails: bool,
}

impl DnsLookup for Discovery {
	fn txt(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		let result = if self.txt_fails {
			Err(DnsFailure::Temporary)
		} else {
			Ok(vec!["v=STSv1; id=1".to_string()])
		};
		Box::pin(async move { result })
	}

	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}

	fn tlsa(&self, _name: &str) -> Lookup<'_, TlsaRrset> {
		Box::pin(async { Ok(TlsaRrset::Absent) })
	}
}

/// A policy host that answers with `body`, or cannot be reached.
struct PolicyHost(Option<&'static str>);

impl crate::mtasts::PolicyFetcher for PolicyHost {
	fn fetch(
		&self,
		_domain: &str,
	) -> std::pin::Pin<
		Box<dyn Future<Output = Result<String, crate::mtasts::PolicyError>> + Send + '_>,
	> {
		let result = self
			.0
			.map(str::to_string)
			.ok_or_else(|| crate::mtasts::PolicyError::Temporary("connection refused".to_string()));
		Box::pin(async move { result })
	}
}

async fn deliver_plain(txt_fails: bool, body: Option<&'static str>) -> Seen {
	attempt_with(
		Arc::new(Discovery { txt_fails }),
		Box::new(PolicyHost(body)),
		Mx::Plain,
		OutboundTls::Strict,
		MxDns::Secure,
	)
	.await
}

#[tokio::test]
async fn a_failed_txt_lookup_delivers_as_without_policy() {
	assert_eq!(deliver_plain(true, None).await, Seen::DeliveredPlain);
}

#[tokio::test]
async fn an_unreachable_policy_host_delivers_as_without_policy() {
	assert_eq!(deliver_plain(false, None).await, Seen::DeliveredPlain);
}

#[tokio::test]
async fn a_malformed_policy_delivers_as_without_policy() {
	assert_eq!(
		deliver_plain(false, Some("version: STSv1\nmode: enforce\n")).await,
		Seen::DeliveredPlain
	);
}

#[tokio::test]
async fn a_fetched_enforce_policy_still_refuses_cleartext() {
	let enforce = "version: STSv1\nmode: enforce\nmx: mx.remote.example\nmax_age: 86400\n";
	assert_eq!(deliver_plain(false, Some(enforce)).await, Seen::Deferred);
}

/// RFC 8460 §4.3: when the policy host is unreachable, the next aggregate
/// report must record a `sts-policy-fetch-error` failure for the recipient
/// domain. The SMTP attempt still runs (opportunistic) and gets its own
/// line, but the policy-fetch line is what the recipient domain needs to
/// see to know their policy host is down.
#[tokio::test]
async fn a_failed_https_fetch_records_sts_policy_fetch_error() {
	let dns = Arc::new(Discovery { txt_fails: false });
	let journal =
		attempt_with_tlsrpt(dns, Box::new(PolicyHost(None)), Mx::Plain, MxDns::Secure).await;
	let fetch_error = journal
		.iter()
		.find(|entry| entry["result"] == "sts-policy-fetch-error")
		.unwrap_or_else(|| panic!("missing sts-policy-fetch-error entry, journal: {journal:?}"));
	assert_eq!(fetch_error["policy_type"], "sts");
	assert_eq!(fetch_error["policy_domain"], "remote.example");
}

/// RFC 8460 §4.3: when the policy body does not parse, the session is
/// recorded as `sts-policy-invalid` (the existing code path already does
/// this; pinned here so the behaviour has a regression test).
#[tokio::test]
async fn a_malformed_policy_body_records_sts_policy_invalid() {
	let dns = Arc::new(Discovery { txt_fails: false });
	let journal = attempt_with_tlsrpt(
		dns,
		Box::new(PolicyHost(Some("not a real policy"))),
		Mx::Plain,
		MxDns::Secure,
	)
	.await;
	let invalid = journal
		.iter()
		.find(|entry| entry["result"] == "sts-policy-invalid")
		.unwrap_or_else(|| panic!("missing sts-policy-invalid entry, journal: {journal:?}"));
	assert_eq!(invalid["policy_type"], "sts");
	assert_eq!(invalid["policy_domain"], "remote.example");
}
