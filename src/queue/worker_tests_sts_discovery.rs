//! MTA-STS discovery outcomes without a cached policy (RFC 8461 section
//! 3.3): when the TXT lookup or the policy fetch fails, delivery goes on
//! as though the domain published no policy, rather than waiting on a
//! policy that may not exist. A cached policy is covered by the store's
//! own tests.

use super::tests_policy_matrix::{Mx, Seen, attempt_with};
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
