//! Real evaluators, with only DNS answers and HTTPS bodies supplied by fixtures.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;

use epistle::dmarc::{DmarcOutcome, evaluate};
use epistle::mtasts::{PolicyError, PolicyFetcher, PolicyStore};
use epistle::spf::{DnsFailure, DnsLookup, SpfOutcome, check_host};

pub const DOMAIN: &str = "sender.example";
pub const MEMORY_LIMIT: usize = 8 * 1024 * 1024;

/// Count the complete evaluation (including DNS parsing for wire cases).
/// The current-thread runtime keeps all measured work on the same allocator
/// thread; unrelated tests use their own thread-local counters.
pub fn bounded<F: Future<Output = ()>>(future: F) {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("test runtime");
	let (outcome, peak) = super::allocation::peak_bytes(|| {
		std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
			runtime.block_on(async {
				tokio::time::timeout(super::common::BANNER_READ_DEADLINE, future)
					.await
					.expect("DNS evaluation must terminate");
			})
		}))
	});
	eprintln!("DNS evaluation peak: {peak} bytes (limit {MEMORY_LIMIT})");
	assert!(
		peak < MEMORY_LIMIT,
		"DNS peak {peak} exceeds {MEMORY_LIMIT}"
	);
	if let Err(panic) = outcome {
		std::panic::resume_unwind(panic);
	}
}

pub async fn spf(dns: &dyn DnsLookup) -> SpfOutcome {
	check_host(
		dns,
		IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
		DOMAIN,
		"sender@sender.example",
		"helo.example",
	)
	.await
}

pub async fn dmarc(dns: &dyn DnsLookup) -> DmarcOutcome {
	evaluate(dns, DOMAIN, (SpfOutcome::Fail, Some(DOMAIN)), &[]).await
}

/// A usable body makes accidental discovery observable as Some(Policy),
/// rather than hiding it behind an HTTPS failure or a panic in the fixture.
struct Fetcher;
impl PolicyFetcher for Fetcher {
	fn fetch(
		&self,
		domain: &str,
	) -> Pin<Box<dyn Future<Output = Result<String, PolicyError>> + Send + '_>> {
		assert_eq!(domain, DOMAIN);
		Box::pin(async {
			Ok("version: STSv1\nmode: enforce\nmx: mx.sender.example\nmax_age: 60\n".into())
		})
	}
}

pub fn store() -> PolicyStore {
	PolicyStore::new(Box::new(Fetcher))
}

type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsFailure>> + Send + 'a>>;

/// Resolver-boundary fixture for payloads too big for a DNS TCP frame.
/// Wire framing and RDATA parsing are covered separately by `wire_cases`.
pub struct Texts {
	pub owner: &'static str,
	pub records: Vec<String>,
}
impl DnsLookup for Texts {
	fn txt(&self, name: &str) -> Answer<'_, Vec<String>> {
		assert_eq!(name, self.owner, "evaluator queried the wrong policy owner");
		Box::pin(async { Ok(self.records.clone()) })
	}
	fn addresses(&self, _: &str) -> Answer<'_, Vec<IpAddr>> {
		panic!("TXT policy must not trigger address lookup")
	}
	fn mx(&self, _: &str) -> Answer<'_, Vec<String>> {
		panic!("TXT policy must not trigger MX lookup")
	}
}

pub fn oversized(prefix: &str) -> String {
	let mut text = prefix.to_owned();
	text.extend(std::iter::repeat_n('x', 65_536 - text.len()));
	assert_eq!(text.len(), 65_536);
	text
}
