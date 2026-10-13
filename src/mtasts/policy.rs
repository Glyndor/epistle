//! MTA-STS policy parsing, fetching and caching (RFC 8461).

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::spf::{DnsFailure, DnsLookup};

/// Policy mode (RFC 8461 section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
	/// `enforce`: refuse delivery that does not match the policy.
	Enforce,
	/// `testing`: report violations but deliver as if no policy applied.
	Testing,
	/// `none`: explicitly disable MTA-STS for this domain.
	None,
}

/// A parsed MTA-STS policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
	/// Enforcement mode (`enforce`, `testing`, or `none`).
	pub mode: Mode,
	/// Allowed MX patterns: exact hostnames or `*.domain` wildcards.
	pub mx: Vec<String>,
	/// How long (seconds) a receiver may cache and apply this policy
	/// before re-fetching it (RFC 8461 §3.2 `max_age`).
	pub max_age: u64,
}

impl Policy {
	/// Whether an MX hostname is permitted by this policy.
	pub fn permits_mx(&self, host: &str) -> bool {
		let host = host.to_ascii_lowercase();
		self.mx.iter().any(|pattern| {
			if let Some(suffix) = pattern.strip_prefix("*.") {
				// Wildcard matches exactly one leftmost label.
				host.strip_suffix(suffix)
					.and_then(|head| head.strip_suffix('.'))
					.is_some_and(|label| !label.is_empty() && !label.contains('.'))
			} else {
				host == *pattern
			}
		})
	}
}

/// Why a policy could not be obtained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
	/// The domain publishes no MTA-STS record.
	NotFound,
	/// Discovery or fetch failed transiently.
	Temporary(String),
	/// The policy file is malformed.
	Malformed(String),
}

/// Parse `mta-sts.txt` (RFC 8461 section 3.2).
pub fn parse(text: &str) -> Result<Policy, PolicyError> {
	let mut version = None;
	let mut mode = None;
	let mut max_age = None;
	let mut mx = Vec::new();

	for line in text.lines() {
		let line = line.trim_end_matches('\r').trim();
		if line.is_empty() {
			continue;
		}
		let Some((key, value)) = line.split_once(':') else {
			return Err(PolicyError::Malformed(format!("bad line \"{line}\"")));
		};
		let value = value.trim();
		match key.trim() {
			"version" => version = Some(value.to_string()),
			"mode" => {
				mode = Some(match value {
					"enforce" => Mode::Enforce,
					"testing" => Mode::Testing,
					"none" => Mode::None,
					other => {
						return Err(PolicyError::Malformed(format!("unknown mode {other}")));
					}
				});
			}
			"max_age" => {
				max_age = Some(
					value
						.parse()
						.map_err(|_| PolicyError::Malformed("bad max_age".into()))?,
				);
			}
			"mx" => mx.push(value.to_ascii_lowercase()),
			// Unknown keys are ignored for forward compatibility.
			_ => {}
		}
	}

	if version.as_deref() != Some("STSv1") {
		return Err(PolicyError::Malformed("version must be STSv1".into()));
	}
	let mode = mode.ok_or_else(|| PolicyError::Malformed("missing mode".into()))?;
	if mode != Mode::None && mx.is_empty() {
		return Err(PolicyError::Malformed("missing mx entries".into()));
	}
	Ok(Policy {
		mode,
		mx,
		max_age: max_age.ok_or_else(|| PolicyError::Malformed("missing max_age".into()))?,
	})
}

type FetchResult = Result<String, PolicyError>;
type FetchFuture<'a> = Pin<Box<dyn Future<Output = FetchResult> + Send + 'a>>;

/// Fetches the HTTPS policy document. Abstracted for offline tests.
pub trait PolicyFetcher: Send + Sync {
	/// GET `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
	fn fetch(&self, domain: &str) -> FetchFuture<'_>;
}

/// Real fetcher over reqwest with WebPKI verification.
pub struct SystemFetcher {
	client: reqwest::Client,
}

impl SystemFetcher {
	/// Build with conservative timeouts and no redirects (RFC 8461 §3.3).
	pub fn new() -> Result<Self, PolicyError> {
		let client = reqwest::Client::builder()
			.timeout(Duration::from_secs(30))
			.redirect(reqwest::redirect::Policy::none())
			.build()
			.map_err(|error| PolicyError::Temporary(error.to_string()))?;
		Ok(SystemFetcher { client })
	}
}

impl PolicyFetcher for SystemFetcher {
	fn fetch(&self, domain: &str) -> FetchFuture<'_> {
		let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
		Box::pin(async move {
			let mut response = self
				.client
				.get(&url)
				.send()
				.await
				.map_err(|error| PolicyError::Temporary(error.to_string()))?;
			if !response.status().is_success() {
				return Err(PolicyError::Temporary(format!(
					"policy fetch returned {}",
					response.status()
				)));
			}
			// Policies are tiny; read incrementally with a hard cap so a hostile
			// recipient domain cannot make us buffer a huge body before the
			// size check (the old `.text()` materialised it all first).
			const MAX_BODY: usize = 64 * 1024;
			let mut body = Vec::new();
			while let Some(chunk) = response
				.chunk()
				.await
				.map_err(|error| PolicyError::Temporary(error.to_string()))?
			{
				if body.len() + chunk.len() > MAX_BODY {
					return Err(PolicyError::Malformed("oversized policy".into()));
				}
				body.extend_from_slice(&chunk);
			}
			String::from_utf8(body).map_err(|error| PolicyError::Malformed(error.to_string()))
		})
	}
}

/// How long a policy is used before it is fetched again, at most. The
/// policy itself stays valid as a fallback for its whole `max_age`.
const MAX_CACHE: Duration = Duration::from_secs(24 * 3600);

/// How long "no policy" is remembered before discovery runs again.
const NO_POLICY_CACHE: Duration = Duration::from_secs(600);

/// One cached discovery result.
#[derive(Clone)]
struct Cached {
	/// The policy, or `None` when the domain publishes none.
	policy: Option<Policy>,
	/// Until then the entry is used as is.
	refresh: Instant,
	/// Until then a policy still applies when a refresh fails (RFC 8461
	/// section 3.3 and 5.1).
	expires: Instant,
}

/// Discovery + cache: TXT presence check, HTTPS fetch, expiry by max_age.
pub struct PolicyStore {
	fetcher: Box<dyn PolicyFetcher>,
	cache: Mutex<HashMap<String, Cached>>,
}

impl PolicyStore {
	/// Create a store over a fetcher.
	pub fn new(fetcher: Box<dyn PolicyFetcher>) -> Self {
		PolicyStore {
			fetcher,
			cache: Mutex::new(HashMap::new()),
		}
	}

	/// The policy for a recipient domain, or `None` when the domain does
	/// not publish MTA-STS.
	///
	/// A cached policy that has not reached its `max_age` keeps applying
	/// when a refresh fails or the TXT record is gone (RFC 8461 sections
	/// 3.3 and 5.1), so blocking the policy host cannot strip an enforce
	/// policy early. Without one, a failed lookup or fetch is returned as
	/// an error, and RFC 8461 section 3.3 has the caller deliver as
	/// though the domain published no policy.
	pub async fn policy(
		&self,
		dns: &dyn DnsLookup,
		domain: &str,
	) -> Result<Option<Policy>, PolicyError> {
		let domain = domain.to_ascii_lowercase();
		let now = Instant::now();
		let cached = self
			.cache
			.lock()
			.expect("mta-sts cache mutex")
			.get(&domain)
			.cloned();
		if let Some(entry) = &cached
			&& now < entry.refresh
		{
			return Ok(entry.policy.clone());
		}
		let fallback = cached
			.filter(|entry| now < entry.expires)
			.and_then(|entry| entry.policy);

		match self.discover(dns, &domain).await {
			Ok(Some(policy)) => {
				let max_age = Duration::from_secs(policy.max_age);
				self.remember(
					&domain,
					Some(policy.clone()),
					max_age.min(MAX_CACHE),
					max_age,
				);
				Ok(Some(policy))
			}
			Ok(None) => match fallback {
				Some(policy) => Ok(Some(policy)),
				None => {
					self.remember(&domain, None, NO_POLICY_CACHE, NO_POLICY_CACHE);
					Ok(None)
				}
			},
			Err(error) => match fallback {
				Some(policy) => {
					tracing::warn!(%domain, ?error, "MTA-STS refresh failed; keeping the cached policy");
					Ok(Some(policy))
				}
				None => Err(error),
			},
		}
	}

	/// Discovery: the `_mta-sts` TXT record (section 3.1), then the policy.
	async fn discover(
		&self,
		dns: &dyn DnsLookup,
		domain: &str,
	) -> Result<Option<Policy>, PolicyError> {
		let records = match dns.txt(&format!("_mta-sts.{domain}")).await {
			Ok(records) => records,
			Err(DnsFailure::Temporary) => {
				return Err(PolicyError::Temporary("TXT lookup failed".into()));
			}
		};
		if !records.iter().any(|record| record.starts_with("v=STSv1")) {
			return Ok(None);
		}
		let body = self.fetcher.fetch(domain).await?;
		parse(&body).map(Some)
	}

	fn remember(&self, domain: &str, policy: Option<Policy>, refresh: Duration, expires: Duration) {
		let now = Instant::now();
		self.cache.lock().expect("mta-sts cache mutex").insert(
			domain.to_string(),
			Cached {
				policy,
				refresh: now + refresh,
				expires: now + expires,
			},
		);
	}

	/// Make the cached entry for `domain` due for refresh now, as if its
	/// refresh time had passed.
	#[cfg(test)]
	pub(crate) fn due_for_refresh(&self, domain: &str) {
		if let Some(entry) = self
			.cache
			.lock()
			.expect("mta-sts cache mutex")
			.get_mut(domain)
		{
			entry.refresh = Instant::now();
		}
	}
}

#[cfg(test)]
#[path = "policy_tests_cache.rs"]
mod tests_cache;

#[cfg(test)]
#[path = "policy_tests_basic.rs"]
mod tests_basic;
