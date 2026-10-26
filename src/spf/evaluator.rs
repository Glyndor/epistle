//! The `check_host()` function (RFC 7208 section 4).

use std::net::IpAddr;

use super::dns::{DnsFailure, DnsLookup};
use super::record::{Mechanism, Qualifier, Record};

/// Maximum DNS-querying terms per evaluation (RFC 7208 section 4.6.4).
pub(crate) const MAX_DNS_MECHANISMS: u32 = 10;

/// Maximum void DNS lookups per evaluation (RFC 7208 section 4.6.4). A
/// void lookup is one that returns either NXDOMAIN or a response with
/// no relevant records. Two voids are tolerated; a third turns the
/// evaluation into `permerror`.
pub(crate) const MAX_VOID_LOOKUPS: u32 = 2;

/// SPF evaluation result (RFC 7208 section 2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpfOutcome {
	/// No SPF record was found for the domain (or multiple were found and
	/// per §4.5 none applies).
	None,
	/// `?all` or an explicit `neutral` mechanism matched: the domain makes
	/// no assertion.
	Neutral,
	/// `+all` or a mechanism matching `ip` matched: the sender is authorized
	/// for the domain.
	Pass,
	/// `-all` matched or a mechanism denied `ip`: the sender is NOT
	/// authorized.
	Fail,
	/// `~all` matched: the sender is probably not authorized. Receiving
	/// servers typically accept but flag the message.
	SoftFail,
	/// A transient error (DNS timeout, recursion limit) prevented evaluation.
	TempError,
	/// A permanent error (malformed record, unsupported mechanism) prevented
	/// evaluation.
	PermError,
}

impl SpfOutcome {
	/// Lowercase keyword for `Received-SPF`.
	pub fn as_str(self) -> &'static str {
		match self {
			SpfOutcome::None => "none",
			SpfOutcome::Neutral => "neutral",
			SpfOutcome::Pass => "pass",
			SpfOutcome::Fail => "fail",
			SpfOutcome::SoftFail => "softfail",
			SpfOutcome::TempError => "temperror",
			SpfOutcome::PermError => "permerror",
		}
	}
}

/// Evaluate SPF for `ip` sending mail from `domain`.
/// `sender` is the RFC 5321 MAIL FROM address (empty for null reverse-path).
/// `helo` is the EHLO/HELO domain announced by the client.
pub async fn check_host(
	dns: &dyn DnsLookup,
	ip: IpAddr,
	domain: &str,
	sender: &str,
	helo: &str,
) -> SpfOutcome {
	let mut budget = Budget::default();
	let ctx = CheckContext {
		dns,
		ip,
		sender,
		helo,
	};
	check_host_inner(&ctx, domain, &mut budget).await
}

/// What every recursive step of [`check_host_inner`] needs about the
/// message being evaluated. The four fields do not change as evaluation
/// descends through `include:` or `redirect=` (RFC 7208 §4.6.3 keeps the
/// same caller identity, only the target domain moves), so holding them
/// in one reference keeps the recursive call below clippy's
/// `too_many_arguments` threshold.
struct CheckContext<'a> {
	dns: &'a dyn DnsLookup,
	ip: IpAddr,
	sender: &'a str,
	helo: &'a str,
}

/// Mutable SPF evaluation state threaded through every recursive step.
/// `remaining` is the RFC 7208 §4.6.4 cap on DNS-querying terms (max 10);
/// `voids` is the cap on lookups that returned no records (max 2);
/// `depth` is the include/redirect nesting depth (`MAX_DEPTH`).
struct Budget {
	remaining: u32,
	voids: u32,
	depth: u32,
}

impl Default for Budget {
	fn default() -> Self {
		Self {
			remaining: MAX_DNS_MECHANISMS,
			voids: 0,
			depth: 0,
		}
	}
}

/// Recursion depth guard: includes/redirects each consume DNS budget, but a
/// cycle of zero-budget terms must still terminate.
const MAX_DEPTH: u32 = 10;

async fn check_host_inner(ctx: &CheckContext<'_>, domain: &str, budget: &mut Budget) -> SpfOutcome {
	if budget.depth >= MAX_DEPTH {
		return SpfOutcome::PermError;
	}

	let record = match fetch_record(ctx.dns, domain, &mut budget.voids).await {
		Ok(Some(record)) => record,
		Ok(None) => return SpfOutcome::None,
		Err(outcome) => return outcome,
	};
	let dns = ctx.dns;
	let ip = ctx.ip;
	let sender = ctx.sender;
	let helo = ctx.helo;

	for (qualifier, mechanism) in &record.directives {
		let matched = match mechanism {
			Mechanism::All => true,
			Mechanism::Ip4 { network, prefix } => match ip {
				IpAddr::V4(v4) => v4_in_network(v4, *network, *prefix),
				IpAddr::V6(_) => false,
			},
			Mechanism::Ip6 { network, prefix } => match ip {
				IpAddr::V6(v6) => v6_in_network(v6, *network, *prefix),
				IpAddr::V4(_) => false,
			},
			Mechanism::A {
				domain: target,
				prefix4,
				prefix6,
			} => {
				if !consume(&mut budget.remaining) {
					return SpfOutcome::PermError;
				}
				let spec = target.as_deref().unwrap_or(domain);
				let name = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(n) => n,
					Err(e) => return e,
				};
				match dns.addresses(&name).await {
					Ok(addresses) => {
						if addresses.is_empty()
							&& let Some(permerror) = count_void(&mut budget.voids)
						{
							return permerror;
						}
						addresses
							.iter()
							.any(|address| address_matches(ip, *address, *prefix4, *prefix6))
					}
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				}
			}
			Mechanism::Mx {
				domain: target,
				prefix4,
				prefix6,
			} => {
				if !consume(&mut budget.remaining) {
					return SpfOutcome::PermError;
				}
				let spec = target.as_deref().unwrap_or(domain);
				let name = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(n) => n,
					Err(e) => return e,
				};
				let exchangers = match dns.mx(&name).await {
					Ok(exchangers) => {
						if exchangers.is_empty()
							&& let Some(permerror) = count_void(&mut budget.voids)
						{
							return permerror;
						}
						exchangers
					}
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				};
				let mut matched = false;
				for exchanger in exchangers.iter().take(10) {
					match dns.addresses(exchanger).await {
						Ok(addresses) => {
							if addresses.is_empty()
								&& let Some(permerror) = count_void(&mut budget.voids)
							{
								return permerror;
							}
							if addresses
								.iter()
								.any(|address| address_matches(ip, *address, *prefix4, *prefix6))
							{
								matched = true;
								break;
							}
						}
						Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
					}
				}
				matched
			}
			Mechanism::Include { domain: spec } => {
				if !consume(&mut budget.remaining) {
					return SpfOutcome::PermError;
				}
				let included = match expand_macro(spec, ip, domain, sender, helo) {
					Ok(d) => d,
					Err(e) => return e,
				};
				let mut nested = Budget {
					remaining: budget.remaining,
					voids: budget.voids,
					depth: budget.depth + 1,
				};
				let include_matched =
					match Box::pin(check_host_inner(ctx, &included, &mut nested)).await {
						SpfOutcome::Pass => true,
						SpfOutcome::Fail | SpfOutcome::SoftFail | SpfOutcome::Neutral => false,
						// include of a domain without a record is a permerror
						// (RFC 7208 section 5.2).
						SpfOutcome::None => return SpfOutcome::PermError,
						outcome @ (SpfOutcome::TempError | SpfOutcome::PermError) => {
							return outcome;
						}
					};
				// Propagate the child's consumed counts back into the
				// caller's budget. The §4.6.4 limits are shared across
				// the whole evaluation, not per-record, so a void that
				// happened inside the include must count against the
				// caller's counter (and vice versa). Same for the
				// remaining DNS-term cap.
				budget.remaining = nested.remaining;
				budget.voids = nested.voids;
				include_matched
			}
			Mechanism::Exists { domain } => {
				// RFC 7208 §5.7: pass if the domain has any A/AAAA record.
				if !consume(&mut budget.remaining) {
					return SpfOutcome::PermError;
				}
				match dns.addresses(domain).await {
					Ok(addresses) => {
						if addresses.is_empty()
							&& let Some(permerror) = count_void(&mut budget.voids)
						{
							return permerror;
						}
						!addresses.is_empty()
					}
					Err(DnsFailure::Temporary) => return SpfOutcome::TempError,
				}
			}
			Mechanism::Ptr { .. } => {
				// RFC 7208 §5.5: deprecated. Evaluating ptr: requires reverse
				// DNS lookups (not in DnsLookup today) and is strongly
				// discouraged by the RFC. Treated as non-matching to avoid
				// PermError on records that contain it. Consumes DNS budget
				// to discourage abuse of multiple ptr: terms.
				if !consume(&mut budget.remaining) {
					return SpfOutcome::PermError;
				}
				false
			}
		};

		if matched {
			return match qualifier {
				Qualifier::Pass => SpfOutcome::Pass,
				Qualifier::Fail => SpfOutcome::Fail,
				Qualifier::SoftFail => SpfOutcome::SoftFail,
				Qualifier::Neutral => SpfOutcome::Neutral,
			};
		}
	}

	if let Some(spec) = &record.redirect {
		if !consume(&mut budget.remaining) {
			return SpfOutcome::PermError;
		}
		let target = match expand_macro(spec, ip, domain, sender, helo) {
			Ok(d) => d,
			Err(e) => return e,
		};
		let mut nested = Budget {
			remaining: budget.remaining,
			voids: budget.voids,
			depth: budget.depth + 1,
		};
		let outcome = Box::pin(check_host_inner(ctx, &target, &mut nested)).await;
		// Propagate the child's consumed counts back into the caller's
		// budget (same §4.6.4 contract as `include:` above).
		budget.remaining = nested.remaining;
		budget.voids = nested.voids;
		// A redirect target without a record is a permerror (section 6.1).
		return if outcome == SpfOutcome::None {
			SpfOutcome::PermError
		} else {
			outcome
		};
	}

	// No mechanism matched and no redirect: default neutral (section 4.7).
	SpfOutcome::Neutral
}

fn consume(budget: &mut u32) -> bool {
	if *budget == 0 {
		return false;
	}
	*budget -= 1;
	true
}

async fn fetch_record(
	dns: &dyn DnsLookup,
	domain: &str,
	void_lookups: &mut u32,
) -> Result<Option<Record>, SpfOutcome> {
	let texts = match dns.txt(domain).await {
		Ok(texts) => {
			// An empty TXT response is a void lookup for the purpose
			// of the §4.6.4 budget: the record fetch is the first
			// lookup the evaluator performs and counts.
			if texts.is_empty()
				&& let Some(permerror) = count_void(void_lookups)
			{
				return Err(permerror);
			}
			texts
		}
		Err(DnsFailure::Temporary) => return Err(SpfOutcome::TempError),
	};
	let mut records = texts
		.iter()
		.filter(|text| *text == "v=spf1" || text.starts_with("v=spf1 "));
	let Some(text) = records.next() else {
		return Ok(None);
	};
	// Multiple v=spf1 records are a permerror (section 4.5).
	if records.next().is_some() {
		return Err(SpfOutcome::PermError);
	}
	super::record::parse(text)
		.map(Some)
		.map_err(|_| SpfOutcome::PermError)
}

/// Add a void lookup to the running count and return
/// [`SpfOutcome::PermError`] once the §4.6.4 budget runs out; `None`
/// while the count is still within tolerance. The caller short-circuits
/// on `Some(PermError)` so the permerror decision bubbles up to
/// `check_host_inner` and back to the public entry point.
fn count_void(void_lookups: &mut u32) -> Option<SpfOutcome> {
	*void_lookups += 1;
	if *void_lookups > MAX_VOID_LOOKUPS {
		Some(SpfOutcome::PermError)
	} else {
		None
	}
}

fn address_matches(ip: IpAddr, candidate: IpAddr, prefix4: u8, prefix6: u8) -> bool {
	match (ip, candidate) {
		(IpAddr::V4(ip), IpAddr::V4(candidate)) => v4_in_network(ip, candidate, prefix4),
		(IpAddr::V6(ip), IpAddr::V6(candidate)) => v6_in_network(ip, candidate, prefix6),
		_ => false,
	}
}

fn v4_in_network(ip: std::net::Ipv4Addr, network: std::net::Ipv4Addr, prefix: u8) -> bool {
	let mask = if prefix == 0 {
		0
	} else {
		u32::MAX << (32 - u32::from(prefix))
	};
	(u32::from(ip) & mask) == (u32::from(network) & mask)
}

fn v6_in_network(ip: std::net::Ipv6Addr, network: std::net::Ipv6Addr, prefix: u8) -> bool {
	let mask = if prefix == 0 {
		0
	} else {
		u128::MAX << (128 - u128::from(prefix))
	};
	(u128::from(ip) & mask) == (u128::from(network) & mask)
}

/// Expand macro-strings in a domain-spec (RFC 7208 §7).
/// Returns `PermError` on malformed macro syntax or unknown macro letter.
/// Fast-paths if `spec` contains no `%`.
pub(crate) fn expand_macro(
	spec: &str,
	ip: IpAddr,
	current_domain: &str,
	sender: &str,
	helo: &str,
) -> Result<String, SpfOutcome> {
	if !spec.contains('%') {
		return Ok(spec.to_string());
	}
	let mut result = String::with_capacity(spec.len() * 2);
	let mut rest = spec;
	while let Some(offset) = rest.find('%') {
		result.push_str(&rest[..offset]);
		rest = &rest[offset + 1..];
		let ch = rest.chars().next().ok_or(SpfOutcome::PermError)?;
		match ch {
			'%' => {
				result.push('%');
				rest = &rest[1..];
			}
			'_' => {
				result.push(' ');
				rest = &rest[1..];
			}
			'-' => {
				result.push_str("%20");
				rest = &rest[1..];
			}
			'{' => {
				let close = rest.find('}').ok_or(SpfOutcome::PermError)?;
				let inner = &rest[1..close];
				rest = &rest[close + 1..];
				result.push_str(&expand_macro_inner(
					inner,
					ip,
					current_domain,
					sender,
					helo,
				)?);
			}
			_ => return Err(SpfOutcome::PermError),
		}
	}
	result.push_str(rest);
	Ok(result)
}

/// Expand the content of `%{...}` (letter + optional transformers).
fn expand_macro_inner(
	inner: &str,
	ip: IpAddr,
	current_domain: &str,
	sender: &str,
	helo: &str,
) -> Result<String, SpfOutcome> {
	let mut chars = inner.chars();
	let letter = chars
		.next()
		.ok_or(SpfOutcome::PermError)?
		.to_ascii_lowercase();
	let (count, reverse, delimiters) = parse_macro_transformers(chars.as_str())?;

	let raw = match letter {
		's' => sender.to_string(),
		'l' => sender
			.split_once('@')
			.map_or(sender, |(local, _)| local)
			.to_string(),
		'o' => sender
			.rsplit_once('@')
			.map_or(sender, |(_, domain)| domain)
			.to_string(),
		'd' => current_domain.to_string(),
		'i' => ip_to_macro_str(ip),
		'v' => match ip {
			IpAddr::V4(_) => "in-addr".to_string(),
			IpAddr::V6(_) => "ip6".to_string(),
		},
		'h' => helo.to_string(),
		_ => return Err(SpfOutcome::PermError),
	};

	let mut parts: Vec<&str> = raw.split(|c: char| delimiters.contains(&c)).collect();
	if reverse {
		parts.reverse();
	}
	if let Some(n) = count {
		let skip = parts.len().saturating_sub(n);
		parts.drain(..skip);
	}
	Ok(parts.join("."))
}

/// Parse `[digit][r][delimiter...]` macro transformers (RFC 7208 §7.1).
fn parse_macro_transformers(s: &str) -> Result<(Option<usize>, bool, Vec<char>), SpfOutcome> {
	let count_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
	let count = if count_end == 0 {
		None
	} else {
		Some(
			s[..count_end]
				.parse::<usize>()
				.map_err(|_| SpfOutcome::PermError)?,
		)
	};
	let rest = &s[count_end..];

	let reverse = matches!(rest.chars().next(), Some('r') | Some('R'));
	let delimiters_str = if reverse { &rest[1..] } else { rest };

	let delimiters = if delimiters_str.is_empty() {
		vec!['.']
	} else {
		let chars: Vec<char> = delimiters_str.chars().collect();
		for &d in &chars {
			if !".+-,/_=".contains(d) {
				return Err(SpfOutcome::PermError);
			}
		}
		chars
	};

	Ok((count, reverse, delimiters))
}

/// Format `ip` for use in macro expansion (RFC 7208 §7.3).
/// IPv4: dotted-decimal. IPv6: 32 lowercase hex nibbles separated by `.`.
fn ip_to_macro_str(ip: IpAddr) -> String {
	match ip {
		IpAddr::V4(v4) => v4.to_string(),
		IpAddr::V6(v6) => {
			let nibbles: Vec<String> = v6
				.octets()
				.iter()
				.flat_map(|&b| [format!("{:x}", (b >> 4) & 0xf), format!("{:x}", b & 0xf)])
				.collect();
			nibbles.join(".")
		}
	}
}

#[cfg(test)]
#[path = "evaluator_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "evaluator_macro_tests.rs"]
mod macro_tests;

#[cfg(test)]
#[path = "evaluator_void_tests.rs"]
mod void_tests;

#[cfg(test)]
#[path = "evaluator_budget_propagation_tests.rs"]
mod budget_propagation_tests;
