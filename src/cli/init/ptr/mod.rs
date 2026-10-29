//! The reverse-DNS block `init` ends with: for every public address, the
//! PTR it has and whether that name is forward-confirmed (it names the
//! configured hostname and the hostname resolves back to the address).
//! Receivers check exactly that before trusting mail, and the PTR is the
//! one record the operator cannot publish in their own zone: it belongs
//! to whoever owns the address, so a missing or wrong one says what to
//! ask the hosting provider for.
//!
//! The lookups are the ones `verify-dns` and `status` use
//! ([`crate::dns::check_host::classify_ptr`] over a [`DnsLookup`]), and
//! the block is informational: nothing in it changes the exit code.

use std::future::Future;
use std::io::Write;
use std::net::IpAddr;

use crate::dns::check_host::{PtrOutcome, classify_ptr};
use crate::spf::{DnsLookup, SystemDns};

/// The production resolver: the system's, with every query bounded by
/// the same timeout `status` applies, so an unreachable resolver delays
/// the end of `init` by seconds, not minutes.
pub(super) fn system_resolver() -> Option<Box<dyn DnsLookup>> {
	let dns = SystemDns::from_system().ok()?;
	Some(Box::new(crate::cli::status::TimeoutDns(dns)))
}

/// Write the block for `addresses` to `out`; nothing at all when there is
/// no address. Without a resolver every address reads "lookup failed".
pub(super) fn render(
	hostname: &str,
	addresses: &[IpAddr],
	dns: Option<&dyn DnsLookup>,
	out: &mut dyn Write,
) {
	if addresses.is_empty() {
		return;
	}
	let found = dns
		.and_then(|dns| block_on(outcomes(hostname, addresses, dns)))
		.unwrap_or_else(|| vec![PtrOutcome::LookupError; addresses.len()]);
	let _ = writeln!(out, "reverse DNS (PTR), expected to name {hostname}:");
	for (address, outcome) in addresses.iter().zip(&found) {
		let _ = writeln!(out, "  {}", line(hostname, *address, outcome));
	}
}

/// Classify every address with one resolver, in order.
async fn outcomes(hostname: &str, addresses: &[IpAddr], dns: &dyn DnsLookup) -> Vec<PtrOutcome> {
	let mut found = Vec::with_capacity(addresses.len());
	for address in addresses {
		found.push(classify_ptr(hostname, *address, dns).await);
	}
	found
}

/// Run `future` to completion from synchronous code. `init` normally runs
/// outside any runtime and gets a small current-thread one; inside a
/// multi-thread runtime the running one is borrowed instead of nesting a
/// second (which panics). A current-thread runtime cannot be blocked from
/// within, so there the answer is `None` and the block reports the
/// lookups as failed rather than panicking.
fn block_on<F: Future>(future: F) -> Option<F::Output> {
	use tokio::runtime::{Builder, Handle, RuntimeFlavor};
	match Handle::try_current() {
		Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
			Some(tokio::task::block_in_place(|| handle.block_on(future)))
		}
		Ok(_) => None,
		Err(_) => {
			let runtime = Builder::new_current_thread().enable_all().build().ok()?;
			Some(runtime.block_on(future))
		}
	}
}

/// One line of the block, after the two-space indent.
fn line(hostname: &str, address: IpAddr, outcome: &PtrOutcome) -> String {
	match outcome {
		PtrOutcome::Ok => format!("{address}: ok, points at {hostname}, which resolves back to it"),
		PtrOutcome::None => format!(
			"{address}: missing; ask your hosting provider to set the PTR of {address} to {hostname}"
		),
		PtrOutcome::PointsElsewhere { found, .. } => format!(
			"{address}: points at {found}; ask your hosting provider to change the PTR of {address} to {hostname}"
		),
		PtrOutcome::DoesNotResolveBack => {
			let kind = if address.is_ipv4() { "A" } else { "AAAA" };
			format!(
				"{address}: points at {hostname}, but {hostname} does not resolve to {address}; publish the {kind} record for {hostname} in its zone"
			)
		}
		PtrOutcome::LookupError => {
			format!("{address}: lookup failed; check again later with `epistle verify-dns`")
		}
	}
}

#[cfg(test)]
mod tests;
