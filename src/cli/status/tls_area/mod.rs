//! The `tls` check: the certificate the server uses is readable, not close
//! to expiry, renewed by something when it is, names the mail hostname, and
//! matches the DANE TLSA record when one is published.

use std::path::PathBuf;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;

use super::Ctx;
use super::clock::epoch;
use super::report::{AreaReport, Item, Level};
use crate::config::Config;

const DAY: i64 = 86_400;

/// Fewer days than this left: warn.
const WARN_DAYS: i64 = 21;

/// Fewer days than this left: fail.
const FAIL_DAYS: i64 = 7;

/// What the check needs from the leaf certificate.
struct Leaf {
	not_after: i64,
	names: Vec<String>,
	/// The whole chain (DER), leaf first, for the TLSA comparison.
	chain: Vec<Vec<u8>>,
}

/// Fewer days than this left on a certificate nothing renews: warn.
const UNRENEWED_WARN_DAYS: i64 = 14;

/// Check the served certificate with the system resolver.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	match crate::spf::SystemDns::from_system() {
		Ok(resolver) => evaluate(ctx, &super::dns_area::TimeoutDns(resolver)).await,
		Err(_) => evaluate(ctx, &NoDns).await,
	}
}

/// Check the served certificate, looking its TLSA record up through `dns`.
pub(super) async fn evaluate(ctx: &Ctx, dns: &dyn crate::spf::DnsLookup) -> AreaReport {
	let config = match ctx.loaded() {
		Ok(config) => config,
		Err(report) => return report,
	};
	let Some(path) = served_certificate(config) else {
		return AreaReport::single(Level::Warn, "no [tls] certificate is configured");
	};
	let leaf = match read_leaf(&path) {
		Ok(leaf) => leaf,
		Err(error) => {
			return AreaReport::fail(format!(
				"cannot read the certificate {}: {error}",
				path.display()
			));
		}
	};
	let remaining = leaf.not_after - epoch(ctx.now);
	let mut items = vec![
		expiry_item(remaining),
		names_item(&config.hostname, &leaf.names),
		renewal_item(config.acme.is_some(), remaining),
	];
	items.extend(super::tls_tlsa::tlsa_item(&config.hostname, &leaf.chain, dns).await);
	items.extend(super::tls_tlsa::pending_item(
		&config.data_dir,
		&config.hostname,
		epoch(ctx.now),
	));
	// Reversed so the first item wins a tie: the expiry reads best first.
	let worst = items
		.iter()
		.rev()
		.max_by_key(|item| item.status)
		.expect("three items");
	let summary = match worst.status {
		Level::Ok => format!("{} {}", config.hostname, items[0].detail),
		_ => format!("{}: {}", config.hostname, worst.detail),
	};
	AreaReport::from_items(items, summary)
}

/// The certificate file the running server presents, resolved the same way
/// `serve` and `epistle probe` resolve it ([`crate::tls::served_tls`]).
fn served_certificate(config: &Config) -> Option<PathBuf> {
	crate::tls::served_tls(config).map(|served| served.tls.cert_file)
}

fn read_leaf(path: &std::path::Path) -> Result<Leaf, String> {
	let chain: Vec<Vec<u8>> = CertificateDer::pem_file_iter(path)
		.map_err(|error| error.to_string())?
		.map(|cert| cert.map(|cert| cert.as_ref().to_vec()))
		.collect::<Result<_, _>>()
		.map_err(|error| error.to_string())?;
	let der = chain.first().ok_or("no certificate in the file")?;
	let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
		.map_err(|error| error.to_string())?;
	let names = cert
		.subject_alternative_name()
		.ok()
		.flatten()
		.map(|san| {
			san.value
				.general_names
				.iter()
				.filter_map(|name| match name {
					GeneralName::DNSName(dns) => Some((*dns).to_string()),
					_ => None,
				})
				.collect()
		})
		.unwrap_or_default();
	Ok(Leaf {
		not_after: cert.validity().not_after.timestamp(),
		names,
		chain: chain.clone(),
	})
}

fn plural(count: i64) -> String {
	format!("{count} day{}", if count == 1 { "" } else { "s" })
}

/// `remaining` is seconds until `notAfter`.
fn expiry_item(remaining: i64) -> Item {
	if remaining <= 0 {
		let days = -remaining / DAY;
		let detail = if days == 0 {
			"expired less than a day ago".to_string()
		} else {
			format!("expired {} ago", plural(days))
		};
		return Item::new("expiry", Level::Fail, detail);
	}
	let days = remaining / DAY;
	let level = if remaining < FAIL_DAYS * DAY {
		Level::Fail
	} else if remaining < WARN_DAYS * DAY {
		Level::Warn
	} else {
		Level::Ok
	};
	Item::new("expiry", level, format!("expires in {}", plural(days)))
}

/// Whether something renews the certificate: ACME does; without it the
/// operator replaces the files, and a certificate close to expiry is worth a
/// warning of its own.
fn renewal_item(acme: bool, remaining: i64) -> Item {
	if acme {
		return Item::new("renewal", Level::Ok, "renewed by ACME");
	}
	if remaining < UNRENEWED_WARN_DAYS * DAY {
		return Item::new(
			"renewal",
			Level::Warn,
			"expires soon and nothing renews it (no [acme]): replace cert_file and key_file; the server picks the new pair up within a minute",
		);
	}
	Item::new(
		"renewal",
		Level::Ok,
		"not renewed automatically (no [acme]); replace the files before it expires",
	)
}

fn names_item(hostname: &str, names: &[String]) -> Item {
	if names.iter().any(|name| covers(name, hostname)) {
		Item::new("names", Level::Ok, format!("{hostname} is covered"))
	} else {
		Item::new(
			"names",
			Level::Fail,
			format!("{hostname} is not covered by: {}", names.join(", ")),
		)
	}
}

/// Whether the certificate name `pattern` covers `host` (RFC 6125: a wildcard
/// stands for exactly one leftmost label).
fn covers(pattern: &str, host: &str) -> bool {
	if pattern.eq_ignore_ascii_case(host) {
		return true;
	}
	match (pattern.strip_prefix("*."), host.split_once('.')) {
		(Some(suffix), Some((label, rest))) => {
			!label.is_empty() && suffix.eq_ignore_ascii_case(rest)
		}
		_ => false,
	}
}

/// A resolver for when the system one cannot start: no TLSA is found, so
/// the comparison is skipped rather than failed.
struct NoDns;

type Lookup<'a, T> =
	std::pin::Pin<Box<dyn Future<Output = Result<T, crate::spf::DnsFailure>> + Send + 'a>>;

impl crate::spf::DnsLookup for NoDns {
	fn txt(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn addresses(&self, _name: &str) -> Lookup<'_, Vec<std::net::IpAddr>> {
		Box::pin(async { Ok(Vec::new()) })
	}
	fn mx(&self, _name: &str) -> Lookup<'_, Vec<String>> {
		Box::pin(async { Ok(Vec::new()) })
	}
}

#[cfg(test)]
mod tests;
