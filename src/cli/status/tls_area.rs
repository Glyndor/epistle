//! The `tls` check: the certificate the server uses is readable, not close
//! to expiry, and names the mail hostname.

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
}

/// Check the served certificate.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
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
	let items = vec![
		expiry_item(leaf.not_after - epoch(ctx.now)),
		names_item(&config.hostname, &leaf.names),
	];
	// Reversed so the first item wins a tie: the expiry reads best first.
	let worst = items
		.iter()
		.rev()
		.max_by_key(|item| item.status)
		.expect("two items");
	let summary = match worst.status {
		Level::Ok => format!("{} {}", config.hostname, items[0].detail),
		_ => format!("{}: {}", config.hostname, worst.detail),
	};
	AreaReport::from_items(items, summary)
}

/// The certificate file the running server holds. `serve` loads `[tls]
/// cert_file`; with `[acme]` the renewal task rewrites
/// `<data_dir>/acme/cert.pem` and hot-reloads it, so that file is the live one
/// once it exists.
fn served_certificate(config: &Config) -> Option<PathBuf> {
	let tls = config.tls.as_ref()?;
	if config.acme.is_some() {
		let renewed = crate::acme::renew::cert_path(&config.data_dir);
		if renewed.exists() {
			return Some(renewed);
		}
	}
	Some(tls.cert_file.clone())
}

fn read_leaf(path: &std::path::Path) -> Result<Leaf, String> {
	let der = CertificateDer::from_pem_file(path).map_err(|error| error.to_string())?;
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

#[cfg(test)]
#[path = "tls_area_tests.rs"]
mod tests;
