//! Name handling for the lockdown: the one comparable form of a DNS name,
//! the names epistle serves, and record equality the way `--undo` needs it.

use std::collections::BTreeMap;

use crate::dns::provider::{DnsRecord, RecordKind};

/// The comparable form of a DNS name: trimmed, without the trailing root
/// dot, lowercase, and every non-ASCII label as its A-label (IDNA), so a
/// provider that lists `Bücher.Example.` and a config that says
/// `xn--bcher-kva.example` name the same thing. A label IDNA refuses is
/// kept lowercase rather than dropped, so it still compares unequal to
/// everything else instead of vanishing.
pub fn canonical_name(raw: &str) -> String {
	let trimmed = raw.trim().trim_end_matches('.');
	trimmed
		.split('.')
		.map(|label| {
			if label.is_ascii() {
				label.to_ascii_lowercase()
			} else {
				idna::domain_to_ascii(label).unwrap_or_else(|_| label.to_lowercase())
			}
		})
		.collect::<Vec<_>>()
		.join(".")
}

/// Whether canonical `name` is `domain` or a name under it.
pub fn in_domain(name: &str, domain: &str) -> bool {
	name == domain
		|| name
			.strip_suffix(domain)
			.is_some_and(|head| head.ends_with('.'))
}

/// The names epistle serves, each with the role printed in the plan. The
/// lockdown never adds a record at one of them.
#[derive(Debug, Clone, Default)]
pub struct ServedNames {
	roles: BTreeMap<String, String>,
}

impl ServedNames {
	/// The names for the hosted `domains` and the mail `hostname`: each
	/// domain, its `autoconfig`, `autodiscover` and `mta-sts` hosts, the
	/// hostname, and every MX target `existing` lists for a hosted domain.
	/// Service names (`_dmarc`, `_domainkey` and DKIM selectors,
	/// `_mta-sts`, `_smtp._tls`) are listed too; the plan also refuses any
	/// name with an underscore label.
	pub fn new(domains: &[String], hostname: &str, existing: &[DnsRecord]) -> Self {
		let mut served = ServedNames::default();
		served.insert(hostname, "the mail hostname".to_string());
		for raw in domains {
			let domain = canonical_name(raw);
			served.insert(&domain, "a mail domain epistle hosts".to_string());
			for (prefix, what) in [
				("autoconfig", "mail client autoconfiguration"),
				("autodiscover", "mail client autodiscovery"),
				("mta-sts", "the MTA-STS policy host"),
				("_dmarc", "the DMARC record"),
				("_domainkey", "the DKIM key tree"),
				("_mta-sts", "the MTA-STS record"),
				("_smtp._tls", "the TLS-RPT record"),
			] {
				served.insert(&format!("{prefix}.{domain}"), format!("{what} of {domain}"));
			}
			for record in existing {
				if record.kind == RecordKind::Mx
					&& canonical_name(&record.name) == domain
					&& let Some(target) = mx_target(&record.value).filter(|t| !t.is_empty())
				{
					served.insert(&target, format!("an MX target of {domain}"));
				}
			}
		}
		served
	}

	fn insert(&mut self, name: &str, role: String) {
		self.roles.entry(canonical_name(name)).or_insert(role);
	}

	/// The role of canonical `name`, when epistle serves it.
	pub fn role(&self, name: &str) -> Option<&str> {
		self.roles.get(name).map(String::as_str)
	}
}

/// An MX value split into its preference and its target. Providers list an
/// MX as `priority target`, as the bare target, or (the ones that cut the
/// trailing dot off the target) as a bare `priority` when the target is the
/// root, which is how a null MX `0 .` comes back from them. The root
/// target is the empty string.
fn mx_parts(value: &str) -> Option<(Option<u16>, &str)> {
	let mut parts = value.split_whitespace();
	let (first, second) = (parts.next()?, parts.next());
	if parts.next().is_some() {
		return None;
	}
	Some(match second {
		Some(target) => (Some(first.parse().ok()?), target),
		None => match first.parse::<u16>() {
			Ok(preference) => (Some(preference), ""),
			Err(_) => (None, first),
		},
	})
}

/// The target of an MX value, canonical, with the null MX target `.` as
/// the empty string.
pub(crate) fn mx_target(value: &str) -> Option<String> {
	let (_, target) = mx_parts(value)?;
	Some(if matches!(target, "." | "") {
		String::new()
	} else {
		canonical_name(target)
	})
}

/// Whether an MX value is the null MX (RFC 7505: preference 0, target `.`).
/// A bare `.` (a listing without the preference) counts too.
pub fn is_null_mx(value: &str) -> bool {
	matches!(mx_parts(value), Some((None | Some(0), "." | "")))
}

/// Whether two records are the same record: same name, same kind and the
/// same value. TXT values compare by their logical text (quoting and
/// 255-octet splitting do not count), MX by preference and target, so a
/// provider that lists `0 .` as a bare `.` still matches.
pub fn same_record(a: &DnsRecord, b: &DnsRecord) -> bool {
	if a.kind != b.kind || canonical_name(&a.name) != canonical_name(&b.name) {
		return false;
	}
	match a.kind {
		RecordKind::Txt => crate::dns::txt::same_txt_value(&a.value, &b.value),
		RecordKind::Mx => {
			(is_null_mx(&a.value) && is_null_mx(&b.value))
				|| (mx_preference(&a.value) == mx_preference(&b.value)
					&& mx_target(&a.value) == mx_target(&b.value))
		}
		_ => a.value.trim() == b.value.trim(),
	}
}

fn mx_preference(value: &str) -> Option<u16> {
	mx_parts(value)?.0
}
