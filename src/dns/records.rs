//! Compute the DNS records epistle expects a deployment to publish: SPF, DKIM,
//! DMARC, MTA-STS, MX and (when a certificate is available) a DANE TLSA record.
//! These pair with [`super::check_domain`] (which verifies them) and can be
//! handed to a [`super::provider::DnsProvider`] to publish, or printed for
//! manual entry.

use std::net::{Ipv4Addr, Ipv6Addr};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};
pub use super::records_services::{Services, SrvService};

/// Map an ACME directory URL to the CA we expect to issue certs for this
/// domain. Returns `None` for unknown directories — emitting a wrong CAA
/// would block legitimate renewal, so we only emit when we recognise the
/// CA. Add a directory here when you bring up a new one.
pub fn caa_ca_for_directory(directory_url: &str) -> Option<&'static str> {
	let normalized = directory_url.trim_end_matches('/');
	match normalized {
		"https://acme-v02.api.letsencrypt.org/directory" => Some("letsencrypt.org"),
		"https://acme-staging-v02.api.letsencrypt.org/directory" => Some("letsencrypt.org"),
		"https://acme.zerossl.com/v2/DV90" => Some("zerossl.com"),
		"https://api.buypass.com/acme/directory" => Some("buypass.com"),
		"https://dv.acme-v02.api.pki.goog/directory" => Some("pki.goog"),
		_ => None,
	}
}

/// A record to publish, paired with the zone it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRecord {
	/// DNS zone (the registrable domain) the record belongs to. The
	/// provider uses this to scope the upsert and authorize its API
	/// token against the right zone.
	pub zone: String,
	/// The record itself, ready to hand to a provider's `upsert`.
	pub record: DnsRecord,
}

const TTL: u32 = 3600;

/// Derive the DNS policy identifier using the public policy writer's renderer.
pub fn mta_sts_id(config: &crate::config::Config) -> String {
	crate::mtasts::publish::publication(config).id
}

/// Split a TXT record value into the strings the wire format requires.
///
/// RFC 1035 §3.3.14 caps each character-string at 255 octets, and most
/// resolvers concatenate the strings back into one logical record. An RSA
/// DKIM `p=` is too long for a single string (~410 bytes for RSA-2048, ~755
/// for RSA-4096); ed25519 fits in one. The split happens on character
/// boundaries, never inside a multi-byte UTF-8 codepoint, because the
/// wire form is length-prefixed bytes, not Unicode code points. The cut is
/// [`crate::dns::txt::txt_character_strings`], the one every provider uses.
pub fn txt_strings(value: &str) -> Vec<String> {
	crate::dns::txt::txt_character_strings(value)
}

/// Render a TXT value for a zone file (RFC 1035 §5.1): long values split
/// into double-quoted strings of at most 255 octets separated by a space,
/// `"` and `\` backslash-escaped, and any octet outside printable ASCII
/// written as a `\DDD` decimal escape. A short value is one quoted string.
/// This is [`crate::dns::txt::txt_presentation`], the form the providers
/// that take presentation form receive.
pub fn txt_zone_form(value: &str) -> String {
	crate::dns::txt::txt_presentation(value)
}

/// The DNS zone a hostname lives in: every label except the leftmost. A
/// hostname like `mail.example.org` is in the `example.org` zone; an
/// apex hostname `example.org` (which is its own zone) returns itself.
/// Used to scope A/AAAA records to the right provider zone when the
/// hostname is a sub-name.
fn host_zone(hostname: &str, domains: &[String]) -> String {
	// A configured domain that contains the hostname is the zone the
	// operator's provider credentials cover; prefer the longest such match
	// (`mx.mail.example.org` under `example.org`, not `mail.example.org`).
	let mut best: Option<&str> = None;
	for domain in domains {
		let matches = hostname.eq_ignore_ascii_case(domain)
			|| hostname
				.strip_suffix(domain.as_str())
				.is_some_and(|prefix| prefix.ends_with('.'));
		if matches && best.is_none_or(|b| domain.len() > b.len()) {
			best = Some(domain.as_str());
		}
	}
	if let Some(zone) = best {
		return zone.to_string();
	}
	match hostname.split_once('.') {
		Some((_, rest)) => rest.to_string(),
		None => hostname.to_string(),
	}
}

/// Per-domain DKIM selectors and their record values. A domain absent
/// from the map keeps the configured default; the map's keys are
/// lowercased to match the way the validator and the routing layer
/// compare domains. Used by [`build_records`] to publish only the
/// selectors that actually sign each domain.
pub type DomainDkim = std::collections::HashMap<String, Vec<(String, String)>>;

/// The records to publish for the given domains and mail hostname.
///
/// `dkim_default` lists every `<selector>._domainkey` value to emit (one per
/// configured signing key, in selector order, the ed25519 selector first,
/// then the optional RSA selector), replaced for a domain in
/// `dkim_per_domain` by that domain's own list; `tlsa` is the `3 0 1` association for
/// the mail host's certificate when one is available; `mta_sts_id`
/// versions the MTA-STS record; `services` selects the SRV locators, one
/// per service the deployment exposes (see [`Services::from_config`]);
/// `caa_directory` is the configured ACME directory URL; when it maps to a
/// known CA via
/// [`caa_ca_for_directory`], a single CAA `0 issue "<ca>"` is emitted for
/// every domain, locking renewal to that CA. Unknown directories emit no
/// CAA (a wrong value would block renewal).
/// `public_ipv4` / `public_ipv6` are the hostname's A and AAAA addresses when
/// the operator has set them in the config; when present, both are emitted in
/// the zone of the hostname's domain, once (not per served domain), before
/// the MX: an MX pointing at a name that does not resolve yet tries the
/// resolver, fails, and yields a hard bounce instead of falling back to the
/// next MX. Parameter order matches the read-the-config order.
#[allow(clippy::too_many_arguments)]
pub fn build_records(
	domains: &[String],
	hostname: &str,
	dkim_default: &[(String, String)],
	dkim_per_domain: &DomainDkim,
	tlsa: Option<&str>,
	mta_sts_id: &str,
	services: Services,
	caa_directory: Option<&str>,
	public_ipv4: Option<Ipv4Addr>,
	public_ipv6: Option<Ipv6Addr>,
) -> Vec<PublishRecord> {
	let mut records = Vec::new();
	// Hostname address records: A and AAAA at the hostname, in the zone of the
	// hostname's parent domain. Order matters: every MX below points at this
	// name, so the address must publish first; a sender that resolves the MX
	// to a hostname without addresses treats the destination as dead and
	// defers instead of using the secondary MX.
	if let Some(ip) = public_ipv4 {
		records.push(PublishRecord {
			zone: host_zone(hostname, domains),
			record: DnsRecord {
				name: hostname.to_string(),
				kind: RecordKind::A,
				value: ip.to_string(),
				ttl: TTL,
				proxied: None,
			},
		});
	}
	if let Some(ip) = public_ipv6 {
		records.push(PublishRecord {
			zone: host_zone(hostname, domains),
			record: DnsRecord {
				name: hostname.to_string(),
				kind: RecordKind::Aaaa,
				value: ip.to_string(),
				ttl: TTL,
				proxied: None,
			},
		});
	}
	for domain in domains {
		let txt = |name: String, value: String| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Txt,
				value,
				ttl: TTL,
				proxied: None,
			},
		};
		let srv = |name: String, port: u16| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Srv,
				value: format!("0 1 {port} {hostname}."),
				ttl: TTL,
				proxied: None,
			},
		};
		let cname = |name: String| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Cname,
				value: hostname.to_string(),
				ttl: TTL,
				proxied: None,
			},
		};

		// SPF: authorize the domain's MX hosts and hard-fail anything else
		// (`-all`). The hard-fail depends on every forwarded message being
		// SRS-rewritten; see `config::validate` for the matching check that
		// rejects `forward` without `srs_secret`.
		records.push(txt(domain.clone(), "v=spf1 mx -all".to_string()));
		// DMARC: a protective default that reports to postmaster.
		records.push(txt(
			format!("_dmarc.{domain}"),
			format!("v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}; adkim=s; aspf=s"),
		));
		// MTA-STS discovery record (the policy itself is served over HTTPS).
		records.push(txt(
			format!("_mta-sts.{domain}"),
			format!("v=STSv1; id={mta_sts_id}"),
		));
		// TLSRPT (RFC 8460): reports on TLS negotiation success/failure so the
		// operator can see when senders cannot reach us over STARTTLS.
		records.push(txt(
			format!("_smtp._tls.{domain}"),
			format!("v=TLSRPTv1; rua=mailto:tlsrpt@{domain}"),
		));
		// MX → the mail hostname at the standard priority. The hostname
		// must resolve (its A/AAAA were emitted first, above), otherwise
		// a sender that tries it bounces instead of falling back to the
		// secondary MX.
		records.push(PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name: domain.clone(),
				kind: RecordKind::Mx,
				value: format!("10 {hostname}"),
				ttl: TTL,
				proxied: None,
			},
		});
		// DKIM public keys, one per configured selector. Two are typical
		// (the ed25519 key plus the optional RSA dual-signing selector);
		// nothing about the format limits that to two. Per-domain
		// overrides take precedence over the default: a domain listed
		// in `dkim_per_domain` publishes only its own selectors, every
		// other domain publishes the default list.
		let dkim_for_domain: &[(String, String)] =
			match dkim_per_domain.get(&domain.to_ascii_lowercase()) {
				Some(pairs) => pairs.as_slice(),
				None => dkim_default,
			};
		for (selector, value) in dkim_for_domain {
			records.push(txt(
				format!("{selector}._domainkey.{domain}"),
				value.clone(),
			));
		}
		// Autoconfig / autodiscover (Thunderbird / Outlook auto-account
		// setup). Both point at the mail hostname so the discovery URL the
		// client gets back resolves to us.
		records.push(cname(format!("autoconfig.{domain}")));
		records.push(cname(format!("autodiscover.{domain}")));
		// MTA-STS policy fetch (RFC 8461 §3.2): clients look up
		// `mta-sts.<domain>` and fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt`.
		// The HTTPS endpoint must use a certificate covering this CNAME.
		records.push(cname(format!("mta-sts.{domain}")));
		// CAA (RFC 8659): lock cert issuance to the configured CA. Only
		// emitted for CAs we recognise — a wrong value would block
		// renewal, so unknown ACME directories stay silent.
		if let Some(ca) = caa_directory.and_then(caa_ca_for_directory) {
			records.push(PublishRecord {
				zone: domain.clone(),
				record: DnsRecord {
					name: domain.clone(),
					kind: RecordKind::Caa,
					value: format!("0 issue \"{ca}\""),
					ttl: TTL,
					proxied: None,
				},
			});
		}
		// Service locators (RFC 6186, 8314, 8621, 5804) — one per service
		// the deployment exposes. A locator names a port, so a client that
		// follows one of a service nobody listens on reaches nothing; the
		// set therefore follows the configuration.
		for service in SrvService::ALL {
			if !services.contains(service) {
				continue;
			}
			records.push(srv(
				format!("{}._tcp.{domain}", service.label()),
				service.port(),
			));
		}
	}

	// One TLSA record for the mail host (shared across all domains), in
	// the zone that holds the hostname: the hostname is a name inside the
	// zone, not a zone of its own.
	if let Some(association) = tlsa {
		records.push(PublishRecord {
			zone: host_zone(hostname, domains),
			record: DnsRecord {
				name: format!("_25._tcp.{hostname}"),
				kind: RecordKind::Tlsa,
				value: association.to_string(),
				ttl: TTL,
				proxied: None,
			},
		});
	}

	records
}

/// Build a DANE-EE `3 0 1` TLSA association (SHA-256 of the full certificate)
/// from a PEM chain — the leaf is the first CERTIFICATE block. Returns `None`
/// if no certificate is found. `3 0 1` needs no X.509 parsing, only the DER.
pub fn tlsa_full_cert(cert_pem: &str) -> Option<String> {
	let der = first_certificate_der(cert_pem)?;
	let digest = ring::digest::digest(&ring::digest::SHA256, &der);
	let hex = digest.as_ref().iter().fold(String::new(), |mut acc, byte| {
		use std::fmt::Write;
		let _ = write!(acc, "{byte:02x}");
		acc
	});
	Some(format!("3 0 1 {hex}"))
}

/// Publish (or refresh) the mail host's DANE TLSA record for a freshly issued
/// certificate via `provider` — called after a cert rotation. A `3 0 1`
/// association of the new leaf certificate is upserted at `_25._tcp.<hostname>`.
/// Returns `Ok(())` with no work when the PEM has no certificate.
pub async fn publish_tlsa(
	provider: &dyn DnsProvider,
	hostname: &str,
	cert_pem: &str,
) -> Result<(), ProviderError> {
	let Some(value) = tlsa_full_cert(cert_pem) else {
		return Ok(());
	};
	let record = DnsRecord {
		name: format!("_25._tcp.{hostname}"),
		kind: RecordKind::Tlsa,
		value,
		ttl: TTL,
		proxied: None,
	};
	// The zone that holds the mail hostname, not the hostname itself: a
	// provider that names its zones looks a zone up by its exact name, and
	// `mail.example.org` is a name inside the `example.org` zone, not a
	// zone of its own.
	let zone = crate::dns::zone::resolve(provider, hostname).await?;
	provider.upsert(&zone, record).await
}

/// Decode the first PEM `CERTIFICATE` block to DER.
fn first_certificate_der(pem: &str) -> Option<Vec<u8>> {
	const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
	const END: &str = "-----END CERTIFICATE-----";
	let start = pem.find(BEGIN)? + BEGIN.len();
	let end = pem[start..].find(END)? + start;
	let body: String = pem[start..end].split_whitespace().collect();
	BASE64.decode(body).ok()
}

#[cfg(test)]
#[path = "records_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "records_tests_b.rs"]
mod tests_b;

#[cfg(test)]
#[path = "records_tests_c.rs"]
mod tests_c;
