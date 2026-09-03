//! Compute the DNS records epistle expects a deployment to publish: SPF, DKIM,
//! DMARC, MTA-STS, MX and (when a certificate is available) a DANE TLSA record.
//! These pair with [`super::check_domain`] (which verifies them) and can be
//! handed to a [`super::provider::DnsProvider`] to publish, or printed for
//! manual entry.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use super::provider::{DnsProvider, DnsRecord, ProviderError, RecordKind};

/// An SRV service descriptor: a `(name, port)` pair the operator wants to
/// advertise. The record's FQDN is `<name>._tcp.<zone>`; priority and weight
/// are the Stalwart-parity defaults (priority 0, weight 1).
struct SrvService {
	name: &'static str,
	port: u16,
}

/// All the SRV records epistle publishes. Per RFC 6186 (IMAP/POP3/SUBMISSION)
/// and RFC 8314 (Implicit TLS), RFC 8621 (JMAP), and ManageSieve (RFC 5804).
/// CalDAV/CardDAV SRVs are added in [`build_records`] when the `webdav`
/// module exposes them.
const SRV_SERVICES: &[SrvService] = &[
	SrvService {
		name: "_submissions",
		port: 465,
	},
	SrvService {
		name: "_submission",
		port: 587,
	},
	SrvService {
		name: "_imaps",
		port: 993,
	},
	SrvService {
		name: "_imap",
		port: 143,
	},
	SrvService {
		name: "_pop3s",
		port: 995,
	},
	SrvService {
		name: "_jmap",
		port: 443,
	},
	SrvService {
		name: "_sieve",
		port: 4190,
	},
];

/// Which extra services the deployment exposes. Drives the optional
/// CalDAV/CardDAV SRV records and the CNAME discovery records. The CAA
/// record is separate: it comes from the `directory_url` of the `acme`
/// config section, and only when that directory names a CA we recognise.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Services {
	/// CalDAV (RFC 4791) is served by the in-tree `webdav` module.
	pub caldav: bool,
	/// CardDAV (RFC 6352) is served by the in-tree `webdav` module.
	pub carddav: bool,
}

impl Services {
	/// Every service on: the default for a full epistle deployment where
	/// the `webdav` listener is configured.
	pub fn all() -> Self {
		Services {
			caldav: true,
			carddav: true,
		}
	}
}

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

/// Split a TXT record value into the strings the wire format requires.
///
/// RFC 1035 §3.3.14 caps each character-string at 255 octets, and most
/// resolvers concatenate the strings back into one logical record. An RSA
/// DKIM `p=` is too long for a single string (~410 bytes for RSA-2048, ~755
/// for RSA-4096); ed25519 fits in one. The split happens on character
/// boundaries, never inside a multi-byte UTF-8 codepoint, because the
/// wire form is length-prefixed bytes, not Unicode code points.
pub fn txt_strings(value: &str) -> Vec<String> {
	const MAX: usize = 255;
	if value.len() <= MAX {
		return vec![value.to_string()];
	}
	let mut out = Vec::new();
	let mut start = 0;
	while start < value.len() {
		let mut end = (start + MAX).min(value.len());
		// Walk back to the previous char boundary if a multibyte character
		// straddles the would-be split point.
		while end < value.len() && !value.is_char_boundary(end) {
			end -= 1;
		}
		out.push(value[start..end].to_string());
		start = end;
	}
	out
}

/// Render a TXT value for a zone file, with long values split into
/// double-quoted strings (RFC 1035 §5). Embedded `"` and `\` are backslash
/// escaped so the zone-file parser keeps them literal. A short value is
/// returned as a single quoted string.
pub fn txt_zone_form(value: &str) -> String {
	let mut out = String::with_capacity(value.len() + 2);
	for part in txt_strings(value) {
		out.push('"');
		for byte in part.bytes() {
			match byte {
				b'"' | b'\\' => {
					out.push('\\');
					out.push(byte as char);
				}
				_ => out.push(byte as char),
			}
		}
		out.push('"');
	}
	out
}

/// The records to publish for the given domains and mail hostname.
///
/// `dkim` lists every `<selector>._domainkey` value to emit (one per
/// configured signing key, in selector order, the ed25519 selector first,
/// then the optional RSA selector); `tlsa` is the `3 0 1` association for
/// the mail host's certificate when one is available; `mta_sts_id`
/// versions the MTA-STS record; `services` toggles the optional SRV records
/// (CalDAV/CardDAV are tied to the `webdav` listener); `caa_directory` is
/// the configured ACME directory URL; when it maps to a known CA via
/// [`caa_ca_for_directory`], a single CAA `0 issue "<ca>"` is emitted for
/// every domain, locking renewal to that CA. Unknown directories emit no
/// CAA (a wrong value would block renewal).
pub fn build_records(
	domains: &[String],
	hostname: &str,
	dkim: &[(String, String)],
	tlsa: Option<&str>,
	mta_sts_id: &str,
	services: Services,
	caa_directory: Option<&str>,
) -> Vec<PublishRecord> {
	let mut records = Vec::new();
	for domain in domains {
		let txt = |name: String, value: String| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Txt,
				value,
				ttl: TTL,
			},
		};
		let srv = |name: String, port: u16| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Srv,
				value: format!("0 1 {port} {hostname}."),
				ttl: TTL,
			},
		};
		let cname = |name: String| PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name,
				kind: RecordKind::Cname,
				value: hostname.to_string(),
				ttl: TTL,
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
		// MX → the mail hostname at the standard priority.
		records.push(PublishRecord {
			zone: domain.clone(),
			record: DnsRecord {
				name: domain.clone(),
				kind: RecordKind::Mx,
				value: format!("10 {hostname}"),
				ttl: TTL,
			},
		});
		// DKIM public keys, one per configured selector. Two are typical
		// (the ed25519 key plus the optional RSA dual-signing selector);
		// nothing about the format limits that to two.
		for (selector, value) in dkim {
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
		// epistle already serves the policy over HTTPS, so the CNAME makes
		// that URL resolvable.
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
				},
			});
		}
		// Service locators (RFC 6186, 8314, 8621, 5804) — mail, JMAP, and
		// ManageSieve always; CalDAV/CardDAV only when the webdav listener
		// exposes them.
		for svc in SRV_SERVICES {
			records.push(srv(format!("{}._{}.{domain}", svc.name, "tcp"), svc.port));
		}
		if services.caldav {
			records.push(srv(format!("_caldavs._tcp.{domain}"), 443));
		}
		if services.carddav {
			records.push(srv(format!("_carddavs._tcp.{domain}"), 443));
		}
	}

	// One TLSA record for the mail host (shared across all domains).
	if let Some(association) = tlsa {
		records.push(PublishRecord {
			zone: hostname.to_string(),
			record: DnsRecord {
				name: format!("_25._tcp.{hostname}"),
				kind: RecordKind::Tlsa,
				value: association.to_string(),
				ttl: TTL,
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
	};
	provider.upsert(hostname, record).await
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
