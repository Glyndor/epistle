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
	SrvService { name: "_submissions", port: 465 },
	SrvService { name: "_submission", port: 587 },
	SrvService { name: "_imaps", port: 993 },
	SrvService { name: "_imap", port: 143 },
	SrvService { name: "_pop3s", port: 995 },
	SrvService { name: "_jmap", port: 443 },
	SrvService { name: "_sieve", port: 4190 },
];

/// Which extra services the deployment exposes. Drives the optional SRV
/// records (CalDAV/CardDAV) and the optional CNAME discovery records (CAA
/// only when the ACME directory is a known one — see
/// [`crate::config::acme::Acme`]).
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

/// The records to publish for the given domains and mail hostname.
///
/// `dkim` is the `<selector>._domainkey` value (from the loaded signer) when
/// DKIM is configured; `tlsa` is the `3 0 1` association for the mail host's
/// certificate when one is available; `mta_sts_id` versions the MTA-STS record;
/// `services` toggles the optional SRV records (CalDAV/CardDAV are tied to the
/// `webdav` listener).
pub fn build_records(
	domains: &[String],
	hostname: &str,
	dkim: Option<(&str, &str)>,
	tlsa: Option<&str>,
	mta_sts_id: &str,
	services: Services,
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

		// SPF: authorize the domain's MX hosts; soft-fail the rest.
		records.push(txt(domain.clone(), "v=spf1 mx ~all".to_string()));
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
		// DKIM public key, if configured.
		if let Some((selector, value)) = dkim {
			records.push(txt(
				format!("{selector}._domainkey.{domain}"),
				value.to_string(),
			));
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
