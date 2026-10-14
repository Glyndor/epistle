//! The DANE TLSA record after an operator's own certificate changed.

use crate::dns::provider::DnsProvider;

/// What happened to `_25._tcp.<hostname>` after a certificate change.
#[derive(Debug, PartialEq, Eq)]
pub enum TlsaUpdate {
	/// The provider published the record for the new certificate.
	Published {
		/// The `3 0 1 <sha256>` association now published.
		value: String,
	},
	/// The provider refused the record; it has to be updated by hand.
	Failed {
		/// The association to publish.
		value: String,
		/// Why the provider refused it.
		error: String,
	},
	/// No `[dns]` provider: the record has to be updated by hand.
	ByHand {
		/// The association to publish.
		value: String,
	},
	/// The chain has no certificate to hash.
	NoCertificate,
}

/// Publish the TLSA record of `chain_pem` through `provider`, the path
/// ACME renewal takes ([`crate::dns::records::publish_tlsa`]), or say what
/// to publish by hand when there is no provider or it refuses.
pub async fn republish_tlsa(
	provider: Option<&dyn DnsProvider>,
	hostname: &str,
	chain_pem: &str,
) -> TlsaUpdate {
	let Some(value) = crate::dns::records::tlsa_full_cert(chain_pem) else {
		return TlsaUpdate::NoCertificate;
	};
	let Some(provider) = provider else {
		return TlsaUpdate::ByHand { value };
	};
	match crate::dns::records::publish_tlsa(provider, hostname, chain_pem).await {
		Ok(()) => TlsaUpdate::Published { value },
		Err(error) => TlsaUpdate::Failed {
			value,
			error: error.to_string(),
		},
	}
}

/// Log what [`republish_tlsa`] did. A record left to the operator is a
/// warning that names it and the value to publish: DANE senders refuse
/// mail while it names the old certificate.
pub fn log_tlsa(update: &TlsaUpdate, hostname: &str) {
	let name = format!("_25._tcp.{hostname}");
	match update {
		TlsaUpdate::Published { value } => {
			tracing::info!(%name, %value, "TLSA record updated for the new certificate");
		}
		TlsaUpdate::Failed { value, error } => tracing::warn!(
			%name,
			%error,
			"the [dns] provider refused the TLSA record for the new certificate; if you publish DANE, set {name} TLSA {value} by hand",
		),
		TlsaUpdate::ByHand { value } => tracing::warn!(
			%name,
			"the certificate changed and no [dns] provider is configured; if you publish DANE, update {name} TLSA to {value} by hand",
		),
		TlsaUpdate::NoCertificate => {}
	}
}

#[cfg(test)]
#[path = "watch_tlsa_tests.rs"]
mod tests;
