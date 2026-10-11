//! TLS acceptor loading and ACME renewal setup. Pulled out of `serve`
//! because `[tls]` and `[acme]` together were a self-contained block of
//! startup wiring that grew every time a renewal or channel-binding knob
//! changed, and the cost belongs with the certificate plumbing.

use tokio_rustls::TlsAcceptor;

use crate::acme::http01::ChallengeStore;
use crate::config::Config;
use crate::tls::{ReloadableAcceptor, tls_server_end_point};

/// TLS/ACME startup state: listener acceptors share one reloadable certificate
/// source, plus the SCRAM channel-binding hash. The ACME renewal task is
/// spawned inside the helper and not returned.
pub(super) struct TlsStack {
	/// The shared TLS acceptor, whose certificate resolver observes renewal
	/// even when a listener retains its clone for the lifetime of the server.
	pub tls_acceptor: Option<TlsAcceptor>,
	/// The certificate reload handle used by the ACME renewal task.
	pub reloadable_tls: Option<ReloadableAcceptor>,
	/// SCRAM-SHA-256-PLUS channel binding hash; `None` when ACME is set
	/// (the certificate rotates under us and a fixed hash would go stale).
	pub channel_binding: Option<Vec<u8>>,
}

/// Load the TLS acceptor, build the reloadable variant, compute the
/// SCRAM channel-binding hash, and spawn the ACME renewal task when one
/// is configured. Failures propagate through `?` so a missing or
/// malformed `[tls]` section stops the start.
pub(super) fn build_tls(
	config: &Config,
	challenge_store: ChallengeStore,
) -> std::io::Result<TlsStack> {
	// TLS is loaded once and shared; failure to load is fatal (fail closed).
	let tls_acceptor = match &config.tls {
		Some(tls_config) => Some(crate::tls::acceptor(tls_config).map_err(std::io::Error::other)?),
		None => None,
	};
	// Every listener clone must retain the same certificate resolver.
	let reloadable_tls = tls_acceptor.map(ReloadableAcceptor::new);
	let tls_acceptor = reloadable_tls.as_ref().map(ReloadableAcceptor::current);

	// SCRAM-SHA-256-PLUS channel binding (tls-server-end-point). Offered only
	// with a static [tls] certificate: under ACME the certificate is reloaded at
	// runtime, which would make a fixed hash stale, so -PLUS stays off there and
	// clients fall back to plain SCRAM.
	let channel_binding = match (&config.tls, &config.acme) {
		(Some(tls), None) => tls_server_end_point(tls),
		_ => None,
	};

	// ACME automatic renewal: publish the certificate to every TLS listener.
	// Requires a [tls] bootstrap certificate to reload into.
	if let Some(acme) = &config.acme {
		match &reloadable_tls {
			Some(reloadable) => {
				// When a DNS provider is configured, refresh the TLSA record on
				// every certificate rotation.
				let tlsa = config
					.dns
					.as_ref()
					.and_then(|dns| dns.build())
					.map(|provider| (provider, config.hostname.clone()));
				tokio::spawn(crate::acme::renew::run(
					acme.directory_url.clone(),
					acme.contacts.clone(),
					acme.domains.clone(),
					challenge_store,
					config.data_dir.clone(),
					reloadable.clone(),
					u64::from(acme.renew_before_days),
					tlsa,
				));
			}
			None => tracing::warn!("[acme] is configured but [tls] is not; skipping ACME renewal"),
		}
	}

	Ok(TlsStack {
		tls_acceptor,
		reloadable_tls,
		channel_binding,
	})
}

#[cfg(test)]
#[path = "serve_tls_tests_reload.rs"]
mod tests_reload;
