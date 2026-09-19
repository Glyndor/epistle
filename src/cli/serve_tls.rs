//! TLS acceptor loading and ACME renewal setup. Pulled out of `serve`
//! because `[tls]` and `[acme]` together were a self-contained block of
//! startup wiring that grew every time a renewal or channel-binding knob
//! changed, and the cost belongs with the certificate plumbing.

use tokio_rustls::TlsAcceptor;

use crate::acme::http01::ChallengeStore;
use crate::config::Config;
use crate::tls::{ReloadableAcceptor, tls_server_end_point};

/// Everything `serve` needs from the TLS/ACME side of startup: the static
/// acceptor (used by IMAP, POP3S and ManageSieve), the hot-reloadable
/// acceptor (used by SMTP, so renewed certificates apply without a
/// restart), and the SCRAM channel-binding hash. The ACME renewal task is
/// spawned inside the helper and not returned.
pub(super) struct TlsStack {
	/// The static TLS acceptor, cloned into every listener that holds one
	/// for the lifetime of the server.
	pub tls_acceptor: Option<TlsAcceptor>,
	/// The hot-reloadable TLS acceptor, swapped in by the ACME renew task.
	pub reloadable_tls: Option<ReloadableAcceptor>,
	/// SCRAM-SHA-256-PLUS channel binding hash; `None` when ACME is set
	/// (the certificate rotates under us and a fixed hash would go stale).
	pub channel_binding: Option<Vec<u8>>,
}

/// Load the TLS acceptor, build the reloadable variant, compute the
/// SCRAM channel-binding hash, and spawn the ACME renewal task when one
/// is configured. Failures propagate through `?` so a missing or
/// malformed `[tls]` section stops the start with the same error text
/// as before the extraction.
pub(super) fn build_tls(
	config: &Config,
	challenge_store: ChallengeStore,
) -> std::io::Result<TlsStack> {
	// TLS is loaded once and shared; failure to load is fatal (fail closed).
	let tls_acceptor = match &config.tls {
		Some(tls_config) => Some(crate::tls::acceptor(tls_config).map_err(std::io::Error::other)?),
		None => None,
	};
	// SMTP listeners use a hot-reloadable acceptor so renewed certificates
	// apply without a restart; IMAP keeps the static acceptor for now.
	let reloadable_tls = tls_acceptor.clone().map(ReloadableAcceptor::new);

	// SCRAM-SHA-256-PLUS channel binding (tls-server-end-point). Offered only
	// with a static [tls] certificate: under ACME the certificate is reloaded at
	// runtime, which would make a fixed hash stale, so -PLUS stays off there and
	// clients fall back to plain SCRAM.
	let channel_binding = match (&config.tls, &config.acme) {
		(Some(tls), None) => tls_server_end_point(tls),
		_ => None,
	};

	// ACME automatic renewal: obtain/renew certificates and hot-reload the SMTP
	// acceptor. Requires a [tls] bootstrap certificate to reload into.
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
