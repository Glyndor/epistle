//! TLS acceptor loading and ACME renewal setup. Pulled out of `serve`
//! because `[tls]` and `[acme]` together were a self-contained block of
//! startup wiring that grew every time a renewal or channel-binding knob
//! changed, and the cost belongs with the certificate plumbing.

use tokio_rustls::TlsAcceptor;

use std::sync::Arc;

use crate::acme::challenge::{ChallengeResponder, Dns01};
use crate::acme::http01::ChallengeStore;
use crate::acme::tlsalpn::AlpnChallengeStore;
use crate::config::{AcmeChallenge, Config};
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
	/// SCRAM-SHA-256-PLUS channel binding hash; `None` when ACME is set.
	/// It follows a static certificate the operator replaces on disk.
	pub channel_binding: Option<crate::tls::EndPoint>,
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
	// The certificate comes from the shared resolver: after a restart the
	// persisted ACME pair must win over the bootstrap one.
	let tls_acceptor = match crate::tls::served_tls(config) {
		Some(served) => Some(crate::tls::acceptor(&served.tls).map_err(std::io::Error::other)?),
		None => None,
	};
	// Every listener clone must retain the same certificate resolver. With
	// TLS-ALPN-01 that resolver also answers the CA's `acme-tls/1` handshake.
	let alpn_store = config
		.acme
		.as_ref()
		.filter(|acme| acme.challenge == AcmeChallenge::TlsAlpn01)
		.map(|_| Arc::new(AlpnChallengeStore::new()));
	let reloadable_tls = tls_acceptor.map(|acceptor| match &alpn_store {
		Some(store) => ReloadableAcceptor::with_acme_alpn(acceptor, store.clone()),
		None => ReloadableAcceptor::new(acceptor),
	});
	let tls_acceptor = reloadable_tls.as_ref().map(ReloadableAcceptor::current);

	// SCRAM-SHA-256-PLUS channel binding (tls-server-end-point). Offered only
	// with a static [tls] certificate: under ACME the certificate is reloaded at
	// runtime, which would make a fixed hash stale, so -PLUS stays off there and
	// clients fall back to plain SCRAM.
	let channel_binding = match (&config.tls, &config.acme) {
		(Some(tls), None) => tls_server_end_point(tls).map(crate::tls::EndPoint::new),
		_ => None,
	};

	// The operator's own pair: pick a replaced pair up without a restart,
	// keep the channel binding with it, and republish its TLSA record.
	if watches_files(config)
		&& let (Some(tls), Some(reloadable)) = (&config.tls, &reloadable_tls)
	{
		let mut watcher = crate::tls::watch::CertWatcher::new(tls.clone(), reloadable.clone());
		if let Some(end_point) = &channel_binding {
			watcher = watcher.with_end_point(end_point.clone());
		}
		let provider = config.dns.build_for_host(&config.hostname);
		tokio::spawn(crate::tls::watch::run(
			watcher,
			provider,
			config.hostname.clone(),
		));
	}

	// ACME automatic renewal: publish the certificate to every TLS listener.
	// Requires a [tls] bootstrap certificate to reload into.
	if let Some(acme) = &config.acme {
		match &reloadable_tls {
			Some(reloadable) => {
				// When a DNS provider is configured, refresh the TLSA record on
				// every certificate rotation.
				let tlsa = config
					.dns
					.build_for_host(&config.hostname)
					.map(|provider| (provider, config.hostname.clone()));
				let responder = responder(config, challenge_store, alpn_store)?;
				tokio::spawn(crate::acme::renew::run(
					acme.directory_url.clone(),
					acme.contacts.clone(),
					acme.domains.clone(),
					responder,
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

/// Whether the certificate files are watched and reloaded when they change:
/// a `[tls]` pair that no `[acme]` manages, which the operator renews by
/// replacing the files.
pub(super) fn watches_files(config: &Config) -> bool {
	config.tls.is_some() && config.acme.is_none()
}

/// The responder for the configured `[acme] challenge`. Validation already
/// refused a dns-01 without a publishing `[dns]` provider; a provider whose
/// credentials cannot be loaded still stops the start here (fail closed).
fn responder(
	config: &Config,
	http01: ChallengeStore,
	alpn: Option<Arc<AlpnChallengeStore>>,
) -> std::io::Result<Arc<dyn ChallengeResponder>> {
	let challenge = config.acme.as_ref().map(|acme| acme.challenge);
	match (challenge, alpn) {
		(Some(AcmeChallenge::TlsAlpn01), Some(store)) => Ok(Arc::new(store)),
		(Some(AcmeChallenge::Dns01), _) => {
			let provider = config.dns.build_for_host(&config.hostname).ok_or_else(|| {
				std::io::Error::other(
					"[acme] challenge = \"dns-01\": the [dns] provider could not be built (check its credentials)",
				)
			})?;
			let visibility = crate::acme::dns01_authoritative::AuthoritativeTxt::from_system()?;
			Ok(Arc::new(Dns01::new(provider, Arc::new(visibility))))
		}
		_ => Ok(Arc::new(http01)),
	}
}

#[cfg(test)]
mod tests;
