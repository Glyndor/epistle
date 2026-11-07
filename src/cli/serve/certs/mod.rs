//! `epistle serve --role certs`: the certificates container.
//!
//! This process holds what lets a caller rewrite the zone, the DNS provider
//! credential and the ACME account key, and runs only the work that needs
//! them: issuance and renewal with the `dns-01` challenge published through
//! `[dns]`, the TLSA record refresh when the certificate changes, the
//! withdrawal of each challenge record once its order is done, and the DNS
//! writes the mail container asks for. It binds no listener and takes no
//! request: it decides from the clock and from the request file
//! `epistle tls renew` leaves under `<data_dir>/acme`.
//!
//! The new pair is written to `<data_dir>/acme/{cert,key}.pem`, which `mail`
//! mounts read-only and picks up without a restart (`--role mail`).
//!
//! The DKIM rotation stays in `mail`, which keeps the keys and drives the
//! rotation; the records it publishes are written here, through the
//! hand-off directory both containers mount (`crate::dns::handoff`). `mail`
//! holds no DNS credential and this container holds no DKIM private key.

use std::path::PathBuf;
use std::sync::Arc;

use crate::acme::challenge::{ChallengeResponder, Dns01};
use crate::acme::renew::{Renewal, RenewalJob, TlsaPublisher};
use crate::config::{Acme, AcmeChallenge, Config};

/// How long the challenges still published get to be withdrawn at shutdown:
/// under the ten seconds Podman waits after SIGTERM by default, which is
/// what the generated `certs` service uses.
const STOP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(8);

/// What the certificates role needs from the configuration: an `[acme]`
/// section that validates with `dns-01`, and a `[dns]` provider to publish
/// the challenge through. `Err` names the missing piece.
pub(in crate::cli) fn requirements(config: &Config) -> Result<&Acme, String> {
	let Some(acme) = config.acme.as_ref() else {
		return Err(
			"`--role certs` renews the ACME certificate, and the configuration has no [acme]"
				.to_string(),
		);
	};
	if acme.challenge != AcmeChallenge::Dns01 {
		return Err(format!(
			"`--role certs` answers only the dns-01 challenge, and [acme] challenge is \"{}\": \
			 http-01 and tls-alpn-01 are answered on ports that `mail` owns. Set [acme] \
			 challenge = \"dns-01\"",
			acme.challenge.as_str()
		));
	}
	if config.dns.is_empty() {
		return Err(
			"`--role certs` publishes the dns-01 challenge through [dns], and the configuration \
			 has no [dns] provider"
				.to_string(),
		);
	}
	Ok(acme)
}

/// Where this role reads the ACME account key: outside data_dir, where only
/// the certificates container mounts it.
pub(super) fn account_key(config: &Config) -> PathBuf {
	crate::cli::init::host_secrets::acme_account_key(&config.data_dir)
}

/// The renewal job of this role: no acceptor to reload, the account key
/// outside data_dir, the challenge and the TLSA record through `provider`.
pub(super) fn renewal(
	config: &Config,
	acme: &Acme,
	responder: Arc<dyn ChallengeResponder>,
	tlsa: TlsaPublisher,
) -> RenewalJob {
	RenewalJob {
		directory_url: acme.directory_url.clone(),
		contacts: acme.contacts.clone(),
		domains: acme.domains.clone(),
		responder,
		data_dir: config.data_dir.clone(),
		account_key: account_key(config),
		reloadable: None,
		renew_before_days: u64::from(acme.renew_before_days),
		tlsa: Some(tlsa),
	}
}

/// The domains this installation serves: the ones a DKIM record may be
/// asked for. The mail container asks this one to write the records of the
/// domains it signs for, and nothing else.
fn served_domains(config: &Config) -> Vec<String> {
	let mut domains: Vec<String> = config
		.domains
		.iter()
		.map(|domain| domain.to_ascii_lowercase())
		.collect();
	for alias in config.domain_aliases.keys() {
		domains.push(alias.to_ascii_lowercase());
	}
	if let Some(dkim) = &config.dkim {
		for entry in &dkim.domain {
			domains.push(entry.name.to_ascii_lowercase());
		}
	}
	domains.sort();
	domains.dedup();
	domains
}

/// The selectors this installation uses besides the ones a rotation makes:
/// the ones the operator wrote in `[dkim]` and in every `[[dkim.domain]]`.
/// A rotation publishes and retires those, so the requests that name them
/// have to be accepted here.
fn configured_selectors(config: &Config) -> Vec<String> {
	config
		.dkim
		.as_ref()
		.map(|dkim| dkim.configured_selectors())
		.unwrap_or_default()
}

/// Run the certificates role until SIGTERM or SIGINT. A configuration this
/// role cannot work with, or a provider whose credential does not load,
/// stops the start (fail closed); a CA or DNS failure later is logged and
/// retried by the renewal loop.
pub(super) async fn serve(config: Config) -> std::io::Result<()> {
	let acme = requirements(&config).map_err(std::io::Error::other)?;
	let provider = config.dns.build_for_host(&config.hostname).ok_or_else(|| {
		std::io::Error::other(
			"the [dns] provider could not be built (check its credentials); the certificates \
			 container needs it for the dns-01 challenge and the TLSA record",
		)
	})?;
	let visibility = crate::acme::dns01_authoritative::AuthoritativeTxt::from_system()?;
	// The journal lets the next start withdraw a record this run could not.
	// It lives under `<data_dir>/acme`, which `mail` mounts read-only, so
	// what this role withdraws was written by this role.
	let journal = crate::acme::challenge::journal_path(&config.data_dir);
	let responder: Arc<dyn ChallengeResponder> =
		Arc::new(Dns01::new(Arc::clone(&provider), Arc::new(visibility)).with_journal(journal));
	let renewal = renewal(
		&config,
		acme,
		responder,
		(Arc::clone(&provider), config.hostname.clone()),
	);
	// The mail container keeps the DKIM keys and drives the rotation; the
	// records it publishes are written here, where the credential is.
	let handoff = crate::dns::handoff::Server::new(
		crate::dns::handoff::dir(&config.data_dir),
		Arc::clone(&provider),
		config.dns.zones(),
		served_domains(&config),
		configured_selectors(&config),
	);
	crate::privdrop::drop_privileges(config.privileges.as_ref())?;
	// Only after the drop: the directories under the data dir are shared
	// with the other container, and this process must not touch them as root.
	let serving = tokio::spawn(handoff.run());
	tracing::info!(
		account_key = %renewal.account_key.display(),
		directory = %crate::acme::renew::cert_path(&config.data_dir)
			.parent()
			.map(|dir| dir.display().to_string())
			.unwrap_or_default(),
		"certificates role: renewing with dns-01, no listener"
	);
	let renewing = Renewal::spawn(|stop| crate::acme::renew::run(renewal, stop));
	let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
	let name = tokio::select! {
		_ = term.recv() => "SIGTERM",
		_ = tokio::signal::ctrl_c() => "SIGINT",
	};
	// The order in flight is dropped and what it published is withdrawn
	// before the container is killed; what is left after the deadline is
	// withdrawn at the next start, from the journal.
	renewing.stop(STOP_DEADLINE).await;
	// A DNS write in flight is dropped with the task: the mail container
	// asks again, and a request that was not answered is taken back.
	serving.abort();
	tracing::info!(signal = name, "certificates role stopped");
	Ok(())
}

#[cfg(test)]
mod tests;
