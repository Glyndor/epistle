//! Background maintenance tasks spawned by `serve`, kept out of the main
//! startup flow.

use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::{Config, Listener};

/// Bind a listener's socket and log it. Shared by every `serve` listener arm.
pub(super) async fn bind(listener: &Listener) -> std::io::Result<TcpListener> {
	let addr = listener.socket_addr();
	let bound = TcpListener::bind(addr).await?;
	tracing::info!(%addr, kind = ?listener.kind, "listening");
	Ok(bound)
}

/// Spawn an axum router on a bound listener, returning the serving task. Shared
/// by the plain-HTTP listener arms (autoconfig, ACME, WebDAV, metrics).
pub(super) fn serve_http(
	listener: TcpListener,
	router: axum::Router,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
	tokio::spawn(async move {
		axum::serve(listener, router)
			.await
			.map_err(std::io::Error::other)
	})
}

/// Spawn the hourly DMARC aggregate-report flush: for each completed day with
/// accumulated delivery records, build the reports and queue them on the
/// outbound spool.
pub(super) fn spawn_dmarc_flush(
	config: &Config,
	spf_dns: Arc<dyn crate::spf::DnsLookup>,
) -> std::io::Result<()> {
	let data_dir = config.data_dir.clone();
	let hostname = config.hostname.clone();
	let spool = crate::storage::FsSpool::open(&config.data_dir)?;
	tokio::spawn(async move {
		let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			interval.tick().await;
			let ts = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			let today = crate::dmarc::aggregate::unix_to_day(ts);
			let messages = crate::dmarc::aggregate::flush_pending(
				&data_dir,
				&today,
				&hostname,
				&format!("postmaster@{hostname}"),
				&hostname,
				spf_dns.as_ref(),
			)
			.await;
			for message in messages {
				if let Err(e) = spool.store(&message) {
					tracing::warn!(%e, "failed to queue DMARC report");
				}
			}
		}
	});
	Ok(())
}

/// JMAP uploaded blobs are transient (RFC 8620 §6.1): time-to-live for an
/// unreferenced upload before it is reclaimed.
const BLOB_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Spawn the hourly JMAP blob reclamation: delete uploaded blobs older than
/// `BLOB_TTL` from the upload store. Only the blob store is swept; stored mail
/// is never touched.
pub(super) fn spawn_blob_reclamation(config: &Config) {
	let data_dir = config.data_dir.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			let removed = crate::api::reclaim_blobs(&data_dir, BLOB_TTL);
			if removed > 0 {
				tracing::info!(removed, "reclaimed expired JMAP blobs");
			}
		}
	});
}

/// Build the OAuth2/OIDC token verifier from `[oauth]`, fetching the JWKS once
/// and spawning an hourly refresh when OIDC discovery is configured. A malformed
/// configuration or an initial fetch failure is fatal (fail closed). Returns
/// `Ok(None)` when no `[oauth]` section is present.
pub(super) async fn build_oauth_verifier(
	config: &Config,
) -> std::io::Result<Option<Arc<crate::oauth::OauthVerifier>>> {
	let Some(oauth) = &config.oauth else {
		return Ok(None);
	};
	oauth
		.validate()
		.map_err(|e| std::io::Error::other(format!("oauth config: {e}")))?;
	let verifier = match (&oauth.public_key, &oauth.discovery_url) {
		(Some(public_key), _) => crate::oauth::OauthVerifier::new(
			&oauth.issuer,
			&oauth.audience,
			&oauth.algorithm,
			public_key,
		)
		.map_err(|e| std::io::Error::other(format!("oauth config: {e:?}")))?,
		(None, Some(discovery_url)) => {
			let default_alg = parse_oauth_alg(&oauth.algorithm)?;
			let client = reqwest::Client::new();
			let keys = crate::oauth::oidc::fetch_keys(&client, discovery_url, default_alg)
				.await
				.map_err(|e| std::io::Error::other(format!("oauth discovery: {e}")))?;
			let verifier =
				crate::oauth::OauthVerifier::from_jwks(&oauth.issuer, &oauth.audience, keys);
			spawn_jwks_refresh(
				verifier.jwks_cache(),
				client,
				discovery_url.clone(),
				default_alg,
			);
			verifier
		}
		(None, None) => unreachable!("validate() rejects the no-source case"),
	};
	Ok(Some(Arc::new(verifier)))
}

/// Build the built-in OAuth authorization server from `[oauth] signing_key`, or
/// `None` when no signing key is configured (the `/oauth/*` grant routes then
/// stay unmounted — fail closed). The signed tokens carry the configured
/// issuer/audience and verify against the configured `public_key`.
pub(super) fn build_authz_server(config: &Config) -> Option<crate::api::oauth::AuthzServer> {
	let oauth = config.oauth.as_ref()?;
	let signing_key = oauth.signing_key.as_ref()?;
	crate::api::oauth::AuthzServer::new(signing_key, &oauth.issuer, &oauth.audience)
}

/// Map the configured algorithm name to a [`crate::jwt::Algorithm`], the default
/// applied to a JWKS key that omits its own `alg`.
fn parse_oauth_alg(algorithm: &str) -> std::io::Result<crate::jwt::Algorithm> {
	match algorithm.to_ascii_uppercase().as_str() {
		"RS256" => Ok(crate::jwt::Algorithm::Rs256),
		"ES256" => Ok(crate::jwt::Algorithm::Es256),
		_ => Err(std::io::Error::other("oauth config: unsupported algorithm")),
	}
}

/// Spawn the hourly JWKS refresh: re-fetch the IdP's keys and swap them into the
/// shared cache so rotated keys are picked up without a restart. A failed fetch
/// keeps the previous keys (it does not clear the cache).
fn spawn_jwks_refresh(
	cache: Option<Arc<std::sync::RwLock<Vec<crate::oauth::Jwk>>>>,
	client: reqwest::Client,
	discovery_url: String,
	default_alg: crate::jwt::Algorithm,
) {
	let Some(cache) = cache else {
		return;
	};
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			match crate::oauth::oidc::fetch_keys(&client, &discovery_url, default_alg).await {
				Ok(keys) => {
					if let Ok(mut guard) = cache.write() {
						*guard = keys;
					}
				}
				Err(error) => tracing::warn!(%error, "oidc jwks refresh failed"),
			}
		}
	});
}

/// Load the SQL directory accounts into the store once, then spawn an hourly
/// refresh task. A no-op unless `[database] directory = true` and a reputation
/// pool is present. The initial load fails closed (a fatal startup error) so the
/// server never runs with a silently empty SQL directory; later refresh failures
/// keep the previously loaded accounts. Account precedence (static and dynamic
/// over SQL) is handled by [`crate::directory_store::AccountStore`].
pub(super) async fn spawn_sql_directory(
	config: &Config,
	pool: &Option<sqlx::PgPool>,
	store: Arc<crate::directory_store::AccountStore>,
) -> std::io::Result<()> {
	let (Some(true), Some(pool)) = (config.database.as_ref().map(|db| db.directory), pool) else {
		return Ok(());
	};
	let accounts = crate::directory_store::load_sql_accounts(pool)
		.await
		.map_err(|error| std::io::Error::other(format!("sql directory load: {error}")))?;
	tracing::info!(count = accounts.len(), "loaded SQL directory accounts");
	store.set_sql_accounts(accounts);
	let pool = pool.clone();
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			match crate::directory_store::load_sql_accounts(&pool).await {
				Ok(accounts) => store.set_sql_accounts(accounts),
				Err(error) => tracing::warn!(%error, "sql directory refresh failed"),
			}
		}
	});
	Ok(())
}

/// Build the live LDAP authenticator from `[ldap]`, or `None` when no section is
/// present. Attached to the store at construction so per-request binds (including
/// for LDAP-only logins) work before the first resolution load completes.
pub(super) fn build_ldap_authenticator(
	config: &Config,
) -> Option<Arc<crate::directory_store::LdapAuthenticator>> {
	config
		.ldap
		.clone()
		.map(|ldap| Arc::new(crate::directory_store::LdapAuthenticator::new(ldap)))
}

/// Load+refresh the LDAP resolution accounts into the store. A no-op unless an
/// `[ldap]` section is present. The initial resolution load fails closed (a fatal
/// startup error) so the server never runs with a silently empty LDAP directory;
/// later refreshes keep the previous set. Account precedence (static/dynamic/SQL
/// over LDAP) is handled by [`crate::directory_store::AccountStore`].
pub(super) async fn spawn_ldap_directory(
	config: &Config,
	store: Arc<crate::directory_store::AccountStore>,
) -> std::io::Result<()> {
	let Some(ldap) = config.ldap.clone() else {
		return Ok(());
	};
	let initial = load_ldap_blocking(ldap.clone())
		.await
		.map_err(|error| std::io::Error::other(format!("ldap directory load: {error}")))?;
	tracing::info!(count = initial.len(), "loaded LDAP directory accounts");
	store.set_ldap_accounts(initial);
	let refresh = std::time::Duration::from_secs(ldap.refresh_secs);
	let task_store = Arc::clone(&store);
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(refresh);
		ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
		loop {
			ticker.tick().await;
			match load_ldap_blocking(ldap.clone()).await {
				Ok(accounts) => task_store.set_ldap_accounts(accounts),
				Err(error) => tracing::warn!(%error, "ldap directory refresh failed"),
			}
		}
	});
	Ok(())
}

/// Run the blocking LDAP resolution search on a blocking thread so the async
/// runtime is never stalled by the synchronous ldap3 I/O.
async fn load_ldap_blocking(
	ldap: crate::config::Ldap,
) -> std::io::Result<Vec<crate::directory_store::LdapAccount>> {
	tokio::task::spawn_blocking(move || crate::directory_store::load_ldap_accounts(&ldap))
		.await
		.map_err(std::io::Error::other)?
		.map_err(std::io::Error::other)
}

/// Spawn the automatic DKIM key-rotation task when `[dkim] rotate_days` and a
/// `[dns]` provider are both configured. Hourly ticks rotate/retire when due.
pub(super) fn spawn_dkim_rotation(
	config: &Config,
	dkim_signer: &Option<crate::dkim::ReloadableSigner>,
) {
	let (Some(dkim), Some(signer), Some(dns)) = (&config.dkim, dkim_signer, &config.dns) else {
		return;
	};
	let (Some(rotate_days), Some(provider)) = (dkim.rotate_days, dns.build()) else {
		return;
	};
	let rotator = crate::dkim::Rotator::new(
		config.data_dir.clone(),
		signer.clone(),
		provider,
		dns.zone.clone(),
		dns.zone.clone(),
		u64::from(rotate_days) * 86_400,
		u64::from(dkim.rotate_overlap_days) * 86_400,
	);
	tokio::spawn(async move {
		let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
		loop {
			ticker.tick().await;
			let now = std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			if let Err(error) = rotator.tick(now).await {
				tracing::warn!(%error, "dkim rotation tick failed");
			}
		}
	});
}
