//! The `serve` command: bind listeners and run until interrupted.

use std::process::ExitCode;
use std::sync::Arc;

use crate::config::{Config, ListenerKind};
use crate::smtp::server::{Server, TlsMode};
use crate::smtp::sink::MessageSink;
use crate::storage::SplitDelivery;

/// Run the server with a validated configuration.
pub fn run(config: Config) -> ExitCode {
	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("error: cannot start async runtime: {error}");
			return ExitCode::FAILURE;
		}
	};
	// Initialise tracing inside the runtime so the OTLP batch exporter (if any)
	// can spawn its background task. The provider is held for a clean shutdown.
	let _guard = runtime.enter();
	let otel_provider = super::tracing_setup::init_tracing(&config);

	let result = runtime.block_on(serve(config));

	// Flush any buffered spans to the collector before exiting.
	if let Some(provider) = otel_provider
		&& let Err(error) = provider.shutdown()
	{
		tracing::warn!(%error, "otel provider shutdown failed");
	}
	match result {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => {
			eprintln!("error: {error}");
			ExitCode::FAILURE
		}
	}
}

async fn serve(config: Config) -> std::io::Result<()> {
	if config.listeners.is_empty() {
		eprintln!("warning: no listeners configured, nothing to serve");
		return Ok(());
	}

	// Recipient resolution and credentials: static config plus the
	// API-managed dynamic accounts, hot-swapped on mutation. An optional live
	// LDAP authenticator is attached here so per-request binds work immediately.
	let ldap_auth = super::serve_tasks::build_ldap_authenticator(&config);
	let mut store = crate::directory_store::AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.map_err(|error| std::io::Error::other(error.to_string()))?
	.with_domain_quotas(config.domain_quotas.clone())
	.with_aliases(config.alias.clone())
	.with_masked_max(config.masked_addresses_max);
	if let Some(auth) = ldap_auth {
		store = store.with_ldap_authenticator(auth);
	}
	// Shared metrics across SMTP listeners, delivery, and the metrics endpoint.
	let metrics = Arc::new(crate::metrics::Metrics::new());
	// Probe the system clock before anything else binds a socket: a drift
	// past the TOTP window breaks two-factor for every account at once,
	// and the counter is what the alert engine reads. The probe sleeps
	// for ~100 ms; doing it before listener setup means the metric is
	// already in place if a slow startup happens to coincide with one.
	crate::clock::check_drift(&metrics);
	// Optional reputation database, migrated at startup. An unreachable
	// database degrades the antispam engine instead of stopping the mail, unless
	// `[database] directory = true` makes it the source of the accounts.
	let reputation_pool = super::serve_tasks::connect_database(&config, &metrics).await?;

	// The directory's audit counters are bumped from the SMTP, IMAP,
	// ManageSieve, WebDAV, API and OAuth paths — every directory rebuilt
	// here shares the same `Arc<Metrics>` so the counters are coherent.
	store = store.with_metrics(metrics.clone());
	// When `[database]` is configured the shared ban store is built and
	// attached to every rebuilt directory. Without a database, the ban
	// store is absent and the per-connection three-strikes counters are
	// the only defence; exactly the pre-table behaviour.
	if let Some(pool) = &reputation_pool {
		let ban_store: Arc<dyn crate::antispam::bans::BanStore> = Arc::new(
			crate::antispam::bans::PgBanStore::new(pool.clone(), Some(metrics.clone())),
		);
		store = store.with_ban_store(ban_store);
	}
	let account_store = Arc::new(store);
	let directory = account_store.handle();

	// At-rest message encryption, loaded once and shared. Fail closed: with
	// encryption enabled but no usable key the server refuses to start.
	let crypto = crate::storage::MessageCrypto::from_config(config.storage.as_ref())
		.map_err(std::io::Error::other)?;

	// Local recipients go to account mailboxes; authenticated relay mail
	// is queued in the outbound spool, DKIM-signed when configured.
	let mut split =
		SplitDelivery::new_with_crypto(&config.data_dir, directory.clone(), crypto.clone())?
			.with_rules(config.rules.clone())
			.with_metrics(metrics.clone());
	// Hot-swappable DKIM signer, so automatic key rotation applies live.
	let mut dkim_signer: Option<crate::dkim::ReloadableSigner> = None;
	if let Some(dkim) = &config.dkim {
		let mut signer = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file)
			.map_err(std::io::Error::other)?;
		if let (Some(selector), Some(key_file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
			signer = signer
				.with_rsa(selector, key_file)
				.map_err(std::io::Error::other)?;
		}
		let reloadable = crate::dkim::ReloadableSigner::new(Arc::new(signer));
		split = split.with_signer(reloadable.clone());
		dkim_signer = Some(reloadable);
	}
	if let Some(secret) = &config.srs_secret {
		let srs = crate::queue::srs::Srs::new(secret.as_bytes());
		split = split.with_srs(srs, config.hostname.clone());
	}
	let webhook = match &config.webhook {
		Some(webhook) => Some(Arc::new(
			crate::webhook::Webhook::new(&webhook.url, webhook.secret.clone())
				.map_err(std::io::Error::other)?
				.with_metrics(metrics.clone()),
		)),
		None => None,
	};
	if let Some(webhook) = &webhook {
		split = split.with_webhook(Arc::clone(webhook));
	}
	// Optional ARC sealer: seals inbound mail under the server hostname using
	// a DKIM-format ed25519 key. Failure to load is fatal (fail closed). The
	// same sealer also seals forwarded mail (RFC 8617) via the delivery sink.
	let arc_sealer = super::serve_tasks::build_arc_sealer(&config)?;
	if let Some(sealer) = &arc_sealer {
		split = split.with_arc_sealer(Arc::clone(sealer));
	}
	let sink: Arc<dyn MessageSink> = Arc::new(split);

	// Optional greylisting store, shared across SMTP listeners. A background
	// task prunes stale triplets so the map stays bounded.
	let greylist = super::serve_tasks::build_greylist(&config);

	// Optional OAuth2/OIDC token verifier for OAUTHBEARER/XOAUTH2. A malformed
	// configuration is fatal (fail closed rather than silently disable it). With
	// OIDC discovery this fetches the JWKS and spawns the hourly refresh task.
	let oauth_verifier = super::serve_tasks::build_oauth_verifier(&config).await?;

	// ACME HTTP-01 challenge store, shared by the responder listener and (later)
	// the renewal task that publishes key authorizations into it.
	let challenge_store = crate::acme::http01::ChallengeStore::new();

	// SPF verification for unauthenticated inbound mail.
	let spf_dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(crate::spf::SystemDns::from_system()?);

	// Optional per-account submission rate limiter, shared across SMTP
	// listeners. The per-account `limit` is resolved at MAIL FROM time
	// (per-domain override, then the server-wide default, then no limit at
	// all); the limiter itself only owns the shared sliding-window state.
	// It is created whenever any limit is configured, so a per-domain
	// override without a global still gets a working limiter.
	let has_any_submission_limit = config.submission_rate_limit_per_min.is_some()
		|| !config.domain_submission_limits.is_empty();
	let send_limiter =
		has_any_submission_limit.then(|| Arc::new(crate::smtp::ratelimit::SendLimiter::new(60)));

	// Optional per-client-IP and per-envelope-sender inbound rate limiters
	// for unauthenticated sessions. The `per_min` ceiling lives alongside
	// the limiter so the listener wiring is a single value (an
	// `InboundLimit`). `None` disables the corresponding check at MAIL
	// FROM time.
	let inbound_ip_limit = config.inbound_rate_limit_per_ip_per_min.map(|per_min| {
		crate::smtp::ratelimit::InboundLimit {
			limiter: Arc::new(crate::smtp::ratelimit::SendLimiter::new(60)),
			per_min,
		}
	});
	let inbound_sender_limit = config.inbound_rate_limit_per_sender_per_min.map(|per_min| {
		crate::smtp::ratelimit::InboundLimit {
			limiter: Arc::new(crate::smtp::ratelimit::SendLimiter::new(60)),
			per_min,
		}
	});

	// Per-tenant aggregate limits. Built once from the static config; with
	// no `[[tenant]]` blocks the result is the identity, every check is a
	// no-op, and the wire below carries an empty `Arc`.
	let tenant_limits = Arc::new(crate::api::TenantLimits::from_config(&config.tenants));

	// Per-account correspondent store: one `Arc` shared by every SMTP
	// listener and the API state. The store is opened here (and not
	// inside `CorrespondentStore::open`) so a single underlying
	// filesystem tree backs every submission path; recording on one
	// path is immediately visible to the cap check on another.
	let correspondents = Arc::new(
		crate::storage::CorrespondentStore::open(&config.data_dir)
			.map_err(std::io::Error::other)?,
	);
	// `daily_new_recipients` is the per-account cap; `None` disables it
	// (the pre-feature behaviour). The cap is the same value across
	// every submission path: a single source of truth at startup.
	let daily_new_recipients = config.new_recipients_per_day;

	// Shared disk-space guard for `data_dir`. `MAIL FROM` rejects with
	// `452` when the filesystem holding the spool cannot hold another
	// message, so the remote retries instead of receiving `250` for a
	// payload the server cannot write. One guard per listener would
	// re-sample on every concurrent connection; one shared guard amortises
	// the cache and keeps the measurement consistent across listeners.
	let disk_guard = Arc::new(crate::smtp::diskspace::DiskGuard::new(
		config.data_dir.clone(),
	));

	// Per-listener concurrency cap; 0 keeps each protocol's built-in default.
	let max_conn = config.max_connections_per_listener.unwrap_or(0);

	// Optional external scanner hook.
	let scanner_hook: Option<Arc<dyn crate::antispam::hook::MailHook>> =
		match &config.scanner_hook_url {
			Some(url) => Some(Arc::new(
				crate::antispam::hook::HttpHook::new(url).map_err(std::io::Error::other)?,
			)),
			None => None,
		};

	// Optional LLM-assisted antispam hook for the uncertain band. The API
	// key is read from the environment via the configured variable name so it
	// never lands in the config file. Built eagerly so a missing key fails
	// the start, not the first mail that hits the band.
	let llm_hook = crate::antispam::llm::LlmHook::from_config(config.antispam_llm.as_ref())?;

	// Optional SQL directory backend: load accounts into the store and refresh.
	super::serve_tasks::spawn_sql_directory(&config, &reputation_pool, Arc::clone(&account_store))
		.await?;

	// Optional LDAP directory backend: load the resolution set and refresh it.
	super::serve_tasks::spawn_ldap_directory(&config, Arc::clone(&account_store)).await?;

	// The queue worker drains the outbound spool in the background.
	let connector = Arc::new(crate::queue::MxConnector::from_system()?);
	let mta_sts = Arc::new(crate::mtasts::PolicyStore::new(Box::new(
		crate::mtasts::SystemFetcher::new().map_err(|error| {
			std::io::Error::other(format!("cannot build MTA-STS fetcher: {error:?}"))
		})?,
	)));
	let mut worker = crate::queue::Worker::new(
		crate::storage::FsSpool::open_with_crypto(&config.data_dir, crypto.clone())?,
		connector,
		&config.hostname,
	)
	.with_bounce_sink(Arc::clone(&sink))
	.with_mta_sts(mta_sts, Arc::clone(&spf_dns))
	.with_dane(Arc::clone(&spf_dns))
	.with_metrics(metrics.clone())
	.with_max_age(config.queue_give_up_secs.unwrap_or(0))
	.with_suppression(crate::queue::SuppressionList::open(&config.data_dir)?)
	.with_transports(config.transport.clone())
	.with_outbound_tls(config.queue.outbound_tls);
	if let Some(webhook) = &webhook {
		worker = worker.with_webhook(Arc::clone(webhook));
	}
	let worker = Arc::new(worker);
	tokio::spawn(worker.run(std::time::Duration::from_secs(30)));

	// DMARC aggregate report flush runs hourly in the background.
	super::serve_tasks::spawn_dmarc_flush(&config, Arc::clone(&spf_dns))?;

	super::serve_tasks::spawn_dkim_rotation(&config, &dkim_signer);

	super::serve_tasks::spawn_alert_engine(
		&config,
		Arc::clone(&metrics),
		webhook.as_ref().map(Arc::clone),
		Arc::new(crate::storage::FsSpool::open_with_crypto(
			&config.data_dir,
			crypto.clone(),
		)?),
	);

	super::serve_tasks::spawn_storage_maintenance(&config);

	// Hourly ban sweep: drops stale auth_failure rows and expired bans so
	// the tables stay bounded. No-op when no database is configured: the
	// ban store is absent in that case.
	super::serve_tasks::spawn_ban_sweep(reputation_pool.clone());

	// TLS is loaded once and shared; failure to load is fatal (fail closed).
	let tls_acceptor = match &config.tls {
		Some(tls_config) => Some(crate::tls::acceptor(tls_config).map_err(std::io::Error::other)?),
		None => None,
	};
	// SMTP listeners use a hot-reloadable acceptor so renewed certificates
	// apply without a restart; IMAP keeps the static acceptor for now.
	let reloadable_tls = tls_acceptor
		.clone()
		.map(crate::tls::ReloadableAcceptor::new);

	// SCRAM-SHA-256-PLUS channel binding (tls-server-end-point). Offered only
	// with a static [tls] certificate: under ACME the certificate is reloaded at
	// runtime, which would make a fixed hash stale, so -PLUS stays off there and
	// clients fall back to plain SCRAM.
	let channel_binding = match (&config.tls, &config.acme) {
		(Some(tls), None) => crate::tls::tls_server_end_point(tls),
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
					challenge_store.clone(),
					config.data_dir.clone(),
					reloadable.clone(),
					u64::from(acme.renew_before_days),
					tlsa,
				));
			}
			None => tracing::warn!("[acme] is configured but [tls] is not; skipping ACME renewal"),
		}
	}

	let mut tasks = Vec::new();
	for listener_config in &config.listeners {
		match listener_config.kind {
			ListenerKind::Api => {
				// Validation guarantees [api] exists for api listeners.
				let api = config
					.api
					.as_ref()
					.ok_or_else(|| std::io::Error::other("api listener without [api] section"))?;
				// Resolve the blob backend the operator configured: a missing
				// or empty `[storage.blobs]` section defaults to the historical
				// on-disk pool at `data_dir`; the S3 backend replaces it when
				// the config names `backend = "s3"`. The constructor fails
				// closed on missing S3 credentials.
				let blob_backend = crate::storage::build_blob_backend(
					&config.data_dir,
					config.storage.as_ref().and_then(|s| s.blobs.as_ref()),
				)?;
				let mut state = crate::api::ApiState::new(
					&api.token_hash,
					config.data_dir.clone(),
					config.domains.clone(),
					Arc::clone(&account_store),
					crate::storage::FsSpool::open_with_crypto(&config.data_dir, crypto.clone())?,
				)
				.with_quota(config.quota_bytes.unwrap_or(0))
				.with_admins(api.admins.clone())
				.with_crypto(crypto.clone())
				.with_directory(directory.clone())
				.with_blob_backend(blob_backend)
				.with_tenant_limits(Arc::clone(&tenant_limits))
				.with_correspondents((*correspondents).clone())
				.with_new_recipients_per_day(daily_new_recipients);
				// Built-in OAuth authorization server, when a signing key is set.
				if let Some(authz) = super::serve_tasks::build_authz_server(&config) {
					state = state.with_authz(authz);
				}
				let listener = super::serve_tasks::bind(listener_config).await?;
				let router = crate::api::router(state);
				tasks.push(tokio::spawn(async move {
					// Serve with the peer address attached so API-key CIDR
					// allowlists can be enforced from `ConnectInfo`.
					axum::serve(
						listener,
						router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
					)
					.await
					.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::Acme => {
				let listener = super::serve_tasks::bind(listener_config).await?;
				let router = crate::acme::http01::router(challenge_store.clone());
				tasks.push(tokio::spawn(async move {
					axum::serve(listener, router)
						.await
						.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::Metrics => {
				let listener = super::serve_tasks::bind(listener_config).await?;
				let metrics = Arc::clone(&metrics);
				let router = axum::Router::new().route(
					"/metrics",
					axum::routing::get(move || {
						let metrics = Arc::clone(&metrics);
						async move {
							(
								[(
									axum::http::header::CONTENT_TYPE,
									"text/plain; version=0.0.4",
								)],
								metrics.render(),
							)
						}
					}),
				);
				tasks.push(tokio::spawn(async move {
					axum::serve(listener, router)
						.await
						.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::Imaps | ListenerKind::Imap => {
				let Some(acceptor) = &tls_acceptor else {
					return Err(std::io::Error::other(
						"IMAP listener without TLS configured",
					));
				};
				let mode = match listener_config.kind {
					ListenerKind::Imap => crate::imap::server::TlsMode::StartTls,
					_ => crate::imap::server::TlsMode::Implicit,
				};
				let listener = super::serve_tasks::bind(listener_config).await?;
				let mut imap_server = crate::imap::server::Server::new(
					&config.hostname,
					config.data_dir.clone(),
					directory.clone(),
					acceptor.clone(),
					mode,
				)
				.with_crypto(crypto.clone())
				.with_retention_days(super::serve_tasks::retention_days(&config));
				if let Some(bytes) = config.quota_bytes {
					imap_server = imap_server.with_quota(bytes);
				}
				if let Some(verifier) = &oauth_verifier {
					imap_server = imap_server.with_oauth(Arc::clone(verifier));
				}
				if let Some(cbind) = &channel_binding {
					imap_server = imap_server.with_channel_binding(cbind.clone());
				}
				imap_server = imap_server.with_max_connections(max_conn);
				tasks.push(tokio::spawn(Arc::new(imap_server).serve(listener)));
			}
			ListenerKind::Pop3s => {
				let Some(acceptor) = &tls_acceptor else {
					return Err(std::io::Error::other(
						"POP3S listener without TLS configured",
					));
				};
				let listener = super::serve_tasks::bind(listener_config).await?;
				let server = Arc::new(
					crate::pop3::server::Server::new(
						config.data_dir.clone(),
						directory.clone(),
						acceptor.clone(),
					)
					.with_crypto(crypto.clone())
					.with_max_connections(max_conn),
				);
				tasks.push(tokio::spawn(server.serve(listener)));
			}
			ListenerKind::Autoconfig => {
				let listener = super::serve_tasks::bind(listener_config).await?;
				let router =
					crate::autodiscovery::router(config.hostname.clone(), config.domains.clone());
				tasks.push(tokio::spawn(async move {
					axum::serve(listener, router)
						.await
						.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::WebDav => {
				let listener = super::serve_tasks::bind(listener_config).await?;
				let router = crate::webdav::router(directory.clone(), config.data_dir.clone());
				tasks.push(super::serve_tasks::serve_http(listener, router));
			}
			ListenerKind::ManageSieve => {
				let Some(acceptor) = &tls_acceptor else {
					return Err(std::io::Error::other(
						"ManageSieve listener without TLS configured",
					));
				};
				let listener = super::serve_tasks::bind(listener_config).await?;
				let server = Arc::new(
					crate::managesieve::server::Server::new(
						config.data_dir.clone(),
						directory.clone(),
						acceptor.clone(),
					)
					.with_max_connections(max_conn),
				);
				tasks.push(tokio::spawn(server.serve(listener)));
			}
			ListenerKind::Smtp | ListenerKind::Submission | ListenerKind::Submissions => {
				let listener = super::serve_tasks::bind(listener_config).await?;
				let mode = match listener_config.kind {
					ListenerKind::Submissions => TlsMode::Implicit,
					_ => TlsMode::Opportunistic,
				};
				let mut server = Server::new(&config.hostname, Arc::clone(&sink))
					.with_directory(directory.clone())
					.with_spf(Arc::clone(&spf_dns))
					.with_dnsbl(
						crate::dnsbl::Dnsbl::new(config.dnsbl_zones.clone())
							.with_domain_zones(config.dnsbl_domain_zones.clone())
							.with_url_zones(config.dnsbl_url_zones.clone()),
					)
					.with_first_time_delay(config.first_time_sender_delay_secs)
					.with_max_connections(max_conn)
					.with_report_dir(config.data_dir.clone());
				if let Some(pool) = &reputation_pool {
					server = server.with_reputation_pool(pool.clone());
					// The corpus key lives under data_dir, encrypted-at-rest tokens.
					match crate::antispam::corpus::BayesStore::open(pool.clone(), &config.data_dir)
					{
						Ok(store) => server = server.with_bayes(store),
						Err(error) => {
							eprintln!("error: cannot open bayes corpus key: {error}");
							return Err(error);
						}
					}
				}
				if let Some(hook) = &scanner_hook {
					server = server.with_hook(Arc::clone(hook));
				}
				// LLM hook only fires when the Bayesian corpus is also wired
				// in: without it the uncertain-band check has nothing to read.
				if let (Some(llm_hook), Some(_)) = (&llm_hook, &reputation_pool) {
					server = server.with_llm(crate::antispam::llm::LlmHook {
						classifier: Arc::clone(&llm_hook.classifier),
						low: llm_hook.low,
						high: llm_hook.high,
					});
				}
				server = server.with_metrics(Arc::clone(&metrics));
				if let Some(sealer) = &arc_sealer {
					server = server.with_arc_sealer(Arc::clone(sealer));
				}
				if let Some(store) = &greylist {
					server = server.with_greylist(Arc::clone(store), config.greylist_delay_secs);
				}
				if let Some(limiter) = &send_limiter {
					server = server.with_send_limiter(Arc::clone(limiter));
				}
				if let Some(limit) = &inbound_ip_limit {
					server = server.with_inbound_ip_limit(crate::smtp::ratelimit::InboundLimit {
						limiter: Arc::clone(&limit.limiter),
						per_min: limit.per_min,
					});
				}
				if let Some(limit) = &inbound_sender_limit {
					server =
						server.with_inbound_sender_limit(crate::smtp::ratelimit::InboundLimit {
							limiter: Arc::clone(&limit.limiter),
							per_min: limit.per_min,
						});
				}
				if !tenant_limits.is_empty() {
					server = server.with_tenant_limits(Arc::clone(&tenant_limits));
				}
				server = server.with_disk_guard(Arc::clone(&disk_guard));
				// Per-account rolling 24h new-recipient cap (plan 4.10).
				// The shared `Arc<CorrespondentStore>` is the one already
				// opened above; the cap itself comes from the static
				// config so it is the same number across every listener.
				server = server.with_correspondents(Arc::clone(&correspondents));
				if daily_new_recipients.is_some() {
					server = server.with_daily_new_recipients(daily_new_recipients);
				}
				if let Some(verifier) = &oauth_verifier {
					server = server.with_oauth(Arc::clone(verifier));
				}
				if let Some(acceptor) = &reloadable_tls {
					server = server.with_tls(acceptor.clone(), mode);
				}
				if let Some(cbind) = &channel_binding {
					server = server.with_channel_binding(cbind.clone());
				}
				tasks.push(tokio::spawn(Arc::new(server).serve(listener)));
			}
		}
	}

	// All privileged ports are now bound; drop OS privileges before serving any
	// connection so a later compromise cannot act as root (no-op when
	// `[privileges]` is unset). Fails closed: a failed drop aborts startup.
	crate::privdrop::drop_privileges(config.privileges.as_ref())?;

	// Run until the first listener fails or a shutdown signal is received.
	let shutdown = async {
		tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
			.expect("register SIGTERM handler")
			.recv()
			.await;
	};
	tokio::select! {
		result = async {
			for task in tasks {
				task.await
					.map_err(|error| std::io::Error::other(error.to_string()))??;
			}
			Ok::<(), std::io::Error>(())
		} => result,
		_ = shutdown => {
			tracing::info!("SIGTERM received, shutting down");
			Ok(())
		}
		_ = tokio::signal::ctrl_c() => {
			tracing::info!("SIGINT received, shutting down");
			Ok(())
		}
	}
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
