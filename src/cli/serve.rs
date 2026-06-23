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
	// API-managed dynamic accounts, hot-swapped on mutation.
	let account_store = Arc::new(
		crate::directory_store::AccountStore::open(
			&config.data_dir,
			config.domains.clone(),
			config.domain_aliases.clone(),
			config.accounts.clone(),
		)
		.map_err(|error| std::io::Error::other(error.to_string()))?
		.with_domain_quotas(config.domain_quotas.clone())
		.with_aliases(config.alias.clone()),
	);
	let directory = account_store.handle();

	// Shared metrics across SMTP listeners, delivery, and the metrics endpoint.
	let metrics = Arc::new(crate::metrics::Metrics::new());

	// Local recipients go to account mailboxes; authenticated relay mail
	// is queued in the outbound spool, DKIM-signed when configured.
	let mut split = SplitDelivery::new(&config.data_dir, directory.clone())?
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
	let arc_sealer = match &config.arc {
		Some(arc) => {
			let key =
				crate::dkim::load_ed25519_key(&arc.key_file).map_err(std::io::Error::other)?;
			Some(Arc::new(crate::arc::sealer::ArcSealer::new(
				key,
				config.hostname.clone(),
				arc.selector.clone(),
			)))
		}
		None => None,
	};
	if let Some(sealer) = &arc_sealer {
		split = split.with_arc_sealer(Arc::clone(sealer));
	}
	let sink: Arc<dyn MessageSink> = Arc::new(split);

	// Optional greylisting store, shared across SMTP listeners. A background
	// task prunes stale triplets so the map stays bounded.
	let greylist = (config.greylist_delay_secs > 0).then(|| {
		let store = Arc::new(crate::antispam::greylist::MemoryGreylist::new());
		let prune_store = Arc::clone(&store);
		tokio::spawn(async move {
			let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
			loop {
				interval.tick().await;
				let now = std::time::SystemTime::now()
					.duration_since(std::time::UNIX_EPOCH)
					.map(|d| d.as_secs())
					.unwrap_or(0);
				prune_store.prune(now, 86_400);
			}
		});
		store
	});

	// Optional OAuth2/OIDC token verifier for OAUTHBEARER/XOAUTH2. A malformed
	// configuration is fatal (fail closed rather than silently disable it). With
	// OIDC discovery this fetches the JWKS and spawns the hourly refresh task.
	let oauth_verifier = super::serve_tasks::build_oauth_verifier(&config).await?;

	// ACME HTTP-01 challenge store, shared by the responder listener and (later)
	// the renewal task that publishes key authorizations into it.
	let challenge_store = crate::acme::http01::ChallengeStore::new();

	// SPF verification for unauthenticated inbound mail.
	let spf_dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(crate::spf::SystemDns::from_system()?);

	// Optional per-account submission rate limiter, shared across SMTP listeners.
	let send_limiter = config
		.submission_rate_limit_per_min
		.map(|per_min| Arc::new(crate::smtp::ratelimit::SendLimiter::new(per_min, 60)));

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

	// Optional reputation database, migrated at startup.
	let reputation_pool = match &config.database {
		Some(db) => Some(
			crate::db::connect(&db.url, db.max_connections)
				.await
				.map_err(std::io::Error::other)?,
		),
		None => None,
	};

	// The queue worker drains the outbound spool in the background.
	let connector = Arc::new(crate::queue::MxConnector::from_system()?);
	let mta_sts = Arc::new(crate::mtasts::PolicyStore::new(Box::new(
		crate::mtasts::SystemFetcher::new().map_err(|error| {
			std::io::Error::other(format!("cannot build MTA-STS fetcher: {error:?}"))
		})?,
	)));
	let mut worker = crate::queue::Worker::new(
		crate::storage::FsSpool::open(&config.data_dir)?,
		connector,
		&config.hostname,
	)
	.with_bounce_sink(Arc::clone(&sink))
	.with_mta_sts(mta_sts, Arc::clone(&spf_dns))
	.with_dane(Arc::clone(&spf_dns))
	.with_metrics(metrics.clone())
	.with_max_age(config.queue_give_up_secs.unwrap_or(0))
	.with_suppression(crate::queue::SuppressionList::open(&config.data_dir)?)
	.with_transports(config.transport.clone());
	if let Some(webhook) = &webhook {
		worker = worker.with_webhook(Arc::clone(webhook));
	}
	let worker = Arc::new(worker);
	tokio::spawn(worker.run(std::time::Duration::from_secs(30)));

	// DMARC aggregate report flush runs hourly in the background.
	super::serve_tasks::spawn_dmarc_flush(&config, Arc::clone(&spf_dns))?;

	super::serve_tasks::spawn_dkim_rotation(&config, &dkim_signer);

	super::serve_tasks::spawn_blob_reclamation(&config);

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
				let state = crate::api::ApiState::new(
					&api.token_hash,
					config.data_dir.clone(),
					config.domains.clone(),
					Arc::clone(&account_store),
					crate::storage::FsSpool::open(&config.data_dir)?,
				)
				.with_quota(config.quota_bytes.unwrap_or(0));
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
				);
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
					.with_dnsbl(crate::dnsbl::Dnsbl::new(config.dnsbl_zones.clone()))
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
mod tests {
	use super::*;
	use std::net::{IpAddr, Ipv4Addr};
	use std::path::Path;

	use crate::config::Listener;
	use crate::smtp::sink::MemorySink;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	fn test_config(data_dir: &Path, listeners: Vec<Listener>) -> Config {
		let toml = format!(
			"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
			data_dir.display()
		);
		let mut config: Config = toml::from_str(&toml).expect("base config");
		config.listeners = listeners;
		config
	}

	#[test]
	fn run_with_no_listeners_exits_cleanly() {
		let dir = tempfile::tempdir().expect("tempdir");
		assert_eq!(run(test_config(dir.path(), vec![])), ExitCode::SUCCESS);
	}

	#[tokio::test]
	async fn serve_binds_and_answers() {
		// Port 0 lets the OS pick a free port; we then talk to it.
		let listener = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
			.await
			.expect("bind");
		let addr = listener.local_addr().expect("addr");

		let sink: Arc<dyn MessageSink> = Arc::new(MemorySink::new());
		let server = Arc::new(Server::new("mail.example.org", sink));
		let task = tokio::spawn(server.serve(listener));

		let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
		let mut buffer = [0u8; 64];
		let read = client.read(&mut buffer).await.expect("greeting");
		assert!(String::from_utf8_lossy(&buffer[..read]).starts_with("220 "));
		client.write_all(b"QUIT\r\n").await.expect("quit");
		task.abort();
	}

	#[tokio::test]
	async fn serve_fails_on_unbindable_address() {
		// Two listeners on the same port: the second bind must fail.
		let probe = TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
			.await
			.expect("probe bind");
		let port = probe.local_addr().expect("addr").port();

		let dir = tempfile::tempdir().expect("tempdir");
		let listener: Listener =
			toml::from_str(&format!("kind = \"smtp\"\nport = {port}")).expect("listener config");
		let config = test_config(dir.path(), vec![listener]);
		assert!(serve(config).await.is_err());
	}

	#[tokio::test]
	async fn serve_fails_on_unwritable_data_dir() {
		let listener: Listener = toml::from_str("kind = \"smtp\"\nport = 0").expect("listener");
		let config = test_config(Path::new("/proc/no-such-dir"), vec![listener]);
		assert!(serve(config).await.is_err());
	}
}
