//! The `serve` command: bind listeners and run until interrupted.

use std::process::ExitCode;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::config::{Config, ListenerKind};
use crate::smtp::server::{Server, TlsMode};
use crate::smtp::sink::MessageSink;
use crate::storage::SplitDelivery;

/// Run the server with a validated configuration.
pub fn run(config: Config) -> ExitCode {
	let filter = tracing_subscriber::EnvFilter::try_from_default_env()
		.unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
	let builder = tracing_subscriber::fmt().with_env_filter(filter);
	match config.log_format {
		crate::config::LogFormat::Json => builder.json().init(),
		crate::config::LogFormat::Text => builder.init(),
	}

	let runtime = match tokio::runtime::Runtime::new() {
		Ok(runtime) => runtime,
		Err(error) => {
			eprintln!("error: cannot start async runtime: {error}");
			return ExitCode::FAILURE;
		}
	};
	match runtime.block_on(serve(config)) {
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
		.map_err(|error| std::io::Error::other(error.to_string()))?,
	);
	let directory = account_store.handle();

	// Shared metrics across SMTP listeners, delivery, and the metrics endpoint.
	let metrics = Arc::new(crate::metrics::Metrics::new());

	// Local recipients go to account mailboxes; authenticated relay mail
	// is queued in the outbound spool, DKIM-signed when configured.
	let mut split = SplitDelivery::new(&config.data_dir, directory.clone())?
		.with_rules(config.rules.clone())
		.with_metrics(metrics.clone());
	if let Some(dkim) = &config.dkim {
		let mut signer = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file)
			.map_err(std::io::Error::other)?;
		if let (Some(selector), Some(key_file)) = (&dkim.rsa_selector, &dkim.rsa_key_file) {
			signer = signer
				.with_rsa(selector, key_file)
				.map_err(std::io::Error::other)?;
		}
		split = split.with_signer(Arc::new(signer));
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

	// Optional ARC sealer: seals inbound mail under the server hostname using
	// a DKIM-format ed25519 key. Failure to load is fatal (fail closed).
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

	// Optional OAuth2/OIDC token verifier for OAUTHBEARER/XOAUTH2. A malformed
	// configuration is fatal (fail closed rather than silently disable it).
	let oauth_verifier = match &config.oauth {
		Some(oauth) => Some(Arc::new(
			crate::oauth::OauthVerifier::new(
				&oauth.issuer,
				&oauth.audience,
				&oauth.algorithm,
				&oauth.public_key,
			)
			.map_err(|e| std::io::Error::other(format!("oauth config: {e:?}")))?,
		)),
		None => None,
	};

	// ACME HTTP-01 challenge store, shared by the responder listener and (later)
	// the renewal task that publishes key authorizations into it.
	let challenge_store = crate::acme::http01::ChallengeStore::new();

	// SPF verification for unauthenticated inbound mail.
	let spf_dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(crate::spf::SystemDns::from_system()?);

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
	.with_metrics(metrics.clone());
	if let Some(webhook) = &webhook {
		worker = worker.with_webhook(Arc::clone(webhook));
	}
	let worker = Arc::new(worker);
	tokio::spawn(worker.run(std::time::Duration::from_secs(30)));

	// DMARC aggregate report flush: once per hour, queue reports for
	// completed days that have accumulated delivery records.
	{
		let data_dir = config.data_dir.clone();
		let hostname = config.hostname.clone();
		let spool = crate::storage::FsSpool::open(&config.data_dir)?;
		let dns = Arc::clone(&spf_dns);
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
					dns.as_ref(),
				)
				.await;
				for message in messages {
					if let Err(e) = spool.store(&message) {
						tracing::warn!(%e, "failed to queue DMARC report");
					}
				}
			}
		});
	}

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

	// ACME automatic renewal: obtain/renew certificates and hot-reload the SMTP
	// acceptor. Requires a [tls] bootstrap certificate to reload into.
	if let Some(acme) = &config.acme {
		match &reloadable_tls {
			Some(reloadable) => {
				tokio::spawn(crate::acme::renew::run(
					acme.directory_url.clone(),
					acme.contacts.clone(),
					acme.domains.clone(),
					challenge_store.clone(),
					config.data_dir.clone(),
					reloadable.clone(),
					u64::from(acme.renew_before_days),
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
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let router = crate::api::router(state);
				tasks.push(tokio::spawn(async move {
					axum::serve(listener, router)
						.await
						.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::Acme => {
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let router = crate::acme::http01::router(challenge_store.clone());
				tasks.push(tokio::spawn(async move {
					axum::serve(listener, router)
						.await
						.map_err(std::io::Error::other)
				}));
			}
			ListenerKind::Metrics => {
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
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
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
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
				tasks.push(tokio::spawn(Arc::new(imap_server).serve(listener)));
			}
			ListenerKind::Pop3s => {
				let Some(acceptor) = &tls_acceptor else {
					return Err(std::io::Error::other(
						"POP3S listener without TLS configured",
					));
				};
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let server = Arc::new(crate::pop3::server::Server::new(
					config.data_dir.clone(),
					directory.clone(),
					acceptor.clone(),
				));
				tasks.push(tokio::spawn(server.serve(listener)));
			}
			ListenerKind::Smtp | ListenerKind::Submission | ListenerKind::Submissions => {
				let addr = listener_config.socket_addr();
				let listener = TcpListener::bind(addr).await?;
				tracing::info!(%addr, kind = ?listener_config.kind, "listening");
				let mode = match listener_config.kind {
					ListenerKind::Submissions => TlsMode::Implicit,
					_ => TlsMode::Opportunistic,
				};
				let mut server = Server::new(&config.hostname, Arc::clone(&sink))
					.with_directory(directory.clone())
					.with_spf(Arc::clone(&spf_dns))
					.with_dnsbl(crate::dnsbl::Dnsbl::new(config.dnsbl_zones.clone()))
					.with_first_time_delay(config.first_time_sender_delay_secs)
					.with_report_dir(config.data_dir.clone());
				if let Some(pool) = &reputation_pool {
					server = server.with_reputation_pool(pool.clone());
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
				if let Some(verifier) = &oauth_verifier {
					server = server.with_oauth(Arc::clone(verifier));
				}
				if let Some(acceptor) = &reloadable_tls {
					server = server.with_tls(acceptor.clone(), mode);
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
