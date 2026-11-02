use crate::config::{Config, ListenerKind};
use crate::directory_store::FileWatcher;
use crate::smtp::server::{Server, TlsMode};
use std::sync::Arc;
mod api_listener;
mod connection_limits;
pub(super) mod dkim;
mod evidence;
mod listeners;
mod metrics;
mod queue;
mod ratelimit;
mod smtp_state;
mod startup;
mod store;
pub(super) mod tasks;
mod tasks_delivery;
mod tls;
mod webdav;
use dkim::SplitCompanions;
use ratelimit::RateLimiters;
use smtp_state::SmtpSharedState;
use tls::TlsStack;
mod run;
pub use run::run;
async fn serve(config: Config) -> std::io::Result<()> {
	crate::log_id::init(&config.data_dir)?;
	crate::mtasts::publish::write_policy(&config)?;
	tasks::log_single_signature_dkim_warning(&config);
	connection_limits::log_retry_schedule_warnings(&config);
	connection_limits::log_adjusted_values(&config);
	if config.listeners.is_empty() {
		super::style::warn("no listeners configured, nothing to serve");
		return Ok(());
	}
	let ldap_auth = tasks::build_ldap_authenticator(&config);
	let crypto = crate::storage::MessageCrypto::from_config(config.storage.as_ref())
		.map_err(std::io::Error::other)?;
	let mut store = store::open_account_store(&config)?;
	for collision in store.address_collisions() {
		tracing::error!("{collision}");
	}
	if let Some(auth) = ldap_auth {
		store = store.with_ldap_authenticator(auth);
	}
	let metrics = Arc::new(crate::metrics::Metrics::new());
	crate::clock::check_drift(&metrics);
	let reputation_pool = tasks::connect_database(&config, &metrics).await?;
	store = store.with_metrics(metrics.clone());
	let policy = ban_policy::ban_policy_for(&config);
	if let Some(pool) = &reputation_pool {
		store = store.with_ban_store(ban_policy::pg_ban_store(pool, &metrics, policy));
	}
	let account_store = store
		.with_scram_enabled(config.auth.scram)
		.with_password_policy(crate::password::Policy::from_config(&config.auth))
		.with_crypto(crypto.clone())
		.into_shared();
	let directory = account_store.handle();
	let SplitCompanions {
		split,
		dkim_signer,
		webhook,
		arc_sealer,
		mut evidence,
	} = dkim::build_split_with_companions(&config, &metrics, directory.clone(), crypto.clone())?;
	let greylist = tasks::build_greylist(&config, reputation_pool.as_ref()).await;
	let oauth_verifier = crate::cli::oauth::advice::build_and_say(&config).await?;
	let challenge_store = crate::acme::http01::ChallengeStore::new();
	let spf_dns: Arc<dyn crate::spf::DnsLookup> = Arc::new(crate::spf::SystemDns::from_system()?);
	let RateLimiters {
		send_limiter,
		inbound_ip_limit,
		inbound_sender_limit,
	} = ratelimit::build_rate_limiters(&config);
	let SmtpSharedState {
		tenant_limits,
		correspondents,
		daily_new_recipients,
		disk_guard,
		max_conn,
		max_connections_per_ip,
		max_message_size,
		max_recipients,
		memory_budget,
		data_rate,
		session_limits,
		scanner_hook,
		clamd,
		llm_hook,
		attachment_policy,
	} = smtp_state::build_smtp_shared_state(&config, &metrics)?;
	let mailbox_limits = connection_limits::MailboxLimits::from_config(&config);
	let http_limits = connection_limits::http_limits(&config);
	let sink = crate::antispam::submission_scan::ScanningSink::wrap_with_attachments(
		config.antispam.scan_authenticated,
		Arc::new(split),
		clamd,
		attachment_policy.clone(),
		Some(metrics.clone()),
		webhook.clone(),
	)?;
	let bayes = tasks::open_bayes(&config, &reputation_pool, &crypto, &metrics)?;
	tasks::spawn_sql_directory(&config, &reputation_pool, Arc::clone(&account_store)).await?;
	tasks::spawn_ldap_directory(&config, Arc::clone(&account_store)).await?;
	let api_keys_set = startup::api_keys(&config);
	let warmup = queue::open_warmup(&config, &metrics, webhook.as_ref());
	let watcher = FileWatcher::new(config.data_dir.clone(), Arc::clone(&account_store))
		.with_api_keys(Arc::clone(&api_keys_set)
			as Arc<dyn crate::directory_store::file_watcher::ApiKeyReloader>)
		.with_warmup(
			Arc::clone(&warmup) as Arc<dyn crate::directory_store::file_watcher::WarmupReloader>
		)
		.spawn(crate::directory_store::reload_status::POLL_INTERVAL);
	evidence::spawn(evidence.tasks.take());
	queue::spawn_queue_worker(
		&config,
		crypto.clone(),
		Arc::clone(&sink),
		Arc::clone(&spf_dns),
		&metrics,
		webhook.as_ref(),
		warmup,
		Arc::clone(&evidence.service),
	)?;
	tasks::spawn_dmarc_flush(&config, Arc::clone(&spf_dns), Arc::clone(&sink))?;
	tasks::spawn_tlsrpt_reports(&config, Arc::clone(&spf_dns), Arc::clone(&sink))?;
	tasks::spawn_dkim_rotation(&config, &dkim_signer, webhook.as_ref().map(Arc::clone));
	tasks::spawn_alert_engine(
		&config,
		Arc::clone(&metrics),
		webhook.as_ref().map(Arc::clone),
		Arc::new(crate::storage::FsSpool::open_with_crypto(
			&config.data_dir,
			crypto.clone(),
		)?),
	);
	tasks::spawn_storage_maintenance(&config);
	tasks::spawn_ban_sweep(reputation_pool.clone(), policy.known_network_window_secs);
	let TlsStack {
		tls_acceptor,
		reloadable_tls,
		channel_binding,
	} = tls::build_tls(&config, challenge_store.clone())?;
	let ipv4_any_ports = startup::ipv4_any_ports(&config);
	let mut tasks = Vec::new();
	let drain = crate::shutdown::Drain::new();
	for listener_config in &config.listeners {
		match listener_config.kind {
			ListenerKind::Api => {
				let state = api_listener::build(
					&config,
					api_listener::Inputs {
						account_store: &account_store,
						directory: &directory,
						api_keys_set: &api_keys_set,
						crypto: &crypto,
						correspondents: &correspondents,
						evidence: &evidence,
						sink: &sink,
						webhook: &webhook,
						max_message_size,
						max_recipients,
						daily_new_recipients,
						send_limiter: &send_limiter,
						tenant_limits: &tenant_limits,
						bayes: &bayes,
					},
				)?;
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let router = crate::api::router(state);
				tasks.push(tasks::serve_http(listener, router, http_limits));
			}
			ListenerKind::Acme => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let router = crate::acme::http01::router(challenge_store.clone());
				tasks.push(tasks::serve_http(listener, router, http_limits));
			}
			ListenerKind::Metrics => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let router = metrics::router(Arc::clone(&metrics));
				tasks.push(tasks::serve_http(listener, router, http_limits));
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
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let mut imap_server = crate::imap::server::Server::new(
					&config.hostname,
					config.data_dir.clone(),
					directory.clone(),
					acceptor.clone(),
					mode,
				)
				.with_crypto(crypto.clone())
				.with_retention_days(tasks::retention_days(&config));
				if let Some((_, queue)) = &bayes {
					imap_server = imap_server.with_training(queue.clone());
				}
				if let Some(bytes) = config.quota_bytes {
					imap_server = imap_server.with_quota(bytes);
				}
				if let Some(verifier) = &oauth_verifier {
					imap_server = imap_server.with_oauth(Arc::clone(verifier));
				}
				if let Some(cbind) = &channel_binding {
					imap_server = imap_server.with_channel_binding(cbind.clone());
				}
				imap_server = imap_server.with_scram_enabled(config.auth.scram);
				imap_server = imap_server
					.with_max_connections(max_conn)
					.with_max_connections_per_ip(mailbox_limits.per_ip)
					.with_preauth_timeout(mailbox_limits.preauth_timeout)
					.with_append_limit(max_message_size)
					.with_per_account_counter(Arc::clone(&mailbox_limits.per_account_counter));
				imap_server = imap_server.with_drain(Arc::clone(&drain));
				tasks.push(tokio::spawn(Arc::new(imap_server).serve(listener)));
			}
			ListenerKind::Pop3s => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let data_dir = config.data_dir.clone();
				let acceptor = tls_acceptor.as_ref();
				tasks.push(listeners::pop3s(
					listener,
					data_dir,
					directory.clone(),
					acceptor,
					crypto.clone(),
					max_conn,
					&mailbox_limits,
				)?);
			}
			ListenerKind::Autoconfig | ListenerKind::Autoconfigs => {
				let tls = match (listener_config.kind, &reloadable_tls) {
					(ListenerKind::Autoconfig, _) => None,
					(_, Some(reloadable)) => Some(reloadable.https()),
					(_, None) => {
						return Err(std::io::Error::other(
							"autoconfigs listener without TLS configured",
						));
					}
				};
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let router = crate::autodiscovery::router_for(&config);
				let serve =
					crate::autodiscovery::serve(listener, router, tls, max_conn, http_limits);
				tasks.push(tokio::spawn(serve));
			}
			ListenerKind::WebDav => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				tasks.push(webdav::spawn(
					listener,
					&config,
					directory.clone(),
					http_limits,
				));
			}
			ListenerKind::ManageSieve => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
				let data_dir = config.data_dir.clone();
				let acceptor = tls_acceptor.as_ref();
				tasks.push(listeners::managesieve(
					listener,
					data_dir,
					directory.clone(),
					acceptor,
					max_conn,
					&mailbox_limits,
				)?);
			}
			ListenerKind::Smtp | ListenerKind::Submission | ListenerKind::Submissions => {
				let listener = tasks::bind(listener_config, &ipv4_any_ports).await?;
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
					.with_max_connections_per_ip(max_connections_per_ip)
					.with_max_message_size(max_message_size)
					.with_max_recipients(max_recipients)
					.with_identification(crate::smtp::identification::Policy::from_config(&config))
					.with_data_rate(data_rate)
					.with_session_limits(session_limits)
					.with_report_dir(config.data_dir.clone())
					.with_data_dir(config.data_dir.clone())
					.with_crypto(Arc::new(crypto.clone()));
				if let Some(pool) = &reputation_pool {
					server = server.with_reputation_pool(pool.clone());
					if let Some((store, _)) = &bayes {
						server = server.with_bayes(Arc::new(store.clone()));
					}
				}
				if let Some(hook) = &scanner_hook {
					server = server.with_hook(Arc::clone(hook));
				}
				server = server.with_attachment_policy(attachment_policy.clone());
				if let (Some(llm_hook), Some(_)) = (&llm_hook, &reputation_pool) {
					server = server.with_llm(crate::antispam::llm::LlmHook {
						classifier: Arc::clone(&llm_hook.classifier),
						low: llm_hook.low,
						high: llm_hook.high,
					});
				}
				if let Some(pass) = startup::subjectpass(&config, reputation_pool.is_some())? {
					server = server.with_subjectpass(pass);
				}
				server = server.with_metrics(Arc::clone(&metrics));
				if let Some(sealer) = &arc_sealer {
					server = server.with_arc_sealer(Arc::clone(sealer));
				}
				if let Some(store) = &greylist {
					server = server.with_greylist(Arc::clone(store), config.greylist_delay_secs);
				}
				server = server.with_bayes_thresholds(
					config.antispam.bayes_junk_at,
					config.antispam.bayes_reject_at,
				);
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
				server = ratelimit::wire_smtp_submission_limits(
					server,
					&config,
					&send_limiter,
					if tenant_limits.is_empty() {
						None
					} else {
						Some(&tenant_limits)
					},
				);
				server = server.with_disk_guard(Arc::clone(&disk_guard));
				server = server.with_quota(Arc::new(crate::smtp::quota::MailboxQuota::on_disk(
					config.data_dir.clone(),
					crypto.clone(),
					config
						.quota_bytes
						.unwrap_or(crate::imap::session::DEFAULT_QUOTA_BYTES),
				)));
				server = server
					.with_correspondents(Arc::clone(&correspondents))
					.with_class_bindings(Arc::clone(&evidence.bindings));
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
				server = server.with_scram_enabled(config.auth.scram);
				server = server.with_drain(Arc::clone(&drain));
				if let Some(budget) = memory_budget.as_ref() {
					server = server.with_memory_budget(Arc::clone(budget));
				}
				tasks.push(tokio::spawn(Arc::new(server).serve(listener)));
			}
		}
	}
	crate::privdrop::drop_privileges(config.privileges.as_ref())?;
	let stopped = wait::until_stopped(tasks, &drain).await;
	watcher.abort();
	let _ = watcher.await;
	crate::directory_store::remove_reload_status(&config.data_dir);
	stopped
}
mod ban_policy;
#[cfg(test)]
mod tests;
mod wait;
