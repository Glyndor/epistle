//! Production API state, including optional static authentication.

use super::{ratelimit, tasks};
use crate::config::Config;
use std::sync::Arc;

pub(super) struct Inputs<'a> {
	pub account_store: &'a Arc<crate::directory_store::AccountStore>,
	pub directory: &'a crate::directory_store::DirectoryHandle,
	pub api_keys_set: &'a Arc<crate::api::ApiKeySet>,
	pub crypto: &'a crate::storage::MessageCrypto,
	pub correspondents: &'a Arc<crate::storage::CorrespondentStore>,
	pub evidence: &'a super::evidence::Evidence,
	pub sink: &'a Arc<dyn crate::smtp::sink::MessageSink>,
	pub webhook: &'a Option<Arc<crate::webhook::Webhook>>,
	pub max_message_size: usize,
	pub max_recipients: usize,
	pub daily_new_recipients: Option<u32>,
	pub send_limiter: &'a Option<Arc<crate::smtp::ratelimit::SendLimiter>>,
	pub tenant_limits: &'a Arc<crate::api::TenantLimits>,
	pub bayes: &'a Option<(
		crate::antispam::corpus::BayesStore,
		crate::antispam::training_queue::TrainingQueue,
	)>,
	/// The hosted-domain state the routes answer with and write through.
	pub live: &'a Arc<crate::editable::LiveConfig>,
	/// The ban store the ban routes manage, with a `[database]`.
	pub ban_admin: &'a Option<Arc<dyn crate::antispam::bans::operator::BanAdmin>>,
	/// Where the configuration was read from, which the health routes name.
	pub config_path: &'a Option<std::path::PathBuf>,
	/// The places for health runs, shared by every API listener.
	pub health_gate: &'a crate::api::HealthGate,
}

/// The state every listener that serves the API shares: built for the first,
/// cloned for the others, so a limit or a counter means the same on all of them.
pub(super) fn shared(
	slot: &mut Option<crate::api::ApiState>,
	config: &Config,
	inputs: Inputs<'_>,
) -> std::io::Result<crate::api::ApiState> {
	if let Some(state) = slot {
		return Ok(state.clone());
	}
	let built = build(config, inputs)?;
	*slot = Some(built.clone());
	Ok(built)
}

pub(super) fn build(config: &Config, inputs: Inputs<'_>) -> std::io::Result<crate::api::ApiState> {
	let Inputs {
		account_store,
		directory,
		api_keys_set,
		crypto,
		correspondents,
		evidence,
		sink,
		webhook,
		max_message_size,
		max_recipients,
		daily_new_recipients,
		send_limiter,
		tenant_limits,
		bayes,
		live,
		ban_admin,
		config_path,
		health_gate,
	} = inputs;
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
	let mut state = crate::api::ApiState::new_with_optional_token(
		api.token_hash.as_deref(),
		config.data_dir.clone(),
		config.domains.clone(),
		Arc::clone(account_store),
		crate::storage::FsSpool::open_with_crypto(&config.data_dir, crypto.clone())?,
	)
	.with_delivery_log_days(config.delivery_log_days())
	.with_webhook(webhook.clone())
	.with_disabled_domains(config.disabled_domains.clone())
	.with_domain_catalog(crate::domain::catalog::Catalog::from_config(config))
	.with_live_domains(Arc::clone(live))
	.with_max_message_size(max_message_size)
	.with_max_recipients(max_recipients)
	.with_event_limits(event_limits(api))
	.with_quota(
		config
			.quota_bytes
			.unwrap_or(crate::imap::session::DEFAULT_QUOTA_BYTES),
	)
	.with_api_keys(Arc::clone(api_keys_set))
	.with_admins(api.admins.clone())
	.with_trusted_proxies(api.trusted_proxies.clone())
	.with_auth_limits(&api.limiter)
	.with_crypto(crypto.clone())
	.with_directory(directory.clone())
	.with_blob_backend(blob_backend)
	.with_correspondents((**correspondents).clone())
	.with_class_bindings(Arc::clone(&evidence.bindings))
	.with_identification(crate::smtp::identification::Policy::from_config(config))
	.with_new_recipients_per_day(daily_new_recipients)
	.with_outbound(Arc::clone(sink));
	state = ratelimit::wire_api_submission_limits(state, config, send_limiter, tenant_limits);
	state = state.with_health_gate(health_gate.clone());
	if let Some(path) = config_path {
		state = state.with_config_path(path.clone());
	}
	if let Some(admin) = ban_admin {
		state = state.with_ban_admin(Arc::clone(admin));
	}
	if let Some((store, queue)) = bayes {
		state = state
			.with_training(queue.clone())
			.with_bayes_store(store.clone());
	}
	// Built-in OAuth authorization server, when a signing key is set.
	if let Some(authz) = tasks::build_authz_server(config)? {
		state = state.with_authz(authz);
	}
	Ok(state)
}

/// The bounds on the admin event stream: the operator's, and the defaults for
/// what `[api]` leaves out.
fn event_limits(api: &crate::config::Api) -> crate::api::EventLimits {
	let defaults = crate::api::EventLimits::default();
	crate::api::EventLimits {
		per_key: api.event_streams_per_key.unwrap_or(defaults.per_key),
		per_server: api.event_streams_per_server.unwrap_or(defaults.per_server),
		max_lifetime: api
			.event_stream_max_secs
			.map_or(defaults.max_lifetime, std::time::Duration::from_secs),
		..defaults
	}
}
