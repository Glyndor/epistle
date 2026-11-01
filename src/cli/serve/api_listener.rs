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
	.with_max_message_size(max_message_size)
	.with_max_recipients(max_recipients)
	.with_quota(
		config
			.quota_bytes
			.unwrap_or(crate::imap::session::DEFAULT_QUOTA_BYTES),
	)
	.with_api_keys(Arc::clone(api_keys_set))
	.with_admins(api.admins.clone())
	.with_trusted_proxies(api.trusted_proxies.clone())
	.with_crypto(crypto.clone())
	.with_directory(directory.clone())
	.with_blob_backend(blob_backend)
	.with_correspondents((**correspondents).clone())
	.with_class_bindings(Arc::clone(&evidence.bindings))
	.with_identification(crate::smtp::identification::Policy::from_config(config))
	.with_new_recipients_per_day(daily_new_recipients)
	.with_outbound(Arc::clone(sink));
	state = ratelimit::wire_api_submission_limits(state, config, send_limiter, tenant_limits);
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
