//! API state construction.

use super::*;

impl ApiState {
	/// Build the state from configuration data. API keys are loaded from
	/// `api_keys.toml` under `data_dir`; a missing or unreadable file leaves the
	/// key set empty (the configured token still authenticates).
	///
	/// As a one-shot migration, this also runs the JMAP blob-ownership
	/// backfill: writes an `.owner` sidecar for every uploaded blob whose
	/// corresponding message already lives under the account's mailboxes, so
	/// pre-existing data stays servable after the per-account download gate
	/// is introduced. Idempotent: sidecars that already name the right account
	/// are not touched.
	pub fn new(
		token_hash: &str,
		data_dir: PathBuf,
		domains: Vec<String>,
		store: Arc<AccountStore>,
		spool: FsSpool,
	) -> Self {
		Self::new_with_optional_token(Some(token_hash), data_dir, domains, store, spool)
	}

	/// Build an API accepting only labelled keys when `token_hash` is absent.
	pub fn new_with_optional_token(
		token_hash: Option<&str>,
		data_dir: PathBuf,
		domains: Vec<String>,
		store: Arc<AccountStore>,
		spool: FsSpool,
	) -> Self {
		// `ApiKeySet::open` only fails on a parse error or a read error
		// other than NotFound. Either way the operator can recover by
		// editing the file and waiting for the watcher to reload;
		// binding the listener with an empty set keeps the API surface
		// up so the static token still authenticates and a corrected
		// file can be observed on the next poll.
		let api_keys = std::sync::Arc::new(
			crate::api::api_keys::ApiKeySet::open(&data_dir)
				.unwrap_or_else(|_| crate::api::api_keys::ApiKeySet::empty()),
		);
		// One-shot backfill before any handler can serve a download. Runs
		// against every known account; the function itself is bounded by the
		// number of stored messages and per-message work is constant, so a
		// large corpus never blocks startup for more than a few seconds of
		// straight `read_dir` + `fs::write` traffic.
		let account_names: Vec<String> = store
			.account_views()
			.into_iter()
			.map(|(name, _, _)| name)
			.collect();
		let stats = crate::api::jmap::backfill_blob_ownership(&data_dir, &account_names);
		if stats.written > 0 || stats.conflicts > 0 || stats.errors > 0 {
			tracing::info!(
				scanned = stats.scanned,
				written = stats.written,
				skipped = stats.skipped,
				conflicts = stats.conflicts,
				errors = stats.errors,
				"jmap blob-ownership backfill complete"
			);
		}
		ApiState {
			inner: Arc::new(Inner {
				token_hash: token_hash.map(str::to_owned),
				data_dir: data_dir.clone(),
				domains,
				store,
				spool,
				auth_limiter: std::sync::Mutex::new(ClientLimiters::new(AUTH_WINDOW)),
				trusted_proxies: Vec::new(),
				configured_digest: std::sync::OnceLock::new(),
				argon2_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(
					MAX_CONCURRENT_ARGON2,
				)),
				argon2_waiting: std::sync::Mutex::new(auth_queue::QueueSlots::default()),
				argon2_queue_max: MAX_ARGON2_QUEUE,
				#[cfg(test)]
				argon2_stats: Default::default(),
				correspondents: None,
				class_bindings: None,
				identification: crate::smtp::identification::Policy::default(),
				new_recipients_per_day: None,
				admins: Vec::new(),
				quota_limit: std::sync::atomic::AtomicU64::new(
					crate::imap::session::DEFAULT_QUOTA_BYTES,
				),
				api_keys,
				push_subscriptions: std::sync::Mutex::new(Vec::new()),
				caller_slots: Arc::default(),
				crypto: MessageCrypto::disabled(),
				authz: None,
				directory: None,
				legacy_warned: std::sync::Mutex::new(std::collections::HashSet::new()),
				blob_backend: Arc::new(crate::storage::blob_backend::FsBackend::new(data_dir)),
				tenant_limits: TenantLimits::default(),
				submission_limit: None,
				bayes: bayes::BayesBindings::default(),
				outbound: None,
				delivery_log_days: 0,
				webhook: None,
				disabled_domains: Vec::new(),
				max_message_size: crate::smtp::session::MAX_MESSAGE_SIZE,
				max_recipients: crate::smtp::session::DEFAULT_MAX_RECIPIENTS,
			}),
		}
	}
}
