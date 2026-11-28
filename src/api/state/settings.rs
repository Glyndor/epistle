//! API state settings.

use super::*;

impl ApiState {
	/// The retention window the operator configured for the per-recipient
	/// delivery log. `None` when the API was built without a config (the
	/// unit tests that exercise other handlers) and `Some(0)` when the
	/// operator explicitly disabled the log.
	pub fn delivery_log_days(&self) -> Option<u64> {
		Some(self.inner.delivery_log_days)
	}

	/// Configure the retention window the deliveries handler reads from.
	/// `0` disables the log (a `404` from the handler); any positive
	/// value opts in. Must be set before the state is shared.
	pub fn with_delivery_log_days(mut self, days: u64) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.delivery_log_days = days;
		}
		self
	}

	/// Attach the configured webhook used for queue cancellation events.
	pub fn with_webhook(mut self, webhook: Option<Arc<crate::webhook::Webhook>>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.webhook = webhook;
		}
		self
	}

	pub(crate) fn webhook(&self) -> Option<&Arc<crate::webhook::Webhook>> {
		self.inner.webhook.as_ref()
	}

	/// Name the hosted domains that are switched off. Must be set before the
	/// state is shared.
	pub fn with_disabled_domains(self, domains: Vec<String>) -> Self {
		let hosted = self.hosted();
		self.set_hosted(hosted::HostedView::hosting(hosted.domains.clone(), domains));
		self
	}

	/// Describe the hosted domains from the configuration file the server
	/// started with, so the domain routes answer what `epistle domain show`
	/// prints. Without it they know only the domains and which are switched
	/// off. Must be set before the state is shared.
	pub fn with_domain_catalog(self, catalog: crate::domain::catalog::Catalog) -> Self {
		let hosted = self.hosted();
		self.set_hosted(hosted::HostedView {
			catalog,
			..(*hosted).clone()
		});
		self
	}

	/// What each hosted domain is.
	pub fn domain_catalog(&self) -> crate::domain::catalog::Catalog {
		self.hosted().catalog.clone()
	}

	/// The hosted domains that are switched off: they stay in
	/// [`ApiState::domains`] but take no mail.
	pub fn disabled_domains(&self) -> Vec<String> {
		self.hosted().disabled.clone()
	}

	/// The per-instance message-size cap. Defaults to
	/// [`crate::smtp::session::MAX_MESSAGE_SIZE`]; operators raise or
	/// lower it with the `max_message_size` config key.
	pub fn max_message_size(&self) -> usize {
		self.inner.max_message_size
	}

	/// Override the per-instance message-size cap. Used by `serve` to
	/// apply the operator's `max_message_size`. Must be set
	/// before the state is shared. `0` keeps the default.
	pub fn with_max_message_size(mut self, bytes: usize) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner)
			&& bytes > 0
		{
			inner.max_message_size = bytes;
		}
		self
	}

	/// How many recipients one message may name through the REST send
	/// endpoint and JMAP `EmailSubmission/set`.
	pub fn max_recipients(&self) -> usize {
		self.inner.max_recipients
	}

	/// Override the per-message recipient cap. Used by `serve` to apply the
	/// operator's `max_recipients`. Must be set before the state is shared.
	/// `0` keeps the default.
	pub fn with_max_recipients(mut self, count: usize) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner)
			&& count > 0
		{
			inner.max_recipients = count;
		}
		self
	}

	/// What a dry run of the send endpoint is charged to.
	pub(crate) fn dry_run_limits(&self) -> &crate::api::v1::send_dry_limits::Limits {
		&self.inner.dry_run
	}

	/// Set how many recipients one account may dry-run in a minute and how
	/// many addresses it never wrote to in a day. Must be set before the state
	/// is shared; a zero keeps the default.
	pub fn with_dry_run_limits(mut self, per_minute: u32, new_per_day: u32) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner)
			&& per_minute > 0
			&& new_per_day > 0
		{
			inner.dry_run = crate::api::v1::send_dry_limits::Limits::new(per_minute, new_per_day);
		}
		self
	}

	/// Apply `[api.limiter]`: the failure budgets of the bearer limiter and
	/// the size of the argon2 gate. Must be set before the state is shared.
	pub fn with_auth_limits(mut self, limits: &crate::config::ApiLimiter) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.auth_limiter = std::sync::Mutex::new(ClientLimiters::from_config(limits));
			inner.argon2_gate =
				Arc::new(tokio::sync::Semaphore::new(limits.max_concurrent_hashes()));
			inner.argon2_queue_max = limits.hash_queue();
		}
		self
	}

	/// Attach the built-in OAuth authorization server. Must be set before the
	/// state is shared (it rebuilds the `Arc` inner). When unset, the `/oauth/*`
	/// grant routes are absent and no tokens are issued.
	pub fn with_authz(mut self, authz: crate::api::oauth::AuthzServer) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.authz = Some(Arc::new(authz));
		}
		self
	}

	/// The built-in OAuth authorization server, when configured.
	pub fn authz(&self) -> Option<&crate::api::oauth::AuthzServer> {
		self.inner.authz.as_deref()
	}

	/// Attach a different blob backend. Must be set before the state is
	/// shared (it rebuilds the `Arc` inner). The default at construction
	/// time is the on-disk pool at the configured `data_dir`; calling this
	/// before the listener starts swaps in the operator-configured S3
	/// backend.
	pub fn with_blob_backend(mut self, backend: Arc<dyn crate::storage::BlobBackend>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.blob_backend = backend;
		}
		self
	}

	/// The blob backend serving this server. The upload and download
	/// handlers go through this for every read and write; they do not know
	/// whether the bytes end up on disk or in an S3 bucket.
	pub fn blob_backend(&self) -> &Arc<dyn crate::storage::BlobBackend> {
		&self.inner.blob_backend
	}

	/// Authenticate `login`/`password` against the account directory, returning
	/// the resolved account identity. Used by the OAuth approval/authorize
	/// endpoints to bind a grant to a real account. Fail-closed and free of any
	/// user-enumeration oracle (see [`crate::smtp::directory::Directory::authenticate`]).
	///
	/// `protocol` tags the call site so an account with a per-account
	/// `allowed_protocols` set is rejected when this caller is not in the
	/// set; the wire response is then identical to an unknown login.
	///
	/// Use [`ApiState::authenticate_with_ip`] when the request carries the
	/// peer IP — the audit log attributes every authentication attempt to its
	/// source IP, which is what the future IP-banning and credential-stuffing
	/// detectors consume.
	pub fn authenticate(
		&self,
		login: &str,
		password: &str,
		protocol: crate::config::Protocol,
	) -> Option<String> {
		self.authenticate_with_ip(login, password, None, protocol)
	}

	/// Authenticate `login`/`password` and attribute the attempt to `ip` in
	/// the audit log. `None` for `ip` is the same as
	/// [`ApiState::authenticate`]: the peer address was not available to the
	/// caller, so it is logged as `unknown`. The audit counters are bumped
	/// from the same path either way. `protocol` is forwarded to the
	/// directory so a restricted account cannot authenticate through this
	/// path.
	pub fn authenticate_with_ip(
		&self,
		login: &str,
		password: &str,
		ip: Option<std::net::IpAddr>,
		protocol: crate::config::Protocol,
	) -> Option<String> {
		self.inner
			.store
			.handle()
			.current()
			.authenticate_with_ip(login, password, ip, protocol)
	}

	/// Set the account names allowed to authenticate to the admin panel. Must be
	/// set before the state is shared (it rebuilds the `Arc` inner).
	pub fn with_admins(mut self, admins: Vec<String>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.admins = admins;
		}
		self
	}

	/// Whether a resolved account name carries the admin-panel privilege.
	pub fn is_admin(&self, name: &str) -> bool {
		self.inner.admins.iter().any(|admin| admin == name)
	}

	/// The currently loaded API keys. Read-only snapshot; callers that
	/// need to look up the key matching a token use this and walk the
	/// snapshot themselves.
	pub fn api_keys(&self) -> &std::sync::Arc<crate::api::api_keys::ApiKeySet> {
		&self.inner.api_keys
	}

	/// Replace the at-rest crypto used for stored messages and blobs. Must be set
	/// before the state is shared (it rebuilds the `Arc` inner).
	pub fn with_crypto(mut self, crypto: MessageCrypto) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.crypto = crypto;
		}
		self
	}

	/// The at-rest crypto for stored messages and uploaded blobs.
	pub fn crypto(&self) -> &MessageCrypto {
		&self.inner.crypto
	}

	/// Attach the hot-reloadable directory used for send-as ownership checks
	/// on the API path. Must be set before the state is shared (it rebuilds
	/// the `Arc` inner). When never attached, every `owns_address` call returns
	/// `false` (fail closed).
	pub fn with_directory(mut self, directory: DirectoryHandle) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.directory = Some(directory);
		}
		self
	}

	/// The live directory, when one is wired.
	pub(crate) fn directory_snapshot(
		&self,
	) -> Option<std::sync::Arc<crate::smtp::directory::Directory>> {
		self.inner.directory.as_ref().map(|handle| handle.current())
	}

	/// Whether `account` owns `address` — used to enforce send-as on the API
	/// path the same way SMTP does (`src/smtp/session/mod.rs`). Fail-closed:
	/// returns `false` when no directory has been attached (e.g. in tests or
	/// if a future deployment forgets to wire it in), never `true`. The SMTP
	/// path also delegates to `Directory::owns_address`, so the API and the
	/// SMTP submission path can never disagree on ownership.
	pub fn owns_address(&self, account: &str, address: &Address) -> bool {
		match &self.inner.directory {
			None => false,
			Some(handle) => handle.current().owns_address(account, address),
		}
	}

	/// Whether `account` may send mail: the per-account send switch, the one
	/// SMTP submission reads. Only an account that was switched off is
	/// refused. With no directory attached nothing is switched off here, and
	/// `owns_address` still fails closed, so no sender is ever accepted.
	pub fn can_send(&self, account: &str) -> bool {
		match &self.inner.directory {
			None => true,
			Some(handle) => handle.current().can_send(account),
		}
	}

	/// Set the server default per-account storage quota in bytes, the
	/// configured `quota_bytes` (0 = unlimited). Without this call the
	/// documented 5 GiB default applies, as in IMAP.
	pub fn with_quota(self, bytes: u64) -> Self {
		self.inner
			.quota_limit
			.store(bytes, std::sync::atomic::Ordering::Relaxed);
		self
	}

	/// Replace the key set the bearer middleware reads. The default
	/// (set by [`ApiState::new`]) loads `api_keys.toml` once at
	/// construction and is never updated; the file watcher calls
	/// [`crate::api::api_keys::ApiKeySet::reload_file`] on `set` whenever
	/// `api_keys.toml` changes, so a server that needs hot-reloadable
	/// keys must pass the same `Arc<ApiKeySet>` it gave to the
	/// watcher. Must be called before the state is shared (the
	/// builder quietly no-ops when the `Arc` is already taken,
	/// mirroring `with_authz`).
	pub fn with_api_keys(mut self, set: std::sync::Arc<crate::api::api_keys::ApiKeySet>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.api_keys = set;
		}
		self
	}
}
