//! Shared API state and bearer-token authentication.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::directory_store::{AccountStore, DirectoryHandle, MaskedAddressStore};
use crate::smtp::address::Address;
use crate::storage::{FsSpool, MessageCrypto};

use super::api_keys::Scope;
use super::error::ApiError;
use super::tenant_limits::TenantLimits;

/// The bearer credentials the middleware extracted from the request, stashed
/// in request extensions so handlers can apply a fine-grained scope check on
/// top of the coarse path/method inference the middleware already did.
#[derive(Clone)]
pub struct MatchedAuth {
	/// The raw bearer token as presented by the client, or `None` for
	/// unauthenticated routes (which never reach the API surface).
	pub token: Option<String>,
	/// The peer IP, when the listener was started with `ConnectInfo`. `None`
	/// means the IP is unknown; an IP-restricted key cannot match in that
	/// case (fail-closed).
	pub client_ip: Option<std::net::IpAddr>,
	/// Whether `token` is the configured static token. Decided once, by the
	/// middleware: the configured hash may be a legacy argon2id one, and
	/// nothing after it compares the bearer against that hash again.
	pub configured: bool,
}

/// State shared by every handler.
#[derive(Clone)]
pub struct ApiState {
	inner: Arc<Inner>,
}

struct Inner {
	/// Token hash: either `sha256:<lowercase-hex>` or a legacy argon2id PHC string.
	token_hash: String,
	data_dir: PathBuf,
	domains: Vec<String>,
	store: Arc<AccountStore>,
	spool: FsSpool,
	auth_limiter: std::sync::Mutex<ClientLimiters>,
	/// SHA-256 of the configured token, set the first time the legacy argon2
	/// hash verified it; from then on a bearer is compared by digest.
	configured_digest: std::sync::OnceLock<[u8; 32]>,
	/// Limits how many argon2 verifications of the configured token run at
	/// once. A request past the limit waits for its turn, it is not refused.
	argon2_gate: std::sync::Arc<tokio::sync::Semaphore>,
	/// Requests waiting for the gate; past [`MAX_ARGON2_QUEUE`] they are refused.
	argon2_waiting: std::sync::atomic::AtomicUsize,
	argon2_queue_max: usize,
	/// Test-only: argon2 runs started, running now, and the most at once.
	#[cfg(test)]
	argon2_stats: [std::sync::atomic::AtomicUsize; 3],
	/// Per-account correspondent store: which addresses the account has
	/// previously written to. The rolling 24h cap on first-time
	/// recipients (`new_recipients_per_day`) reads from and writes to
	/// this; tests can swap it out via [`ApiState::with_correspondents`]
	/// so the same test tempdir is reused across handlers.
	correspondents: Option<crate::storage::CorrespondentStore>,
	class_bindings: Option<Arc<crate::evidence::bindings::BindingSet>>,
	/// Cap on first-time recipients per account in any rolling 24h window.
	/// `None` disables the cap (the default). Lives on `ApiState` so
	/// the REST and JMAP submission paths share a single source of
	/// truth, and tests can rebuild `ApiState` with a tighter limit
	/// without touching the file.
	new_recipients_per_day: Option<u32>,
	/// Account names allowed to authenticate to the admin panel.
	admins: Vec<String>,
	/// Per-account storage quota in bytes; 0 means unlimited.
	quota_limit: std::sync::atomic::AtomicU64,
	/// Labeled bearer API keys, loaded from `api_keys.toml`; any non-expired,
	/// IP-permitted key authenticates alongside the configured token. Held
	/// behind an `Arc<ApiKeySet>` so the file watcher can swap the live
	/// set on a CLI edit without rebuilding `ApiState` and without holding
	/// a lock across every request, the snapshot guard is taken per
	/// request and dropped before the response goes out.
	api_keys: std::sync::Arc<super::api_keys::ApiKeySet>,
	/// Session-scoped PushSubscription objects (RFC 8620 §7.2). Held in memory:
	/// real out-of-band delivery is out of scope, so these only need to round-trip
	/// through `PushSubscription/get`/`set`. Each carries the caller that created it.
	push_subscriptions: std::sync::Mutex<Vec<super::jmap::push_subscription::StoredSubscription>>,
	/// JMAP work in flight per caller and kind (event-source streams, API
	/// requests, uploads), so one credential cannot hold more than its limits.
	caller_slots: Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>,
	/// At-rest crypto for stored message bodies and uploaded blobs.
	crypto: MessageCrypto,
	/// The built-in OAuth 2.0 authorization server, present only when a signing
	/// key is configured. When `None`, the `/oauth/*` grant routes are not mounted
	/// and no tokens are issued (fail closed).
	authz: Option<Arc<super::oauth::AuthzServer>>,
	/// Hot-reloadable directory shared with SMTP/IMAP/ManageSieve. Required for
	/// send-as ownership checks on the API path; when absent, every
	/// `owns_address` call returns `false` (fail closed).
	directory: Option<DirectoryHandle>,
	/// Labels of API keys whose `scopes` field is empty (legacy) and that
	/// have already triggered the one-time deprecation warning. Keyed by
	/// label so re-warning across the lifetime of a single process is
	/// prevented.
	legacy_warned: std::sync::Mutex<std::collections::HashSet<String>>,
	/// Pluggable blob store. Defaults to the filesystem root at `data_dir`;
	/// the S3 backend replaces it when `[storage.blobs] backend = "s3"` is
	/// configured. The handler-side helpers do not know which is in play —
	/// they speak to the trait the same way either way.
	blob_backend: Arc<dyn crate::storage::BlobBackend>,
	/// Per-tenant aggregate limits (accounts, storage, submission rate).
	/// Empty when no `[[tenant]]` is configured; the empty state is the
	/// identity, every check short-circuits to "no cap".
	tenant_limits: TenantLimits,
	/// The per-account submission limiter the SMTP listeners share, and
	/// the server-wide per-account cap; see `state_submission.rs`.
	submission_limit: Option<(Arc<crate::smtp::ratelimit::SendLimiter>, Option<u32>)>,
	/// Per-account Bayesian wiring: the training queue and the
	/// store, both `None` without a database. Builders and accessors
	/// live in `state_bayes.rs`.
	bayes: bayes::BayesBindings,
	/// The outbound path SMTP submission uses (routing, DKIM, local
	/// delivery); `None` sends straight to `spool`. See `state_outbound.rs`.
	outbound: Option<Arc<dyn crate::smtp::sink::MessageSink>>,
	/// Retention window in days for the per-recipient delivery log
	/// (`<data_dir>/deliverylog/`). `0` (the default) disables the log;
	/// the deliveries handler turns that into a `404` so the caller is
	/// not silently handed an empty page.
	delivery_log_days: u64,
	/// Hosted domains switched off (`disabled_domains`).
	disabled_domains: Vec<String>,
	/// Per-instance message-size cap, applied consistently to SMTP
	/// (`SIZE` extension, per-line running check, end-of-DATA check,
	/// per-chunk BDAT cap), the JMAP `Email/set` build, the JMAP
	/// `EmailSubmission/set` builder, the JMAP `upload` body limit,
	/// and the REST `POST /api/v1/send` body limit. The default is
	/// [`crate::smtp::session::MAX_MESSAGE_SIZE`]; operators raise or
	/// lower it with the `[server] max_message_size` config key.
	max_message_size: usize,
}

#[path = "state_limiter.rs"]
mod limiter;
use limiter::{AUTH_WINDOW, ClientLimiters};

pub use super::account_view::AccountView;

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
		// `ApiKeySet::open` only fails on a parse error or a read error
		// other than NotFound. Either way the operator can recover by
		// editing the file and waiting for the watcher to reload;
		// binding the listener with an empty set keeps the API surface
		// up so the static token still authenticates and a corrected
		// file can be observed on the next poll.
		let api_keys = std::sync::Arc::new(
			super::api_keys::ApiKeySet::open(&data_dir)
				.unwrap_or_else(|_| super::api_keys::ApiKeySet::empty()),
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
		let stats = super::jmap::backfill_blob_ownership(&data_dir, &account_names);
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
				token_hash: token_hash.to_string(),
				data_dir: data_dir.clone(),
				domains,
				store,
				spool,
				auth_limiter: std::sync::Mutex::new(ClientLimiters::new(AUTH_WINDOW)),
				configured_digest: std::sync::OnceLock::new(),
				argon2_gate: std::sync::Arc::new(tokio::sync::Semaphore::new(
					MAX_CONCURRENT_ARGON2,
				)),
				argon2_waiting: std::sync::atomic::AtomicUsize::new(0),
				argon2_queue_max: MAX_ARGON2_QUEUE,
				#[cfg(test)]
				argon2_stats: Default::default(),
				correspondents: None,
				class_bindings: None,
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
				disabled_domains: Vec::new(),
				max_message_size: crate::smtp::session::MAX_MESSAGE_SIZE,
			}),
		}
	}

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

	/// Name the hosted domains that are switched off. Must be set before the
	/// state is shared.
	pub fn with_disabled_domains(mut self, domains: Vec<String>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.disabled_domains = domains;
		}
		self
	}

	/// The hosted domains that are switched off: they stay in
	/// [`ApiState::domains`] but take no mail.
	pub fn disabled_domains(&self) -> &[String] {
		&self.inner.disabled_domains
	}

	/// The per-instance message-size cap. Defaults to
	/// [`crate::smtp::session::MAX_MESSAGE_SIZE`]; operators raise or
	/// lower it with the `[server] max_message_size` config key.
	pub fn max_message_size(&self) -> usize {
		self.inner.max_message_size
	}

	/// Override the per-instance message-size cap. Used by `serve` to
	/// apply the operator's `[server] max_message_size`. Must be set
	/// before the state is shared. `0` keeps the default.
	pub fn with_max_message_size(mut self, bytes: usize) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner)
			&& bytes > 0
		{
			inner.max_message_size = bytes;
		}
		self
	}

	/// Attach the built-in OAuth authorization server. Must be set before the
	/// state is shared (it rebuilds the `Arc` inner). When unset, the `/oauth/*`
	/// grant routes are absent and no tokens are issued.
	pub fn with_authz(mut self, authz: super::oauth::AuthzServer) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.authz = Some(Arc::new(authz));
		}
		self
	}

	/// The built-in OAuth authorization server, when configured.
	pub fn authz(&self) -> Option<&super::oauth::AuthzServer> {
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
	pub fn api_keys(&self) -> &std::sync::Arc<super::api_keys::ApiKeySet> {
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
	/// [`super::api_keys::ApiKeySet::reload_from`] on `set` whenever
	/// `api_keys.toml` changes, so a server that needs hot-reloadable
	/// keys must pass the same `Arc<ApiKeySet>` it gave to the
	/// watcher. Must be called before the state is shared (the
	/// builder quietly no-ops when the `Arc` is already taken,
	/// mirroring `with_authz`).
	pub fn with_api_keys(mut self, set: std::sync::Arc<super::api_keys::ApiKeySet>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.api_keys = set;
		}
		self
	}

	/// Test-only: count one wrong token from `ip` without sending a request.
	#[cfg(test)]
	pub(crate) fn seed_auth_failure(&self, ip: std::net::IpAddr) {
		self.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.record_failure(Some(ip), std::time::Instant::now());
	}

	/// Test-only: change how many requests may wait for an argon2 turn.
	#[cfg(test)]
	pub(crate) fn with_argon2_queue(mut self, max: usize) -> Self {
		Arc::get_mut(&mut self.inner)
			.expect("with_argon2_queue must be called before the state is shared")
			.argon2_queue_max = max;
		self
	}

	/// Test-only: requests holding a place in the argon2 queue right now.
	#[cfg(test)]
	pub(crate) fn argon2_waiting(&self) -> usize {
		self.inner
			.argon2_waiting
			.load(std::sync::atomic::Ordering::SeqCst)
	}

	/// Test-only: argon2 verifications running right now.
	#[cfg(test)]
	pub(crate) fn argon2_running(&self) -> usize {
		self.inner.argon2_stats[1].load(std::sync::atomic::Ordering::SeqCst)
	}

	/// Test-only: (argon2 runs started, most at once).
	#[cfg(test)]
	pub(crate) fn argon2_stats(&self) -> (usize, usize) {
		use std::sync::atomic::Ordering::SeqCst;
		(
			self.inner.argon2_stats[0].load(SeqCst),
			self.inner.argon2_stats[2].load(SeqCst),
		)
	}

	/// Test-only: behave as if the configured token had already verified once.
	#[cfg(test)]
	pub(crate) fn prime_configured_token(&self, token: &str) {
		let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
		let mut known = [0u8; 32];
		known.copy_from_slice(digest.as_ref());
		let _ = self.inner.configured_digest.set(known);
	}

	/// Test-only: lower the global failure ceiling so a test can reach it.
	#[cfg(test)]
	pub(crate) fn with_auth_global_max(mut self, max: u32) -> Self {
		let inner = Arc::get_mut(&mut self.inner)
			.expect("with_auth_global_max must be called before the state is shared");
		let window = inner
			.auth_limiter
			.get_mut()
			.unwrap_or_else(|p| p.into_inner())
			.window();
		inner.auth_limiter =
			std::sync::Mutex::new(ClientLimiters::new(window).with_global_max(max));
		self
	}

	/// Replace the auth-failure limiter with one built around a custom
	/// window. Test-only: the router-level rate-limit test builds its state
	/// with a long window so the wall clock under a loaded parallel run is
	/// never the thing under test. The window logic itself is covered by
	/// `state_limiter_tests.rs`. Must be called before the state is shared
	/// (the other builders quietly no-op when the `Arc` is already taken;
	/// this one panics, because a test-only builder that silently does
	/// nothing defeats its own control).
	#[cfg(test)]
	pub(crate) fn with_auth_window(mut self, window: std::time::Duration) -> Self {
		let inner = Arc::get_mut(&mut self.inner)
			.expect("with_auth_window must be called before the state is shared");
		inner.auth_limiter = std::sync::Mutex::new(ClientLimiters::new(window));
		self
	}

	/// Attach the per-tenant aggregate limits. Must be set before the state
	/// is shared (it rebuilds the `Arc` inner). With no configured tenants
	/// the runtime is the identity, every check returns "no cap". The
	/// `Arc` lets the SMTP server share the same instance without a clone.
	pub fn with_tenant_limits(mut self, limits: Arc<TenantLimits>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.tenant_limits = (*limits).clone();
		}
		self
	}

	/// Attach the per-account correspondent store. Must be set before
	/// the state is shared (it rebuilds the `Arc` inner). Required for
	/// the rolling 24h new-recipient cap (`POST /api/v1/send`, JMAP
	/// `EmailSubmission/set`); unset handlers fall through to the
	/// pre-feature behaviour rather than silently skipping the cap.
	pub fn with_correspondents(mut self, store: crate::storage::CorrespondentStore) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.correspondents = Some(store);
		}
		self
	}

	/// The per-account correspondent store when one has been attached.
	/// `None` means the cap cannot be enforced; handlers fall through
	/// to the pre-feature behaviour instead.
	pub fn correspondents(&self) -> Option<&crate::storage::CorrespondentStore> {
		self.inner.correspondents.as_ref()
	}

	/// Set the rolling 24h cap on first-time recipients per account
	/// (`Config::new_recipients_per_day`). Must be set before the state
	/// is shared (it rebuilds the `Arc` inner). `None` disables the cap.
	pub fn with_new_recipients_per_day(mut self, limit: Option<u32>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.new_recipients_per_day = limit;
		}
		self
	}

	/// The configured daily new-recipient cap, when one is in effect.
	/// `None` means the cap is disabled; every submission is allowed.
	pub fn new_recipients_per_day(&self) -> Option<u32> {
		self.inner.new_recipients_per_day
	}

	/// The per-tenant aggregate limits. Empty when no `[[tenant]]` is
	/// configured; the empty state short-circuits every check to "no cap",
	/// which is the pre-tenancy behaviour bit-for-bit.
	pub fn tenant_limits(&self) -> &TenantLimits {
		&self.inner.tenant_limits
	}

	/// Shared handle for wiring the same limits into the SMTP server. Kept
	/// separate from `tenant_limits()` so callers do not need to construct
	/// an `Arc` themselves just to mirror the state.
	pub fn tenant_limits_handle(&self) -> Arc<TenantLimits> {
		Arc::new(self.inner.tenant_limits.clone())
	}

	/// The quota in force for `account` (its own, its domain's, else the
	/// server default); `None` is no limit. The rule IMAP QUOTA applies.
	pub(crate) fn quota_for_account(&self, account: &str) -> Option<u64> {
		match self.directory_snapshot() {
			Some(directory) => {
				crate::smtp::quota::limit_for(&directory, account, self.quota_limit())
			}
			None => Some(self.quota_limit()).filter(|bytes| *bytes != 0),
		}
	}

	/// The server default per-account storage quota in bytes (0 = unlimited).
	pub fn quota_limit(&self) -> u64 {
		self.inner
			.quota_limit
			.load(std::sync::atomic::Ordering::Relaxed)
	}

	/// The mail domains this server hosts, as configured at startup. Used by
	/// the API to accept or reject account and domain operations.
	pub fn domains(&self) -> &[String] {
		&self.inner.domains
	}

	/// A snapshot of every account in the directory, with its delivery
	/// addresses and whether its mailbox is dynamic (provisioned on first
	/// delivery rather than declared up front).
	pub fn accounts(&self) -> Vec<AccountView> {
		self.inner
			.store
			.account_views()
			.into_iter()
			.map(|(name, addresses, dynamic)| AccountView {
				display_name: self.inner.store.display_name(&name),
				name,
				addresses,
				dynamic,
			})
			.collect()
	}

	/// The account directory this state was built over. Exposed for handlers
	/// that need operations not exposed on `State` itself (for example
	/// password changes or alias rewrites).
	pub fn store(&self) -> &AccountStore {
		&self.inner.store
	}

	/// Shared handle to the masked-address store. Handlers call
	/// [`crate::directory_store::MaskedAddressStore::add`] / `remove` /
	/// `set_enabled` directly; the store persists on each call and rebuilds
	/// the directory on the way back so the next resolution cycle sees the
	/// change.
	pub fn masked_handle(&self) -> std::sync::Arc<std::sync::RwLock<MaskedAddressStore>> {
		self.inner.store.masked_handle()
	}

	/// The on-disk spool where accepted messages land before queueing.
	pub fn spool(&self) -> &FsSpool {
		&self.inner.spool
	}

	/// The server's data directory: root for the spool, key material, and
	/// other persistent state.
	pub fn data_dir(&self) -> &std::path::Path {
		&self.inner.data_dir
	}

	/// Run `f` against the mutable PushSubscription store, returning its result.
	/// Used by `PushSubscription/get` and `/set`, which filter by caller.
	pub(crate) fn with_push_subscriptions<R>(
		&self,
		f: impl FnOnce(&mut Vec<super::jmap::push_subscription::StoredSubscription>) -> R,
	) -> R {
		let mut guard = self
			.inner
			.push_subscriptions
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		f(&mut guard)
	}

	/// The per-caller counts of JMAP work in flight
	/// ([`super::jmap::caller_slots`]).
	pub(crate) fn caller_slots(
		&self,
	) -> Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>> {
		Arc::clone(&self.inner.caller_slots)
	}
}

/// The client IP extracted from the `ConnectInfo<SocketAddr>` extension of
/// the inbound request. `None` when the listener was not built with
/// `into_make_service_with_connect_info` (e.g. in unit tests, where the IP
/// is irrelevant to the test and `unknown` will be logged). The audit
/// channel renders `None` as the literal `unknown` so the field is always
/// present and filterable.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<std::net::IpAddr>);

/// Infer the coarse-grained scope the request needs from its method and path.
/// The middleware uses this as a first pass; per-method JMAP handlers
/// (`src/api/jmap/mod.rs::dispatch_request`) tighten it on top.
///
/// Unambiguous routes (`POST /api/v1/send`, `POST /jmap/upload`) get a
/// single-scope slice. `POST /jmap/api` is ambiguous (every method call
/// shares the same path), so the slice accepts any of `Read`/`Write`/`Send`
/// — the dispatcher then enforces the actual scope per method call. The
/// SCIM 2.0 surface under `/scim/v2` is its own damage class; both reads
/// and writes on it require the dedicated `Scim` scope.
fn acceptable_scopes_for(method: &axum::http::Method, path: &str) -> Vec<Scope> {
	const ALL: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send];
	if method == axum::http::Method::POST && path == "/api/v1/send" {
		return vec![Scope::Send];
	}
	if path.starts_with("/scim/v2") {
		return vec![Scope::Scim];
	}
	match *method {
		axum::http::Method::GET | axum::http::Method::HEAD => vec![Scope::Read],
		axum::http::Method::POST
		| axum::http::Method::PUT
		| axum::http::Method::DELETE
		| axum::http::Method::PATCH => {
			if path.starts_with("/api/v1/") || path.starts_with("/jmap/upload") {
				vec![Scope::Write]
			} else {
				ALL.to_vec()
			}
		}
		_ => vec![Scope::Write],
	}
}

/// Argon2 verifications of the configured token allowed to run at once.
const MAX_CONCURRENT_ARGON2: usize = 2;

/// Requests that may wait for an argon2 turn; the next one is told `429`.
const MAX_ARGON2_QUEUE: usize = 64;

/// Longest bearer token considered at all.
const MAX_BEARER_LEN: usize = 1024;

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	mut request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	// Read `now` once and pass the same value to both the pre-check and the
	// record/reset at the bottom of the request, so a single request can never
	// roll the window between the read and the write.
	let now = std::time::Instant::now();
	// The client IP for API-key CIDR allowlists and for the failure limit.
	// `ConnectInfo` is present when the router is served with
	// `into_make_service_with_connect_info`; absent (e.g. in tests) it is
	// `None`, so an IP-restricted key cannot match and every such request
	// shares one failure budget.
	// A dual-stack `::` listener reports an IPv4 peer as `::ffff:a.b.c.d`;
	// canonicalize here so an operator who pinned `192.0.2.0/24` on their key
	// still gets matched by an IPv4 client that connected through the dual-stack
	// bind. The audit channel uses the same canonical form.
	let client_ip = request
		.extensions()
		.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
		.map(|info| crate::net::canonical_peer(info.0).ip());
	// Reject before any token work when this client's failure budget is
	// exhausted, and reserve one failure under the same lock: requests that
	// arrive together would all pass a bare check before any was counted. The
	// reservation is given back below if the token proves valid.
	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if !limiter.reserve(client_ip, now) {
			return Err(ApiError::rate_limited());
		}
	}

	let token = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		// Nothing a key or the configured token can be: refused before any
		// hashing, so oversized junk costs a comparison of lengths.
		.filter(|value| !value.is_empty() && value.len() <= MAX_BEARER_LEN)
		.map(str::to_owned);

	// Coarse-grained scope from the request line: the per-route JMAP handlers
	// apply their own fine-grained check on top of this. Unambiguous
	// mutators (e.g. POST /api/v1/send, POST /jmap/upload) are caught here;
	// ambiguous routes (POST /jmap/api) accept any scoped key and let the
	// dispatcher decide per method call.
	let acceptable_scopes = acceptable_scopes_for(request.method(), request.uri().path());
	let token_ref = token.as_deref();
	// The configured token has every scope; a leaked configured token is
	// admin-equivalent regardless.
	// API keys first: a SHA-256 lookup, so a key never pays for the configured
	// token's (possibly argon2) hash.
	let key_ok = token_ref.is_some_and(|t| state.key_authorizes(t, client_ip, &acceptable_scopes));
	let configured = match token_ref {
		Some(t) if !key_ok => match state.bearer_is_configured_async(t).await {
			Ok(answer) => answer,
			// Too many guesses are already waiting for an argon2: tell this
			// one to come back. Nothing was checked, so it was no failed
			// credential and the failure it reserved is given back: otherwise
			// a flood that fills the queue would run good clients into
			// their limit.
			Err(auth::ArgonBusy) => {
				state
					.inner
					.auth_limiter
					.lock()
					.unwrap_or_else(|p| p.into_inner())
					.refund(client_ip);
				return Err(ApiError::rate_limited());
			}
		},
		_ => false,
	};
	let authorized = configured || key_ok;

	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		// A valid call gives back only the failure it reserved, not the
		// client's earlier ones: someone holding one key of their own could
		// otherwise guess, call and guess again.
		if authorized {
			limiter.refund(client_ip);
		}
		// Only a request that failed is asked about the /48 and the global
		// ceiling; a valid token is never refused for other people's failures.
		if !authorized && limiter.limited_after_failure(client_ip, now) {
			return Err(ApiError::rate_limited());
		}
	}

	if !authorized {
		return Err(ApiError::unauthenticated());
	}
	// Inject the resolved client IP so privileged handlers can attribute
	// their state-changing actions in the audit log.
	request.extensions_mut().insert(ClientIp(client_ip));
	// Stash the matched credentials so per-route handlers can apply a
	// fine-grained scope check on top of the coarse path/method inference
	// the middleware just performed.
	request.extensions_mut().insert(MatchedAuth {
		token: token.clone(),
		client_ip,
		configured,
	});
	Ok(next.run(request).await)
}

#[cfg(test)]
thread_local! {
	/// How many times this thread compared a bearer against the configured
	/// token hash, which may be a legacy argon2id one.
	pub(crate) static CONFIGURED_HASH_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[path = "state_auth.rs"]
mod auth;

#[path = "state_bayes.rs"]
mod bayes;

#[path = "state_outbound.rs"]
mod outbound;

#[path = "state_submission.rs"]
mod submission;

#[path = "state_classes.rs"]
mod classes;

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "state_limiter_tests.rs"]
mod limiter_tests;
