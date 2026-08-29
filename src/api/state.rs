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
use super::domain_scope::DomainScope;
use super::error::ApiError;

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
	auth_limiter: std::sync::Mutex<AuthLimiter>,
	/// Account names allowed to authenticate to the admin panel.
	admins: Vec<String>,
	/// Per-account storage quota in bytes; 0 means unlimited.
	quota_limit: std::sync::atomic::AtomicU64,
	/// Labeled bearer API keys, loaded from `api_keys.toml`; any non-expired,
	/// IP-permitted key authenticates alongside the configured token.
	api_keys: Vec<super::api_keys::ApiKey>,
	/// Session-scoped PushSubscription objects (RFC 8620 §7.2). Held in memory:
	/// real out-of-band delivery is out of scope, so these only need to round-trip
	/// through `PushSubscription/get`/`set`. Keyed by subscription id.
	push_subscriptions: std::sync::Mutex<Vec<serde_json::Value>>,
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
}

/// Sliding-window failure counter. Prevents brute force on the bearer token.
struct AuthLimiter {
	failures: u32,
	window_start: std::time::Instant,
}

const AUTH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const AUTH_MAX_FAILURES: u32 = 20;

impl AuthLimiter {
	fn new() -> Self {
		AuthLimiter {
			failures: 0,
			window_start: std::time::Instant::now(),
		}
	}

	fn is_limited(&mut self) -> bool {
		if self.window_start.elapsed() >= AUTH_WINDOW {
			self.failures = 0;
			self.window_start = std::time::Instant::now();
		}
		self.failures >= AUTH_MAX_FAILURES
	}

	fn record_failure(&mut self) {
		if self.window_start.elapsed() >= AUTH_WINDOW {
			self.failures = 0;
			self.window_start = std::time::Instant::now();
		}
		self.failures = self.failures.saturating_add(1);
	}

	fn reset(&mut self) {
		self.failures = 0;
		self.window_start = std::time::Instant::now();
	}
}

/// What the API exposes about an account: never credentials.
#[derive(Clone, serde::Serialize)]
pub struct AccountView {
	pub name: String,
	pub addresses: Vec<String>,
	/// Whether the account is API-managed (deletable) or from the config.
	pub dynamic: bool,
}

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
		let api_keys = super::api_keys::ApiKeyStore::open(&data_dir)
			.map(|store| store.keys().to_vec())
			.unwrap_or_default();
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
				auth_limiter: std::sync::Mutex::new(AuthLimiter::new()),
				admins: Vec::new(),
				quota_limit: std::sync::atomic::AtomicU64::new(0),
				api_keys,
				push_subscriptions: std::sync::Mutex::new(Vec::new()),
				crypto: MessageCrypto::disabled(),
				authz: None,
				directory: None,
				legacy_warned: std::sync::Mutex::new(std::collections::HashSet::new()),
				blob_backend: Arc::new(crate::storage::blob_backend::FsBackend::new(data_dir)),
			}),
		}
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
	pub fn authenticate(&self, login: &str, password: &str) -> Option<String> {
		self.inner
			.store
			.handle()
			.current()
			.authenticate(login, password)
	}

	/// Set the account names allowed to authenticate to the admin panel. Must be
	/// set before the state is shared (it rebuilds the `Arc` inner).
	pub fn with_admins(mut self, admins: Vec<String>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.admins = admins;
		}
		self
	}

	/// The domains the credentials in `auth` are allowed to act on.
	///
	/// The static token is unrestricted. A key carries whatever it declared,
	/// and a key that declared nothing keeps the reach every key had before
	/// the field existed. Credentials that match no key at all admit no
	/// domain: the middleware has already authorized the request by the time
	/// a handler asks, so failing to identify the key here means the state
	/// changed underneath us, and that is not a reason to widen anyone.
	pub fn domain_scope(&self, auth: &MatchedAuth) -> DomainScope {
		let Some(token) = auth.token.as_deref() else {
			return DomainScope::Only(Vec::new());
		};
		if self.token_matches(token) {
			return DomainScope::All;
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		const EVERY_SCOPE: &[Scope] = &[Scope::Read, Scope::Write, Scope::Send, Scope::Scim];
		self.inner
			.api_keys
			.iter()
			.find(|key| key.admits_any(token, auth.client_ip, now, EVERY_SCOPE))
			.map_or_else(|| DomainScope::Only(Vec::new()), DomainScope::of_key)
	}

	/// Whether a resolved account name carries the admin-panel privilege.
	pub fn is_admin(&self, name: &str) -> bool {
		self.inner.admins.iter().any(|admin| admin == name)
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

	/// Set the per-account storage quota in bytes (0 = unlimited).
	pub fn with_quota(self, bytes: u64) -> Self {
		self.inner
			.quota_limit
			.store(bytes, std::sync::atomic::Ordering::Relaxed);
		self
	}

	/// The configured per-account storage quota in bytes (0 = unlimited).
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

	/// The current PushSubscription objects (RFC 8620 §7.2), cloned out for a
	/// `PushSubscription/get`.
	pub fn push_subscriptions(&self) -> Vec<serde_json::Value> {
		self.inner
			.push_subscriptions
			.lock()
			.unwrap_or_else(|p| p.into_inner())
			.clone()
	}

	/// Run `f` against the mutable PushSubscription store, returning its result.
	/// Used by `PushSubscription/set` to create and destroy subscriptions.
	pub fn with_push_subscriptions<R>(
		&self,
		f: impl FnOnce(&mut Vec<serde_json::Value>) -> R,
	) -> R {
		let mut guard = self
			.inner
			.push_subscriptions
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		f(&mut guard)
	}

	/// A cheap, opaque state token for an account's mail, derived from total
	/// stored bytes. It changes whenever a message is added, removed, or resized,
	/// which is enough for the connection-scoped WebSocket push (RFC 8887 §5) to
	/// signal "something changed" to the client that made the change. It is not a
	/// JMAP change-log cursor (we do not track one — see `/changes`).
	pub fn account_state(&self, account: &str) -> String {
		let usage =
			crate::imap::mailbox::account_usage(&self.inner.data_dir, account, &self.inner.crypto);
		format!("{usage}")
	}

	/// Whether `token` from `client_ip` authorizes a request that needs one
	/// of `acceptable_scopes`: the configured token matches, or any
	/// non-expired, IP-permitted API key's hash matches and the key carries
	/// at least one of the acceptable scopes. Fail-closed: an expired,
	/// IP-restricted or under-scoped key that does not match is no different
	/// from no key at all.
	///
	/// The configured token has every scope — a leaked configured token is
	/// admin-equivalent regardless. Per-key scopes only matter for the
	/// optional, labeled keys in `api_keys.toml`.
	///
	/// Pass a single-element slice when the route is unambiguous (e.g.
	/// `POST /api/v1/send` is always `Send`); pass a multi-element slice
	/// when the coarse path/method inference is ambiguous and the handler
	/// will tighten (e.g. `POST /jmap/api`, where the actual scope depends on
	/// the JMAP method in the request body).
	fn authorizes(
		&self,
		token: &str,
		client_ip: Option<std::net::IpAddr>,
		acceptable_scopes: &[Scope],
	) -> bool {
		if self.token_matches(token) {
			return true;
		}
		let now = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_secs())
			.unwrap_or(0);
		let matched = self
			.inner
			.api_keys
			.iter()
			.find(|key| key.admits_any(token, client_ip, now, acceptable_scopes));
		if let Some(key) = matched
			&& key.scopes.is_empty()
		{
			self.warn_legacy_key_once(&key.label);
		}
		matched.is_some()
	}

	/// Emit the one-time-per-key warning for legacy (un-scoped) keys. The
	/// state is shared across requests (it lives behind an `Arc`), so the
	/// `Mutex<HashSet>` deduplicates: an operator who restarts will see one
	/// warning per legacy key per process lifetime, not one per request.
	fn warn_legacy_key_once(&self, label: &str) {
		let mut warned = self
			.inner
			.legacy_warned
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if warned.insert(label.to_string()) {
			tracing::warn!(
				key_label = label,
				"API key has no scopes; granting full legacy access. \
				 Scopes will be required in a future release; rotate this key \
				 with `--scope read|write|send` to keep its blast radius small."
			);
		}
	}

	/// Re-check `auth` against `required_scope`. Used by handlers whose scope
	/// cannot be inferred from path+method (most JMAP method calls — the same
	/// `POST /jmap/api` route serves reads, writes and outbound submissions
	/// depending on the request body, so the middleware's coarse inference
	/// defaults to passing any scoped key and lets each handler tighten it).
	pub fn require_scope(&self, auth: &MatchedAuth, scope: Scope) -> Result<(), ApiError> {
		match &auth.token {
			Some(token) if self.authorizes(token, auth.client_ip, &[scope]) => Ok(()),
			_ => Err(ApiError::unauthenticated()),
		}
	}

	fn token_matches(&self, token: &str) -> bool {
		let stored = &self.inner.token_hash;
		if let Some(expected_hex) = stored.strip_prefix("sha256:") {
			// O(1) SHA-256: correct threat model for a bearer token.
			// Comparing hex-encoded digests: timing leaks here cannot reveal
			// the preimage (SHA-256 is pre-image resistant).
			let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
			let actual_hex = digest
				.as_ref()
				.iter()
				.fold(String::with_capacity(64), |mut s, b| {
					use std::fmt::Write;
					write!(s, "{b:02x}").ok();
					s
				});
			crate::api::oauth::constant_time_eq(expected_hex.as_bytes(), actual_hex.as_bytes())
		} else {
			// Backward compat: argon2id PHC (legacy; generate new hash with `mail token-hash`).
			crate::smtp::auth::verify_password(stored, token)
		}
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

/// Middleware: every request must carry the bearer token.
pub async fn require_bearer_token(
	State(state): State<ApiState>,
	mut request: Request,
	next: Next,
) -> Result<Response, ApiError> {
	// Reject before any token work when failure budget is exhausted.
	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if limiter.is_limited() {
			return Err(ApiError::rate_limited());
		}
	}

	// The client IP for API-key CIDR allowlists. `ConnectInfo` is present when
	// the router is served with `into_make_service_with_connect_info`; absent
	// (e.g. in tests) it is `None`, so an IP-restricted key cannot match.
	let client_ip = request
		.extensions()
		.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
		.map(|info| info.0.ip());

	let token = request
		.headers()
		.get(axum::http::header::AUTHORIZATION)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.strip_prefix("Bearer "))
		.map(str::to_owned);

	// Coarse-grained scope from the request line: the per-route JMAP handlers
	// apply their own fine-grained check on top of this. Unambiguous
	// mutators (e.g. POST /api/v1/send, POST /jmap/upload) are caught here;
	// ambiguous routes (POST /jmap/api) accept any scoped key and let the
	// dispatcher decide per method call.
	let acceptable_scopes = acceptable_scopes_for(request.method(), request.uri().path());
	let token_ref = token.as_deref();
	let authorized = token_ref.is_some_and(|t| state.authorizes(t, client_ip, &acceptable_scopes));

	{
		let mut limiter = state
			.inner
			.auth_limiter
			.lock()
			.unwrap_or_else(|p| p.into_inner());
		if authorized {
			limiter.reset();
		} else {
			limiter.record_failure();
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
	});
	Ok(next.run(request).await)
}

#[cfg(test)]
#[path = "state_tests.rs"]
mod tests;
