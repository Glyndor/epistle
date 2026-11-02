//! Shared API state and bearer-token authentication.

use std::path::PathBuf;
use std::sync::Arc;

use crate::directory_store::{AccountStore, DirectoryHandle, MaskedAddressStore};
use crate::smtp::address::Address;
use crate::storage::{FsSpool, MessageCrypto};

use super::tenant_limits::TenantLimits;

/// The bearer credentials the middleware extracted from the request, stashed
/// in request extensions so handlers can apply a fine-grained scope check on
/// top of the coarse path/method inference the middleware already did.
#[derive(Clone)]
pub struct MatchedAuth {
	/// The raw bearer token as presented by the client, or `None` for
	/// unauthenticated routes (which never reach the API surface).
	pub token: Option<String>,
	/// The effective client IP, when the listener has `ConnectInfo`. `None`
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
	token_hash: Option<String>,
	data_dir: PathBuf,
	domains: Vec<String>,
	store: Arc<AccountStore>,
	spool: FsSpool,
	auth_limiter: std::sync::Mutex<ClientLimiters>,
	trusted_proxies: Vec<crate::cidr::Cidr>,
	/// SHA-256 of the configured token, set the first time the legacy argon2
	/// hash verified it; from then on a bearer is compared by digest.
	configured_digest: std::sync::OnceLock<[u8; 32]>,
	/// Limits how many argon2 verifications of the configured token run at
	/// once. A request past the limit waits for its turn, it is not refused.
	argon2_gate: std::sync::Arc<tokio::sync::Semaphore>,
	/// Requests waiting for the gate; past [`MAX_ARGON2_QUEUE`] they are refused.
	argon2_waiting: std::sync::Mutex<auth_queue::QueueSlots>,
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
	/// Which identification and reputation headers a submission gets,
	/// shared with the SMTP submission path so the same message carries
	/// the same fields whichever of the three sent it.
	identification: crate::smtp::identification::Policy,
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
	/// the server-wide per-account cap; see `submission.rs`.
	submission_limit: Option<(Arc<crate::smtp::ratelimit::SendLimiter>, Option<u32>)>,
	/// Per-account Bayesian wiring: the training queue and the
	/// store, both `None` without a database. Builders and accessors
	/// live in `bayes.rs`.
	bayes: bayes::BayesBindings,
	/// The outbound path SMTP submission uses (routing, DKIM, local
	/// delivery); `None` sends straight to `spool`. See `outbound.rs`.
	outbound: Option<Arc<dyn crate::smtp::sink::MessageSink>>,
	/// Retention window in days for the per-recipient delivery log
	/// (`<data_dir>/deliverylog/`). `0` (the default) disables the log;
	/// the deliveries handler turns that into a `404` so the caller is
	/// not silently handed an empty page.
	delivery_log_days: u64,
	/// Optional advisory webhook used for queue cancellation events.
	webhook: Option<Arc<crate::webhook::Webhook>>,
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
	/// Recipients one message may name through the REST send endpoint and
	/// JMAP `EmailSubmission/set`, the same count the SMTP listeners accept.
	/// The default is [`crate::smtp::session::DEFAULT_MAX_RECIPIENTS`].
	max_recipients: usize,
}

mod limiter;
use limiter::{AUTH_WINDOW, ClientLimiters};

pub use super::account_view::AccountView;

mod construction;
mod settings;
#[cfg(test)]
mod test_support;
mod views;

/// The effective client IP resolved from the `ConnectInfo<SocketAddr>` extension of
/// the inbound request. `None` when the listener was not built with
/// `into_make_service_with_connect_info` (e.g. in unit tests, where the IP
/// is irrelevant to the test and `unknown` will be logged). The audit
/// channel renders `None` as the literal `unknown` so the field is always
/// present and filterable.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub Option<std::net::IpAddr>);

/// Argon2 verifications of the configured token allowed to run at once.
const MAX_CONCURRENT_ARGON2: usize = 2;

/// Requests that may wait for an argon2 turn; the next one is told `429`.
const MAX_ARGON2_QUEUE: usize = 64;

#[cfg(test)]
thread_local! {
	/// How many times this thread compared a bearer against the configured
	/// token hash, which may be a legacy argon2id one.
	pub(crate) static CONFIGURED_HASH_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

mod bearer;
/// The scopes the bearer middleware accepts for a request line, for the tests
/// that hold the OpenAPI description to it.
#[cfg(test)]
pub(in crate::api) use bearer::acceptable_scopes_for;
pub use bearer::require_bearer_token;

mod auth_queue;

mod auth;

mod bayes;

mod outbound;

mod submission;

mod classes;

#[cfg(test)]
mod tests;

mod client_ip;
