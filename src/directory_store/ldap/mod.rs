//! LDAP / Active Directory directory backend.
//!
//! Authentication against an LDAP/AD server is network I/O (a `bind` is a round
//! trip), but the directory's `authenticate` path is synchronous and called from
//! synchronous IMAP/SMTP code. To bridge the two without making the whole auth
//! path async, this module runs ldap3's *async* `LdapConnAsync` API on a
//! dedicated OS thread that owns a private current-thread Tokio runtime:
//! [`LdapAuthenticator`] owns that worker, hands it `(login, password)` requests
//! over an `mpsc` channel, and blocks the caller on a per-request reply channel
//! until the bind resolves. (ldap3's `sync` `LdapConn` does not drive its
//! connection future correctly off the main thread, so the async API on an
//! explicitly-owned runtime is used in every path here.)
//!
//! ## The bind-while-blocking tradeoff
//!
//! `authenticate` blocks the calling thread for the duration of one LDAP bind,
//! so a caller on a tokio worker hands the worker over first (see
//! `crate::util::blocking::may_block`). Every wait is bounded: the connection
//! attempt, each request on the worker, and the caller's wait for the reply
//! all give up after a deadline and fail closed. A single worker thread
//! *serializes* binds: a slow LDAP server throttles concurrent logins to one
//! at a time. A small pool of worker threads is a future optimization; one
//! worker keeps the model simple and correct.
//!
//! ## Security
//!
//! - Fail closed: any LDAP error, a missing entry, or a failed user bind maps to
//!   `None`. There is no distinction between "unknown user" and "wrong password"
//!   — both return `None`, and both cost the same number of connections and
//!   binds, so there is no user-enumeration oracle in the count of round trips.
//! - Filter injection is prevented by escaping the login per RFC 4515 before it
//!   is substituted into the configured search filter.
//! - Plaintext `ldap://` is supported but discouraged: credentials cross the
//!   wire in the clear. Prefer `ldaps://` or StartTLS (`tls = true`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, channel, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ldap3::{Ldap as LdapConnAsyncHandle, LdapConnAsync, LdapConnSettings, SearchEntry};
use limits::{Limits, capped_search, within};

pub(crate) mod limits;

use crate::config::Ldap;
use crate::smtp::address::Address;
use crate::util::address::normalize;
use crate::util::path_component::{AccountName, DigestName};

/// How long one TCP connect may take. Past it the attempt fails closed; the
/// whole login is bounded by [`Limits::AUTH`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How many logins may wait for the worker. A login that finds the queue
/// full is turned away as [`LdapBusy`] instead of waiting behind them.
const QUEUE_DEPTH: usize = 32;

/// The directory could not be asked in time. This is not a verdict on the
/// credential, so it is not a failed login for the account; the two cases
/// differ in what the client cost the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapBusy {
	/// The request cost the directory nothing: the queue was full, it
	/// expired while it waited, or no connection could be made (refused,
	/// unresolvable, or not accepted in time). A directory that is down
	/// is no reason to count its clients' attempts against them.
	NotSent,
	/// The worker took the request and opened a connection to the directory,
	/// which then did not answer in time or broke off. The attempt was
	/// made, so the caller counts it against the client.
	Reached,
}

/// How one login ended on the worker.
enum Outcome {
	/// The bind succeeded for this account.
	Account(String),
	/// The directory answered and refused: no such entry or a wrong password.
	Refused,
	/// The directory could not be reached or stopped answering.
	Unavailable,
}

/// One authentication request handed to the worker thread: the login to look up,
/// the password to bind with, and the channel the worker replies on.
struct AuthRequest {
	login: String,
	password: String,
	reply: std::sync::mpsc::Sender<Option<String>>,
	/// When the caller stops waiting. A request still queued after this is
	/// dropped unanswered: nobody is listening, and binding for it would
	/// only keep the worker from the logins that are.
	expires: Instant,
	/// Set by the worker once it holds a connection to the directory for
	/// this request.
	reached: Arc<AtomicBool>,
}

/// A live LDAP directory authenticator backed by a dedicated worker thread.
///
/// Cheap to share behind an `Arc`. [`LdapAuthenticator::authenticate`] is
/// synchronous and safe to call from the existing synchronous auth path.
pub struct LdapAuthenticator {
	/// The request sender. An `Option` so [`Drop`] can drop it (closing the
	/// channel and ending the worker loop) *before* joining the worker thread —
	/// joining while the sender is still alive would deadlock.
	requests: Option<SyncSender<AuthRequest>>,
	worker: Option<JoinHandle<()>>,
	/// How long [`Self::authenticate`] waits for the worker's reply.
	deadline: Duration,
}

impl std::fmt::Debug for LdapAuthenticator {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("LdapAuthenticator")
	}
}

impl LdapAuthenticator {
	/// Spawn the worker thread for the given configuration. The configuration is
	/// validated by the caller ([`Ldap::validate`]); this only starts the thread.
	pub fn new(config: Ldap) -> Self {
		Self::with_limits(config, Limits::AUTH)
	}

	/// [`LdapAuthenticator::new`] with an explicit per-login budget.
	pub(crate) fn with_limits(config: Ldap, limits: Limits) -> Self {
		Self::with_queue(config, limits, QUEUE_DEPTH)
	}

	/// [`Self::with_limits`] with room for `queue` logins waiting for the
	/// worker. The caller waits at most `limits.timeout` for one login.
	pub(crate) fn with_queue(config: Ldap, limits: Limits, queue: usize) -> Self {
		let (tx, rx) = sync_channel::<AuthRequest>(queue);
		let worker = std::thread::Builder::new()
			.name("ldap-auth".to_string())
			.spawn(move || worker_loop(config, limits, rx))
			.expect("spawn ldap worker thread");
		LdapAuthenticator {
			requests: Some(tx),
			worker: Some(worker),
			deadline: limits.timeout,
		}
	}

	/// Authenticate a login with a password against the LDAP server: the
	/// mapped account name on success, `None` when the directory refused the
	/// login, and [`LdapBusy`] when it could not be asked in time.
	///
	/// Synchronous: it queues the request for the worker thread and blocks on
	/// the reply, for at most the deadline. A full queue, a missed deadline,
	/// an unreachable server and a dead worker are all `Err(LdapBusy)`.
	pub fn authenticate(&self, login: &str, password: &str) -> Result<Option<String>, LdapBusy> {
		let (reply_tx, reply_rx) = channel();
		let reached = Arc::new(AtomicBool::new(false));
		let request = AuthRequest {
			login: login.to_string(),
			password: password.to_string(),
			reply: reply_tx,
			expires: Instant::now() + self.deadline,
			reached: Arc::clone(&reached),
		};
		let requests = self.requests.as_ref().ok_or(LdapBusy::NotSent)?;
		requests.try_send(request).map_err(|_| LdapBusy::NotSent)?;
		reply_rx.recv_timeout(self.deadline).map_err(|_| {
			if reached.load(Ordering::SeqCst) {
				LdapBusy::Reached
			} else {
				LdapBusy::NotSent
			}
		})
	}
}

impl Drop for LdapAuthenticator {
	fn drop(&mut self) {
		// Drop the sender first: that closes the channel and ends the worker's
		// `for request in requests` loop. Only then join — joining while a sender
		// is still alive would block forever (the loop never sees the channel
		// close).
		self.requests.take();
		if let Some(worker) = self.worker.take() {
			let _ = worker.join();
		}
	}
}

/// The worker thread body: owns a private current-thread Tokio runtime and
/// services authentication requests until the request channel closes. Each
/// request is resolved with `block_on`, which drives the connection future
/// spawned by [`ldap3::drive!`] on that same runtime.
fn worker_loop(config: Ldap, limits: Limits, requests: Receiver<AuthRequest>) {
	let runtime = match tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime,
		// A runtime that cannot be built answers nothing: each caller's
		// reply channel closes and it reports the directory as busy.
		Err(_) => {
			for _request in requests {}
			return;
		}
	};
	for request in requests {
		// Nobody is waiting for this one any more.
		let Some(left) = time_left(request.expires, Instant::now()) else {
			continue;
		};
		// A server that stops answering mid-exchange must not hold the
		// worker, and with it every later login, past the caller's deadline.
		let outcome = runtime.block_on(async {
			tokio::time::timeout(
				left,
				authenticate_once(
					&config,
					limits,
					&request.login,
					&request.password,
					&request.reached,
				),
			)
			.await
		});
		// Unavailable and timed out send nothing: the closed channel is the
		// caller's signal that the directory could not be asked.
		if let Ok(Outcome::Account(account)) = outcome {
			let _ = request.reply.send(Some(account));
		} else if let Ok(Outcome::Refused) = outcome {
			let _ = request.reply.send(None);
		}
	}
}

/// How long a request still has before its caller stops waiting, `None`
/// once that moment has passed.
fn time_left(expires: Instant, now: Instant) -> Option<Duration> {
	expires
		.checked_duration_since(now)
		.filter(|left| !left.is_zero())
}

/// Resolve and bind one login. Returns the mapped account name on success.
///
/// Steps: (1) open a connection and bind as the configured service DN;
/// (2) search the base DN with the escaped user filter; (3) take the found
/// entry's DN and the account/mail attribute; (4) open a *fresh* connection and
/// bind as that DN with the supplied password. A fresh connection per request
/// (no caching) sidesteps connection-lifetime issues across `block_on` calls;
/// auth is infrequent, so the extra connect is acceptable. Any failure returns
/// `None` (fail closed).
async fn authenticate_once(
	config: &Ldap,
	limits: Limits,
	login: &str,
	password: &str,
	reached: &AtomicBool,
) -> Outcome {
	// An empty password would, on many servers, be an unauthenticated bind that
	// "succeeds" — reject it outright so it never reaches the user bind.
	if password.is_empty() {
		return Outcome::Refused;
	}
	let filter = build_filter(&config.user_filter, login);

	// (1)+(2): service-bind, then search for the login's entry.
	let entry = match search_entry(config, limits, &filter, reached).await {
		Ok(Some(entry)) => entry,
		Ok(None) => {
			return spend_the_user_bind(config, password, reached).await;
		}
		Err(Unreachable) => return Outcome::Unavailable,
	};

	// (3): map the entry to an account name and recover its DN for the bind.
	let Some(account) = account_name(config, &entry) else {
		return spend_the_user_bind(config, password, reached).await;
	};
	let user_dn = entry.dn;
	if user_dn.is_empty() {
		return spend_the_user_bind(config, password, reached).await;
	}

	// (4): bind as the user on a fresh connection. Success authenticates; an
	// answer that refuses the bind is a wrong password, no answer is not.
	let Ok(mut user_conn) = connect(config, reached).await else {
		return Outcome::Unavailable;
	};
	let bound = user_conn.simple_bind(&user_dn, password).await;
	let _ = user_conn.unbind().await;
	match bound.map(|result| result.success().is_ok()) {
		Ok(true) => Outcome::Account(account),
		Ok(false) => Outcome::Refused,
		Err(_) => Outcome::Unavailable,
	}
}

/// The directory could not be reached, or answered with an error that is not
/// about the login (a failed service bind, a search error).
struct Unreachable;

/// Make the round trips of step (4) for a login that has no entry: a fresh
/// connection and a bind that cannot succeed. A login the directory knows
/// costs a connection and a bind for the user on top of the search; without
/// this one an unknown login would end a connection early and the count of
/// round trips would say which logins exist. It also ends the way step (4)
/// does: refused when the directory answered, unavailable when it did not.
async fn spend_the_user_bind(config: &Ldap, password: &str, reached: &AtomicBool) -> Outcome {
	let Ok(mut conn) = connect(config, reached).await else {
		return Outcome::Unavailable;
	};
	let unused_dn = format!("cn=unknown-login,{}", config.base_dn);
	let bound = conn.simple_bind(&unused_dn, password).await;
	let _ = conn.unbind().await;
	// The same classification step (4) gives a known login: whether the
	// directory answered decides it, never whether the entry exists.
	match bound {
		Ok(_) => Outcome::Refused,
		Err(_) => Outcome::Unavailable,
	}
}

/// Open a fresh connection, service-bind, and search for the single entry
/// matching `filter` under the base DN. `Ok` carries the first matching
/// entry, or `None` when the directory has none; `Err` is any failure to ask.
async fn search_entry(
	config: &Ldap,
	limits: Limits,
	filter: &str,
	reached: &AtomicBool,
) -> Result<Option<SearchEntry>, Unreachable> {
	let mut conn = connect(config, reached).await.map_err(|_| Unreachable)?;
	let found = service_search(&mut conn, config, limits, filter).await;
	let _ = conn.unbind().await;
	found
}

async fn service_search(
	conn: &mut LdapConnAsyncHandle,
	config: &Ldap,
	limits: Limits,
	filter: &str,
) -> Result<Option<SearchEntry>, Unreachable> {
	conn.simple_bind(&config.bind_dn, &config.bind_password)
		.await
		.map_err(|_| Unreachable)?
		.success()
		.map_err(|_| Unreachable)?;
	let attrs = vec![
		config.account_attribute.as_str(),
		config.mail_attribute.as_str(),
	];
	let entries = capped_search(conn, &config.base_dn, filter, attrs, limits.entries)
		.await
		.map_err(|_| Unreachable)?;
	Ok(entries.into_iter().next())
}

/// Open an async connection honoring the TLS toggle and spawn its driver future
/// (via [`ldap3::drive!`]) on the current runtime. `ldaps://` URLs always
/// negotiate TLS; for `ldap://` URLs the toggle requests StartTLS.
async fn connect(
	config: &Ldap,
	reached: &AtomicBool,
) -> ldap3::result::Result<LdapConnAsyncHandle> {
	let settings = LdapConnSettings::new()
		.set_starttls(config.tls && config.url.starts_with("ldap://"))
		.set_conn_timeout(CONNECT_TIMEOUT);
	let (conn, ldap) = LdapConnAsync::with_settings(settings, &config.url).await?;
	ldap3::drive!(conn);
	reached.store(true, Ordering::SeqCst);
	Ok(ldap)
}

/// Map a found entry to its account name: the first value of the configured
/// account attribute, falling back to the mail attribute, else `None`.
///
/// A value that cannot be one directory name is skipped with a warning that
/// carries a pseudonym of it, never the value, so it never reaches the data
/// directory.
fn account_name(config: &Ldap, entry: &SearchEntry) -> Option<String> {
	let name = first_value(entry, &config.account_attribute)
		.or_else(|| first_value(entry, &config.mail_attribute))?;
	if AccountName::new(&name).is_ok() {
		Some(name)
	} else {
		tracing::warn!(
			account = %DigestName::pseudonym(&name),
			"ignoring an LDAP entry whose account name cannot be a directory name",
		);
		None
	}
}

/// The first value of an attribute on an entry, if present and non-empty.
fn first_value(entry: &SearchEntry, attribute: &str) -> Option<String> {
	entry
		.attrs
		.get(attribute)
		.and_then(|values| values.first())
		.filter(|value| !value.is_empty())
		.cloned()
}

/// The delivered addresses of an entry: every value of the given attribute
/// that is a valid mailbox, in the stored form (the local part and the
/// domain lowercased).
///
/// The directory server is not ours, so the attribute it serves can carry
/// anything. A value that is not a valid address is skipped with a warning
/// that carries a pseudonym of it, never the value, so an injected address
/// never reaches the directory.
fn validated_addresses(entry: &SearchEntry, attribute: &str) -> Vec<String> {
	entry
		.attrs
		.get(attribute)
		.into_iter()
		.flatten()
		.filter_map(|raw| match Address::parse(raw) {
			Ok(_) => Some(normalize(raw)),
			Err(_) => {
				tracing::warn!(
					address = %DigestName::pseudonym(raw),
					"ignoring an LDAP address that is not a valid mailbox",
				);
				None
			}
		})
		.collect()
}

/// Substitute the escaped login for every `%s` placeholder in `template`. The
/// login is escaped per RFC 4515 first, so the result is injection-safe.
fn build_filter(template: &str, login: &str) -> String {
	template.replace("%s", &escape_filter(login))
}

/// Escape a value for use inside an LDAP search filter per RFC 4515 §3: the
/// metacharacters `* ( ) \` and the NUL byte are replaced by their `\\xx`
/// hex escapes. This prevents an attacker-controlled login from altering the
/// filter's structure (filter injection).
pub fn escape_filter(value: &str) -> String {
	let mut out = String::with_capacity(value.len());
	for ch in value.chars() {
		match ch {
			'*' => out.push_str("\\2a"),
			'(' => out.push_str("\\28"),
			')' => out.push_str("\\29"),
			'\\' => out.push_str("\\5c"),
			'\0' => out.push_str("\\00"),
			other => out.push(other),
		}
	}
	out
}

/// A directory account discovered by the LDAP search-load: the mapped account
/// name and its delivered addresses (the mail attribute values that are valid
/// mailboxes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAccount {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account: the valid mail attribute values,
	/// in their stored form.
	pub addresses: Vec<String>,
}

/// Search the whole directory (base DN + filter with `%s` removed so every user
/// matches) and produce one [`LdapAccount`] per entry. This is the read-mostly
/// *resolution* load, run at startup and refreshed periodically; it is loaded
/// into the in-memory directory so `resolve` stays synchronous. Authentication
/// still does a live per-request bind via [`LdapAuthenticator`].
///
/// Synchronous (blocking) — it owns a private current-thread Tokio runtime and
/// drives the async LDAP I/O to completion, so it is safe to call from a
/// non-runtime thread (e.g. inside `tokio::task::spawn_blocking`) and never from
/// inside an async context. Fails closed: any LDAP error is returned as an error
/// rather than a partial set.
pub fn load_ldap_accounts(config: &Ldap) -> ldap3::result::Result<Vec<LdapAccount>> {
	load_with_limits(config, Limits::LOAD)
}

/// [`load_ldap_accounts`] with an explicit budget.
pub(crate) fn load_with_limits(
	config: &Ldap,
	limits: Limits,
) -> ldap3::result::Result<Vec<LdapAccount>> {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| ldap3::LdapError::Io { source: error })?;
	runtime.block_on(within(
		limits.timeout,
		load_ldap_accounts_async(config, limits.entries),
	))
}

/// The async core of [`load_ldap_accounts`]: service-bind, search every user
/// (`%s` → `*`), and map each entry to an [`LdapAccount`]. The mail attribute
/// values that are not valid mailboxes are skipped, and the ones that are
/// reach the account in their stored form (lowercased).
async fn load_ldap_accounts_async(
	config: &Ldap,
	cap: usize,
) -> ldap3::result::Result<Vec<LdapAccount>> {
	let mut conn = connect(config, &AtomicBool::new(false)).await?;
	conn.simple_bind(&config.bind_dn, &config.bind_password)
		.await?
		.success()?;
	// Replace `%s` with `*` so the filter matches every user (a presence-style
	// wildcard), keeping any structural part of the configured filter intact.
	let filter = config.user_filter.replace("%s", "*");
	let attrs = vec![
		config.account_attribute.as_str(),
		config.mail_attribute.as_str(),
	];
	let entries = capped_search(&mut conn, &config.base_dn, &filter, attrs, cap).await?;
	let _ = conn.unbind().await;

	let mut accounts: Vec<LdapAccount> = entries
		.into_iter()
		.filter_map(|entry| {
			let name = account_name(config, &entry)?;
			let addresses = validated_addresses(&entry, &config.mail_attribute);
			Some(LdapAccount { name, addresses })
		})
		.collect();
	// Stable ordering keeps the merge deterministic across reloads.
	accounts.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(accounts)
}

#[cfg(test)]
mod tests;
