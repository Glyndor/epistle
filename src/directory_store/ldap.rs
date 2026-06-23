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
//! `authenticate` blocks the calling tokio worker thread for the duration of one
//! LDAP bind. Authentication is infrequent (once per session, not per message),
//! so the cost is acceptable. A single worker thread *serializes* binds: a slow
//! LDAP server throttles concurrent logins to one at a time. A small pool of
//! worker threads is a future optimization; one worker keeps the model simple
//! and correct.
//!
//! ## Security
//!
//! - Fail closed: any LDAP error, a missing entry, or a failed user bind maps to
//!   `None`. There is no distinction between "unknown user" and "wrong password"
//!   — both return `None`, so there is no user-enumeration oracle.
//! - Filter injection is prevented by escaping the login per RFC 4515 before it
//!   is substituted into the configured search filter.
//! - Plaintext `ldap://` is supported but discouraged: credentials cross the
//!   wire in the clear. Prefer `ldaps://` or StartTLS (`tls = true`).

use std::sync::mpsc::{Receiver, Sender, channel};
use std::thread::JoinHandle;

use ldap3::{Ldap as LdapConnAsyncHandle, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

use crate::config::Ldap;

/// One authentication request handed to the worker thread: the login to look up,
/// the password to bind with, and the channel the worker replies on.
struct AuthRequest {
	login: String,
	password: String,
	reply: Sender<Option<String>>,
}

/// A live LDAP directory authenticator backed by a dedicated worker thread.
///
/// Cheap to share behind an `Arc`. [`LdapAuthenticator::authenticate`] is
/// synchronous and safe to call from the existing synchronous auth path.
pub struct LdapAuthenticator {
	/// The request sender. An `Option` so [`Drop`] can drop it (closing the
	/// channel and ending the worker loop) *before* joining the worker thread —
	/// joining while the sender is still alive would deadlock.
	requests: Option<Sender<AuthRequest>>,
	worker: Option<JoinHandle<()>>,
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
		let (tx, rx) = channel::<AuthRequest>();
		let worker = std::thread::Builder::new()
			.name("ldap-auth".to_string())
			.spawn(move || worker_loop(config, rx))
			.expect("spawn ldap worker thread");
		LdapAuthenticator {
			requests: Some(tx),
			worker: Some(worker),
		}
	}

	/// Authenticate a login with a password against the LDAP server, returning
	/// the mapped account name on success or `None` on any failure.
	///
	/// Synchronous: it sends the request to the worker thread and blocks on the
	/// reply. A dead worker (its receiver dropped) fails closed as `None`.
	pub fn authenticate(&self, login: &str, password: &str) -> Option<String> {
		let (reply_tx, reply_rx) = channel();
		let request = AuthRequest {
			login: login.to_string(),
			password: password.to_string(),
			reply: reply_tx,
		};
		let requests = self.requests.as_ref()?;
		if requests.send(request).is_err() {
			return None;
		}
		reply_rx.recv().ok().flatten()
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
fn worker_loop(config: Ldap, requests: Receiver<AuthRequest>) {
	let runtime = match tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
	{
		Ok(runtime) => runtime,
		// A runtime that cannot be built means every request fails closed.
		Err(_) => {
			for request in requests {
				let _ = request.reply.send(None);
			}
			return;
		}
	};
	for request in requests {
		let outcome = runtime.block_on(authenticate_once(
			&config,
			&request.login,
			&request.password,
		));
		// A receiver that has gone away just means the caller timed out; ignore.
		let _ = request.reply.send(outcome);
	}
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
async fn authenticate_once(config: &Ldap, login: &str, password: &str) -> Option<String> {
	// An empty password would, on many servers, be an unauthenticated bind that
	// "succeeds" — reject it outright so it never reaches the user bind.
	if password.is_empty() {
		return None;
	}
	let filter = build_filter(&config.user_filter, login);

	// (1)+(2): service-bind, then search for the login's entry.
	let entry = search_entry(config, &filter).await?;

	// (3): map the entry to an account name and recover its DN for the bind.
	let account = account_name(config, &entry)?;
	let user_dn = entry.dn;
	if user_dn.is_empty() {
		return None;
	}

	// (4): bind as the user on a fresh connection. Success authenticates.
	let mut user_conn = connect(config).await.ok()?;
	let bound = user_conn
		.simple_bind(&user_dn, password)
		.await
		.ok()
		.and_then(|result| result.success().ok())
		.is_some();
	let _ = user_conn.unbind().await;
	bound.then_some(account)
}

/// Open a fresh connection, service-bind, and search for the single entry
/// matching `filter` under the base DN. Returns the first matching entry, or
/// `None` on any error or no match.
async fn search_entry(config: &Ldap, filter: &str) -> Option<SearchEntry> {
	let mut conn = connect(config).await.ok()?;
	conn.simple_bind(&config.bind_dn, &config.bind_password)
		.await
		.ok()?
		.success()
		.ok()?;
	let attrs = vec![
		config.account_attribute.as_str(),
		config.mail_attribute.as_str(),
	];
	let result = conn
		.search(&config.base_dn, Scope::Subtree, filter, attrs)
		.await
		.ok();
	let entry = result
		.and_then(|result| result.success().ok())
		.and_then(|(entries, _)| entries.into_iter().next())
		.map(SearchEntry::construct);
	let _ = conn.unbind().await;
	entry
}

/// Open an async connection honoring the TLS toggle and spawn its driver future
/// (via [`ldap3::drive!`]) on the current runtime. `ldaps://` URLs always
/// negotiate TLS; for `ldap://` URLs the toggle requests StartTLS.
async fn connect(config: &Ldap) -> ldap3::result::Result<LdapConnAsyncHandle> {
	let settings =
		LdapConnSettings::new().set_starttls(config.tls && config.url.starts_with("ldap://"));
	let (conn, ldap) = LdapConnAsync::with_settings(settings, &config.url).await?;
	ldap3::drive!(conn);
	Ok(ldap)
}

/// Map a found entry to its account name: the first value of the configured
/// account attribute, falling back to the mail attribute, else `None`.
fn account_name(config: &Ldap, entry: &SearchEntry) -> Option<String> {
	first_value(entry, &config.account_attribute)
		.or_else(|| first_value(entry, &config.mail_attribute))
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
/// name and its delivered addresses (the mail attribute values).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAccount {
	/// Account name; doubles as the mailbox directory name.
	pub name: String,
	/// Addresses delivered to this account (the mail attribute values).
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
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.map_err(|error| ldap3::LdapError::Io { source: error })?;
	runtime.block_on(load_ldap_accounts_async(config))
}

/// The async core of [`load_ldap_accounts`]: service-bind, search every user
/// (`%s` → `*`), and map each entry to an [`LdapAccount`].
async fn load_ldap_accounts_async(config: &Ldap) -> ldap3::result::Result<Vec<LdapAccount>> {
	let mut conn = connect(config).await?;
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
	let (entries, _) = conn
		.search(&config.base_dn, Scope::Subtree, &filter, attrs)
		.await?
		.success()?;
	let _ = conn.unbind().await;

	let mut accounts: Vec<LdapAccount> = entries
		.into_iter()
		.map(SearchEntry::construct)
		.filter_map(|entry| {
			let name = account_name(config, &entry)?;
			let addresses = entry
				.attrs
				.get(&config.mail_attribute)
				.cloned()
				.unwrap_or_default();
			Some(LdapAccount { name, addresses })
		})
		.collect();
	// Stable ordering keeps the merge deterministic across reloads.
	accounts.sort_by(|a, b| a.name.cmp(&b.name));
	Ok(accounts)
}

#[cfg(test)]
#[path = "ldap_tests.rs"]
mod tests;
