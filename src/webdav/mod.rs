//! A WebDAV (RFC 4918, class 1) server for per-account file storage.
//!
//! Each mail account gets a private file tree at
//! `<data_dir>/accounts/<account>/dav`, served over HTTP and authenticated with
//! HTTP Basic against the mail directory. The authenticated account selects the
//! tree, so an account can only ever read and write its own files — the
//! owner-only ACL — and request paths are confined to that tree, rejecting any
//! traversal. The router is mounted on its own listener; see
//! [`crate::config::ListenerKind::WebDav`].
//!
//! The module is split for the project's per-file code-line budget:
//! - [`auth`] — Basic credential parsing and the ACL.
//! - [`path`] — request-path-to-disk mapping with traversal protection.
//! - [`handler`] — method dispatch and the per-method handlers.
//! - [`propfind`] — the `207 Multi-Status` XML body.
//! - [`carddav`] — the CardDAV (RFC 6352) layer: addressbook collections,
//!   the `REPORT` method, and the discovery props.
//! - [`caldav`] — the CalDAV (RFC 4791) layer: calendar collections, the
//!   calendar `REPORT`s, free-busy, and the scheduling Outbox (RFC 6638).
//! - [`rrule`] — a self-contained iCalendar recurrence expander for free-busy.
//! - [`sync`] and `sync_report`: the per-collection change log, the
//!   `DAV:sync-token`/`CS:getctag` it yields, and the RFC 6578
//!   `sync-collection` REPORT.

use std::path::PathBuf;

use axum::Router;
use axum::routing::any;

use crate::directory_store::DirectoryHandle;

pub mod auth;
pub mod bounds;
pub mod caldav;
pub mod caldav_busy;
pub mod caldav_filter;
mod caldav_filter_ical;
mod caldav_filter_xml;
mod caldav_hrefs;
pub mod carddav;
pub mod carddav_filter;
pub mod handler;
mod href;
pub mod path;
pub mod propfind;
pub mod quota;
mod reply;
mod report_bounds;
pub mod rrule;
pub mod sync;
mod sync_report;
#[cfg(test)]
mod test_support;

/// Shared handler state: the directory (for authentication) and the data root
/// under which each account's `dav` tree lives.
#[derive(Clone)]
pub struct WebDavState {
	/// Hot-swappable directory handle used to authenticate every request.
	pub directory: DirectoryHandle,
	/// Server data directory; account trees live beneath `accounts/<n>/dav`.
	pub data_dir: PathBuf,
	/// Reverse-proxy networks the listener trusts to forward `X-Forwarded-For`
	/// truthfully. Empty trusts no proxy. The `[api] trusted_proxies` value
	/// from the operator's configuration is wired in by the `serve` command
	/// so the audit log and ban store see the client behind a trusted proxy
	/// under the address the proxy reports, never the proxy's own socket.
	pub trusted_proxies: Vec<crate::cidr::Cidr>,
	/// The quota, in bytes, of an account that has none of its own or of its
	/// domain (the server's `quota_bytes`). `0` is no limit.
	pub quota_default: u64,
	/// How stored mail is measured, so WebDAV counts it the way IMAP QUOTA does.
	pub crypto: crate::storage::MessageCrypto,
}

impl WebDavState {
	/// Set the default quota and the way mail is measured against it.
	pub fn with_quota(mut self, default_bytes: u64, crypto: crate::storage::MessageCrypto) -> Self {
		self.quota_default = default_bytes;
		self.crypto = crypto;
		self
	}

	/// Attach the trusted-proxy network list. The `serve` command passes the
	/// `[api] trusted_proxies` value through so the WebDAV listener shares the
	/// same proxy configuration as the API listener.
	pub fn with_trusted_proxies(mut self, proxies: Vec<crate::cidr::Cidr>) -> Self {
		self.trusted_proxies = proxies;
		self
	}
}

/// Build the WebDAV router. A single catch-all route forwards every method and
/// path to [`handler::dispatch`], which authenticates and then branches on the
/// method — necessary because axum's `MethodFilter` does not cover the WebDAV
/// verbs (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`).
pub fn router(directory: DirectoryHandle, data_dir: PathBuf) -> Router {
	router_with_trusted(directory, data_dir, Vec::new())
}

/// Build the WebDAV router with the trusted-proxy network list. Production
/// uses this so the failure log and ban store see a peer's real address
/// when the request reached the listener through a trusted reverse proxy.
pub fn router_with_trusted(
	directory: DirectoryHandle,
	data_dir: PathBuf,
	trusted_proxies: Vec<crate::cidr::Cidr>,
) -> Router {
	let state = WebDavState {
		directory,
		data_dir,
		trusted_proxies,
		quota_default: crate::imap::session::DEFAULT_QUOTA_BYTES,
		crypto: crate::storage::MessageCrypto::disabled(),
	};
	router_for(state)
}

/// Build the WebDAV router over a fully specified state. Production uses this
/// to apply the server's quota and its mail encryption setting.
pub fn router_for(state: WebDavState) -> Router {
	Router::new()
		.fallback(any(handler::dispatch))
		.with_state(state)
}

#[cfg(test)]
mod href_tests;
