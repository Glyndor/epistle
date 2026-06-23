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

use std::path::PathBuf;

use axum::Router;
use axum::routing::any;

use crate::directory_store::DirectoryHandle;

pub mod auth;
pub mod carddav;
pub mod handler;
pub mod path;
pub mod propfind;

/// Shared handler state: the directory (for authentication) and the data root
/// under which each account's `dav` tree lives.
#[derive(Clone)]
pub struct WebDavState {
	/// Hot-swappable directory handle used to authenticate every request.
	pub directory: DirectoryHandle,
	/// Server data directory; account trees live beneath `accounts/<n>/dav`.
	pub data_dir: PathBuf,
}

/// Build the WebDAV router. A single catch-all route forwards every method and
/// path to [`handler::dispatch`], which authenticates and then branches on the
/// method — necessary because axum's `MethodFilter` does not cover the WebDAV
/// verbs (`PROPFIND`, `MKCOL`, `COPY`, `MOVE`).
pub fn router(directory: DirectoryHandle, data_dir: PathBuf) -> Router {
	let state = WebDavState {
		directory,
		data_dir,
	};
	Router::new()
		.fallback(any(handler::dispatch))
		.with_state(state)
}
