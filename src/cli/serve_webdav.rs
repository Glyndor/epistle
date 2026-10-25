//! Spawn the WebDAV listener. The `[api] trusted_proxies` list is shared
//! with the API listener so a request that reached the server through a
//! trusted reverse proxy is logged under the real client address, not the
//! proxy's own socket peer. `[api] trusted_proxies = []` (no `[api]`
//! section) trusts no proxy.

use crate::config::Config;
use crate::directory_store::DirectoryHandle;
use crate::net::http_serve::Limits;

pub(super) fn spawn(
	listener: tokio::net::TcpListener,
	config: &Config,
	directory: DirectoryHandle,
	http_limits: Limits,
) -> tokio::task::JoinHandle<std::io::Result<()>> {
	let trusted_proxies = config
		.api
		.as_ref()
		.map_or(Vec::new(), |a| a.trusted_proxies.clone());
	// Same default and same measure as IMAP QUOTA and SMTP delivery. The
	// configuration already loaded once at start-up, so a failure here means
	// the key went away since: the listener then fails closed.
	let crypto = match crate::storage::MessageCrypto::from_config(config.storage.as_ref()) {
		Ok(crypto) => crypto,
		Err(error) => return tokio::spawn(async move { Err(std::io::Error::other(error)) }),
	};
	let quota_default = config
		.quota_bytes
		.unwrap_or(crate::imap::session::DEFAULT_QUOTA_BYTES);
	let state = crate::webdav::WebDavState {
		directory,
		data_dir: config.data_dir.clone(),
		trusted_proxies,
		quota_default: 0,
		crypto: crate::storage::MessageCrypto::disabled(),
	}
	.with_quota(quota_default, crypto);
	let router = crate::webdav::router_for(state);
	super::serve_tasks::serve_http(listener, router, http_limits)
}
