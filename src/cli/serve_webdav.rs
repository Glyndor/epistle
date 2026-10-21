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
	let router =
		crate::webdav::router_with_trusted(directory, config.data_dir.clone(), trusted_proxies);
	super::serve_tasks::serve_http(listener, router, http_limits)
}
