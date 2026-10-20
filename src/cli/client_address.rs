//! Whether the address the server sees on a socket is the client's own.
//!
//! A `--ip-cidr` allowlist (`epistle api-key create`, `epistle app-password
//! create`) and the per-client connection caps are matched against the peer of
//! the connection, so they only mean something when the container network
//! carries the real client address. The generated compose file is where that is
//! decided: `epistle init` gives the `mail` service `network_mode: "pasta"`,
//! and pasta hands the listener the client's address where a bridge funnels
//! every connection through `rootlessport` and the listener sees one internal
//! address for everyone.
//!
//! This module reads that file and nothing else. It cannot tell rootless from
//! rootful Podman, nor Podman from Docker: `podup` hides the engine and nothing
//! in the data directory records the mode. It reports the one fact that decides
//! whether an address allowlist can match, and stays silent when the file is
//! absent or unreadable.

use std::path::Path;

/// The compose network modes that hand the listener the client's address.
/// `pasta` is what `epistle init` writes; `host` is the operator's own choice
/// to share the host network namespace.
const PASSTHROUGH: [&str; 2] = ["pasta", "host"];

/// The clause naming why the client address does not survive, or `None` when
/// there is nothing to say: no container stack, an unreadable or unparseable
/// file, or a network mode that keeps the client address.
pub(crate) fn hidden_clause(data_dir: &Path) -> Option<String> {
	let compose = super::init::compose_file_path(data_dir);
	let bytes = std::fs::read(&compose).ok()?;
	let document: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
	let service = document.get("services")?.get("mail")?.as_object()?;
	let mode = service
		.get("network_mode")
		.and_then(serde_json::Value::as_str);
	hidden_clause_for(mode)
}

/// The advisory for one credential pinned with `--ip-cidr` that this network
/// cannot decide, naming `subject` ("this key", `key "billing"`), or `None`
/// when the credential carries no allowlist or the network keeps the client
/// address.
///
/// A CIDR allowlist is matched against the address the server sees on the
/// socket. When that address is the container's, the credential refuses the
/// clients it was meant to admit and admits every client the container's own
/// network holds. It is an advisory about the network, not about the request
/// that created it, so it changes nothing about what was stored.
pub(crate) fn cidr_advisory(data_dir: &Path, cidr: Option<&str>, subject: &str) -> Option<String> {
	let clause = hidden_clause(data_dir)?;
	let cidr = cidr?;
	Some(format!(
		"{subject} holds --ip-cidr {cidr}, which is matched against the address the server \
		 sees on the socket, and {clause}: the address that arrives is the container's, not \
		 the client's. The key then refuses the clients it was meant to admit and admits \
		 every client the container's network holds. Give the mail service network_mode \
		 \"pasta\", which is what `epistle init` writes, or put a proxy in front of the API, \
		 list it in [api] trusted_proxies and have it set X-Forwarded-For"
	))
}

/// [`hidden_clause`] for an already-read `network_mode`, split out so a test
/// can drive every branch without writing a compose file.
fn hidden_clause_for(mode: Option<&str>) -> Option<String> {
	match mode {
		Some(mode) if PASSTHROUGH.contains(&mode) => None,
		Some(mode) => Some(format!("the compose file sets network_mode {mode:?}")),
		None => Some(String::from(
			"the compose file sets no network_mode, so the engine's bridge default applies",
		)),
	}
}

#[cfg(test)]
#[path = "client_address_tests.rs"]
mod tests;
