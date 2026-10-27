//! Resolve host probe targets from the running stack's port publications.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use serde::Deserialize;

use super::{ProbeLine, build_verifier, loopback_for, probe_all, probe_one};
use crate::config::{Config, Listener};

#[derive(Deserialize)]
struct Row {
	#[serde(rename = "Service")]
	service: String,
	#[serde(rename = "Publishers")]
	publishers: Option<Vec<Publisher>>,
}

#[derive(Deserialize)]
struct Publisher {
	#[serde(rename = "URL")]
	url: String,
	#[serde(rename = "TargetPort")]
	target: u16,
	#[serde(rename = "PublishedPort")]
	published: Option<u16>,
	#[serde(rename = "Protocol")]
	protocol: String,
}

/// Preserve local healthchecks inside containers and standalone installs.
fn local(compose: &Path, container: bool) -> bool {
	container || matches!(compose.try_exists(), Ok(false))
}

/// Probe the host's actual bindings, or the local listeners without a stack.
pub(in crate::cli) async fn probe(
	config: &Config,
	cert: Option<&Path>,
	podup: &str,
) -> std::io::Result<Vec<ProbeLine>> {
	let container = Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists();
	probe_in(config, cert, podup, container).await
}

/// `probe` with the container marker given, so a test does not depend on the
/// environment it runs in (a CI job inside a container has the marker).
pub(in crate::cli) async fn probe_in(
	config: &Config,
	cert: Option<&Path>,
	podup: &str,
	container: bool,
) -> std::io::Result<Vec<ProbeLine>> {
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	if local(&compose, container) {
		return probe_all(&config.listeners, cert).await;
	}
	let podup = podup.to_string();
	let json = tokio::task::spawn_blocking(move || {
		crate::cli::stack::started::ps_json_with(
			&podup,
			&compose,
			crate::cli::stack::started::PS_TIMEOUT,
		)
	})
	.await
	.unwrap_or_else(|error| Err(format!("port discovery task failed: {error}")));
	let pinned = build_verifier(cert);
	Ok(probe_with(&config.listeners, json, |listener| {
		let pinned = &pinned;
		async move { probe_one(&listener, pinned).await }
	})
	.await)
}

/// Why the `mail` publications cannot be used to dial the listeners.
#[derive(Clone, Debug)]
enum Unusable {
	/// `podup ps` answered and lists no `mail` row. It lists running
	/// containers only, so `mail` is down, for example between the stop and
	/// the start of a restart. That is a failure, not something left unchecked.
	NotRunning,
	/// The publications could not be read, so the probe cannot tell.
	Unknown(String),
}

/// Keep one result per configured listener even with multiple host bindings.
async fn probe_with<F, Fut>(
	listeners: &[Listener],
	json: Result<String, String>,
	mut probe: F,
) -> Vec<ProbeLine>
where
	F: FnMut(Listener) -> Fut,
	Fut: std::future::Future<Output = ProbeLine>,
{
	let publications = json
		.map_err(Unusable::Unknown)
		.and_then(|json| parse(&json));
	let mut lines = Vec::with_capacity(listeners.len());
	for listener in listeners {
		let targets = match &publications {
			Ok(ports) => targets(listener, ports).map_err(|_| {
				Unusable::Unknown("no usable TCP publication for this listener".into())
			}),
			Err(unusable) => Err(unusable.clone()),
		};
		let line = match targets {
			Ok(targets) => {
				let mut result = None;
				for target in targets {
					let line = probe(target).await;
					let failed = !line.ok;
					result = Some(line);
					if failed {
						break;
					}
				}
				result.expect("at least one target")
			}
			Err(Unusable::NotRunning) => ProbeLine {
				kind: listener.kind.as_str(),
				addr: listener.socket_addr().to_string(),
				ok: false,
				error: Some(
					"the mail container is not running: `podup ps` does not list it".to_string(),
				),
				warning: None,
			},
			Err(Unusable::Unknown(reason)) => ProbeLine {
				kind: listener.kind.as_str(),
				addr: listener.socket_addr().to_string(),
				ok: false,
				error: None,
				warning: Some(format!(
					"not checkable from here: {reason}; check the mail container and its published ports with `epistle stack ps --json`"
				)),
			},
		};
		lines.push(line);
	}
	lines
}

fn parse(json: &str) -> Result<Vec<Publisher>, Unusable> {
	let unknown = |reason: &str| Unusable::Unknown(reason.to_string());
	let rows: Vec<Row> = serde_json::from_str(json)
		.map_err(|_| unknown("cannot read port publications from podup ps"))?;
	let mut mail = rows.into_iter().filter(|row| row.service == "mail");
	let row = mail.next().ok_or(Unusable::NotRunning)?;
	if mail.next().is_some() {
		return Err(unknown("multiple mail containers are listed by podup ps"));
	}
	row.publishers
		.ok_or_else(|| unknown("podup ps has no port publication metadata"))
}

fn targets(listener: &Listener, ports: &[Publisher]) -> Result<Vec<Listener>, ()> {
	let mut addresses = Vec::new();
	for port in ports
		.iter()
		.filter(|port| port.target == listener.socket_addr().port() && port.protocol == "tcp")
	{
		let Some(published) = port.published.filter(|port| *port != 0) else {
			continue;
		};
		let ip: IpAddr = port.url.parse().map_err(|_| ())?;
		let address = SocketAddr::new(loopback_for(ip), published);
		if !addresses.contains(&address) {
			addresses.push(address);
		}
	}
	if addresses.is_empty() {
		return Err(());
	}
	Ok(addresses
		.into_iter()
		.map(|addr| Listener {
			kind: listener.kind,
			addr: addr.ip(),
			port: Some(addr.port()),
		})
		.collect())
}

#[cfg(test)]
#[path = "published_tests.rs"]
mod tests;
