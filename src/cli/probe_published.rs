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
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	let container = Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists();
	if local(&compose, container) {
		return probe_all(&config.listeners, cert).await;
	}
	let podup = podup.to_string();
	let json = tokio::task::spawn_blocking(move || {
		crate::cli::stack_started::ps_json_with(
			&podup,
			&compose,
			crate::cli::stack_started::PS_TIMEOUT,
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
	let publications = json.and_then(|json| parse(&json));
	let mut lines = Vec::with_capacity(listeners.len());
	for listener in listeners {
		let targets = publications
			.as_ref()
			.map_err(String::as_str)
			.and_then(|ports| {
				targets(listener, ports).map_err(|_| "no usable TCP publication for this listener")
			});
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
			Err(reason) => ProbeLine {
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

fn parse(json: &str) -> Result<Vec<Publisher>, String> {
	let rows: Vec<Row> = serde_json::from_str(json)
		.map_err(|_| "cannot read port publications from podup ps".to_string())?;
	let mut mail = rows.into_iter().filter(|row| row.service == "mail");
	let row = mail.next().ok_or("mail is not listed by podup ps")?;
	if mail.next().is_some() {
		return Err("multiple mail containers are listed by podup ps".to_string());
	}
	row.publishers
		.ok_or_else(|| "podup ps has no port publication metadata".to_string())
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
#[path = "probe_published_tests.rs"]
mod tests;
