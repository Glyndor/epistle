//! The host side of the generated `ports:` map.
//!
//! `init` publishes every listener whose bind is not loopback as
//! `<port>:<port>`: the listener keeps the unspecified bind it was written
//! with inside the container and the host receives the port on every address
//! it owns. `epistle service set` narrows the host side of one mapping to a
//! single address (`<address>:<port>:<port>`) and leaves the container bind
//! alone, because a loopback or private bind inside the container is not an
//! address the pasta mapping can reach.
//!
//! A narrow address lives in the generated file only, so every writer reads
//! the map back before rendering it: enabling another service, an `init` rerun
//! or `stack update` must not quietly put a listener back on every host
//! address the operator took away from it.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use super::apply::ApplyError;
use super::compose::{compose_file_path, render_document};
use crate::config::{Listener, ListenerKind};

/// The bind a listener published on a host address uses inside the container.
/// The container side and the address the host reaches can not be the same
/// address: a container-side loopback bind answers nothing through the pasta
/// mapping.
pub(crate) const CONTAINER_BIND: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Render one mapping. An absent host address keeps the
/// `<port>:<port>` form every other writer of the map uses, so a stack nobody
/// narrowed renders the bytes `init` wrote. An IPv6 address goes in brackets:
/// the engine reads the colons in a bare `::1:143:143` as the port separator.
pub(super) fn entry(host: Option<IpAddr>, port: u16) -> String {
	match host {
		Some(IpAddr::V6(address)) => {
			format!("[{address}]:{port}:{port}")
		}
		Some(address) => format!("{address}:{port}:{port}"),
		_ => format!("{port}:{port}"),
	}
}

/// Split one mapping into the host address it fixes and the port it publishes.
/// `143:143`, `127.0.0.1:143:143` and `[::1]:143:143` all parse; anything
/// that does not end in the same port twice is not a mapping of ours.
pub(super) fn parse(mapping: &str) -> Option<(Option<IpAddr>, u16)> {
	let fields: Vec<&str> = mapping.split(':').collect();
	if fields.len() < 2 {
		return None;
	}
	let tail = &fields[fields.len() - 2..];
	let port: u16 = tail[1].parse().ok()?;
	if tail[0].parse::<u16>().ok()? != port {
		return None;
	}
	let host = match fields.len() {
		2 => None,
		_ => Some(
			fields[..fields.len() - 2]
				.join(":")
				.replace(['[', ']'], "")
				.parse()
				.ok()?,
		),
	};
	Some((host, port))
}

/// The host address each mapping of `document` fixes, keyed by the port it
/// publishes. The first mapping for a port wins: two mappings for one port are
/// a conflict the engine refuses to bind, so the file is already broken and the
/// older entry is the one the operator saw last.
pub(super) fn hosts(document: &serde_json::Value) -> BTreeMap<u16, IpAddr> {
	let mut map = BTreeMap::new();
	for mapping in mail_ports(document)
		.iter()
		.filter_map(serde_json::Value::as_str)
	{
		if let Some((Some(address), port)) = parse(mapping) {
			map.entry(port).or_insert(address);
		}
	}
	map
}

/// The narrow addresses the generated file already fixes. A file that cannot
/// be read or parsed yields nothing: the callers are displaying a listing or
/// re-rendering a map, and failing a listing over an unreadable stack file
/// would be worse than showing no host column.
pub(crate) fn hosts_in_file(path: &Path) -> BTreeMap<u16, IpAddr> {
	match std::fs::read(path) {
		Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
			Ok(document) => hosts(&document),
			Err(_) => BTreeMap::new(),
		},
		Err(_) => BTreeMap::new(),
	}
}

/// Map the listeners to the `ports:` array of the `mail` service. Every
/// non-loopback listener is published as `<port>:<port>` so the host port is
/// the same number the listener binds inside the container, on every address
/// the host owns. Loopback listeners (a `127.0.0.1` API, for example) are
/// reachable inside the container through the pasta mapping but not from the
/// host network, so they do not get a `ports:` entry. The list is returned in
/// the same order the listeners appear in the config; the operator reads it in
/// that order in the rendered file.
///
/// `IpAddr::is_loopback` recognises `127.0.0.0/8` and `::1` only. An
/// IPv4-mapped IPv6 form (`::ffff:127.0.0.1`) would otherwise slip past the
/// loopback check and produce a `19123:19123` publish for a listener that only
/// ever sees loopback packets. `to_canonical` collapses the IPv4-mapped form to
/// its IPv4 representation first, so the loopback check sees the address the
/// operator actually bound.
///
/// `narrow` carries the host address each port is already published on, so a
/// change to one listener never widens another one back to every address.
/// `publish` overrides the address of one listener, which is what
/// `epistle service set` asks for.
pub(super) fn published(
	listeners: &[Listener],
	narrow: &BTreeMap<u16, IpAddr>,
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Vec<String> {
	let mut ports = Vec::with_capacity(listeners.len());
	for listener in listeners {
		if listener.addr.to_canonical().is_loopback() {
			continue;
		}
		let port = listener
			.port
			.unwrap_or_else(|| listener.kind.default_port());
		let host = match publish {
			Some((kind, host)) if kind == listener.kind => host,
			_ => narrow.get(&port).copied(),
		};
		ports.push(entry(host, port));
	}
	ports
}

/// The mapping the generated file carries now, next to the one a change would
/// leave in it. A pair of the two, or `None` when there is no compose file.
type Mappings = Option<(Vec<String>, Vec<String>)>;

/// The generated file, its current mapping and the one the listeners ask for.
struct Map {
	path: PathBuf,
	original: Vec<u8>,
	document: serde_json::Value,
	current: Vec<String>,
	wanted: Vec<String>,
}

/// Read the generated map once. `None` means the install has no compose file,
/// so there is no map to compare and none to write.
fn read_map(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Option<Map>, ApplyError> {
	let path = compose_file_path(data_dir);
	let existing = match std::fs::read(&path) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(ApplyError::ConfigRead(path, error)),
	};
	let mut document: serde_json::Value = serde_json::from_slice(&existing)
		.map_err(|error| ApplyError::ConfigEncode(format!("invalid compose JSON: {error}")))?;
	mail_mut(&mut document)?;
	let current = mail_ports(&document)
		.iter()
		.filter_map(serde_json::Value::as_str)
		.map(str::to_string)
		.collect();
	let wanted = published(listeners, &hosts(&document), publish);
	Ok(Some(Map {
		path,
		original: existing,
		document,
		current,
		wanted,
	}))
}

/// The `ports:` map the generated file carries now, and the one the listeners
/// ask for. `None` means the install has no compose file.
pub(crate) fn preview(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Mappings, ApplyError> {
	Ok(read_map(data_dir, listeners, publish)?.map(|map| (map.current, map.wanted)))
}

/// Write the `ports:` map the listeners ask for. `None` means the install has
/// no compose file; `Some(changed)` says whether the file was rewritten.
pub(crate) fn update(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Option<bool>, ApplyError> {
	let Some(Map {
		path,
		mut document,
		current,
		wanted,
		..
	}) = read_map(data_dir, listeners, publish)?
	else {
		return Ok(None);
	};
	if current == wanted {
		return Ok(Some(false));
	}
	mail_mut(&mut document)?.insert("ports".into(), serde_json::json!(wanted));
	let bytes = render_document(&document)?;
	crate::storage::write_secret(&path, bytes.as_bytes())
		.map_err(|error| ApplyError::ConfigWrite(path, error))?;
	Ok(Some(true))
}

/// Render and validate a companion before the TOML can be replaced.
pub(crate) fn prepare(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Option<crate::cli::config_edit::Companion>, ApplyError> {
	let Some(mut map) = read_map(data_dir, listeners, publish)? else {
		return Ok(None);
	};
	if map.current == map.wanted {
		return Ok(None);
	}
	mail_mut(&mut map.document)?.insert("ports".into(), serde_json::json!(map.wanted));
	let candidate = render_document(&map.document)?.into_bytes();
	Ok(Some(crate::cli::config_edit::Companion {
		path: map.path,
		original: map.original,
		candidate,
	}))
}

/// Whether the operator's override already publishes one of `ports` for `mail`.
/// Every stack invocation passes `compose.override.yaml` after
/// `compose.yaml` (`epistle stack` builds that argv), so a mapping in it wins
/// over the generated one and the operator has to hear that.
///
/// The override is YAML and no YAML parser ships in the binary, so this scans
/// the `mail` block for the numbers a `ports:` item carries. A mapping
/// publishes `[ADDRESS:]PORT:PORT`, so `143` in an item names the port; other
/// values in the block (a memory limit, an image tag) are not ports and do not
/// match. A file this scan cannot make sense of reports `false`: the warning is
/// advice, and refusing a valid change over it would be worse.
pub(crate) fn override_publishes(data_dir: &Path, ports: &[u16]) -> bool {
	let path = compose_file_path(data_dir).with_file_name("compose.override.yaml");
	let Ok(text) = std::fs::read_to_string(path) else {
		return false;
	};
	let mut mail_at: Option<usize> = None;
	let mut list_at: Option<usize> = None;
	for line in text.lines() {
		let indent = indent(line);
		let body = line.trim();
		if body.is_empty() || body.starts_with('#') {
			continue;
		}
		if mail_at.is_some_and(|at| indent <= at) {
			mail_at = None;
		}
		if list_at.is_some_and(|at| indent <= at) {
			list_at = None;
		}
		if list_at.is_some() {
			if publishes(body.trim_start_matches('-'), ports) {
				return true;
			}
			continue;
		}
		if mail_at.is_none() {
			mail_at = body
				.strip_suffix(':')
				.filter(|key| *key == "mail")
				.map(|_| indent);
			continue;
		}
		let (key, rest) = body.split_once(':').unwrap_or((body, ""));
		if key.trim() == "ports" {
			// The list can sit on this line (`ports: ["143:143"]`) or on
			// the lines below it, indented (`ports: !override` plus items).
			if publishes(rest, ports) {
				return true;
			}
			list_at = Some(indent);
		}
	}
	false
}

/// Whether a `ports:` value names one of `ports`. A mapping is
/// `[ADDRESS:]PORT:PORT`, so the numbers are the ports; `!override`, a
/// comment and an empty value carry none and never match.
fn publishes(value: &str, ports: &[u16]) -> bool {
	value
		.split(|c: char| {
			c.is_whitespace() || matches!(c, ':' | ',' | '[' | ']' | '{' | '}' | '"' | '\'')
		})
		.map(|field| field.trim().trim_matches(['"', '\'']))
		.any(|field| ports.iter().any(|port| *field == port.to_string()))
}

/// The column a line is indented by.
fn indent(line: &str) -> usize {
	line.len() - line.trim_start().len()
}

/// The `ports:` array of the `mail` service, empty when the file has none.
fn mail_ports(document: &serde_json::Value) -> &[serde_json::Value] {
	document
		.get("services")
		.and_then(|services| services.get("mail"))
		.and_then(|mail| mail.get("ports"))
		.and_then(serde_json::Value::as_array)
		.map(Vec::as_slice)
		.unwrap_or_default()
}

/// The `mail` service object, which the map only makes sense inside.
fn mail_mut(
	document: &mut serde_json::Value,
) -> Result<&mut serde_json::Map<String, serde_json::Value>, ApplyError> {
	document
		.get_mut("services")
		.and_then(|services| services.get_mut("mail"))
		.and_then(serde_json::Value::as_object_mut)
		.ok_or_else(|| ApplyError::ConfigEncode("compose services.mail must be an object".into()))
}

#[cfg(test)]
#[path = "compose_publish_tests.rs"]
mod tests;
