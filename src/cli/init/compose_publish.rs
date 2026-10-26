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
//! address the operator took away from it. A listener that serves HTTP without
//! TLS does not need the map to remember anything: it stays on loopback
//! whenever the map has no address for it, and a wildcard in the map is the
//! same wide publication as the bare form, so it narrows with it.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use super::apply::ApplyError;
use super::compose::{compose_file_path, render_document};
use super::compose_read;
use crate::config::{Config, Listener, ListenerKind};

/// The bind a listener published on a host address uses inside the container.
/// The container side and the address the host reaches can not be the same
/// address: a container-side loopback bind answers nothing through the pasta
/// mapping.
pub(crate) const CONTAINER_BIND: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The unspecified bind of the IPv6 family, which is also dual-stack: the
/// container side of a mapping published on an IPv6 host address, and what
/// `init` writes for a listener that inherits SMTP's bind.
pub(crate) const CONTAINER_BIND_DUAL: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

/// Whether a listener answers HTTP that no TLS transport protects. Mail
/// certificates do not encrypt these, so they belong behind a TLS terminator
/// on loopback, and one definition of that rule decides both what `epistle
/// service set` accepts and what the generated map publishes.
pub(crate) fn plain_http(kind: ListenerKind) -> bool {
	matches!(
		kind,
		ListenerKind::Api | ListenerKind::WebDav | ListenerKind::Autoconfig
	)
}

/// The address a listener that serves HTTP without TLS is published on when
/// nothing has narrowed it. The bind in `mail.toml` is the one inside the
/// container, so it can not carry the decision the operator made on the host,
/// and a regeneration that lost the map would otherwise put these listeners on
/// every address of the machine.
fn plain_http_host(kind: ListenerKind) -> Option<IpAddr> {
	plain_http(kind).then_some(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Render one mapping. An absent host address, and an unspecified one, keep
/// the `<port>:<port>` form every other writer of the map uses, so a stack
/// nobody narrowed renders the bytes `init` wrote. A wildcard publishes on
/// every address the host owns either way, and the explicit
/// `0.0.0.0:PORT:PORT` and `[::]:PORT:PORT` forms were measured to be refused
/// by pasta on Podman 5.4.2, so neither is written. An IPv6 address goes in
/// brackets: the engine reads the colons in a bare `::1:143:143` as the port
/// separator.
pub(super) fn entry(host: Option<IpAddr>, port: u16) -> String {
	match host {
		Some(IpAddr::V6(address)) if !address.is_unspecified() => {
			format!("[{address}]:{port}:{port}")
		}
		Some(IpAddr::V4(address)) if !address.is_unspecified() => {
			format!("{address}:{port}:{port}")
		}
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

/// The narrow addresses the generated file already fixes. A file that does
/// not parse yields nothing: the callers are re-rendering a map, and a
/// generated file no parser can read is one the next write replaces whole.
/// A file that can not be read at all is an error: it is a FIFO or a device at
/// the path, and a listing that hid it would leave a command with no way to
/// tell the operator that the stack file is not a file.
pub(crate) fn hosts_in_file(path: &Path) -> Result<BTreeMap<u16, IpAddr>, String> {
	Ok(document_in_file(path)?
		.as_ref()
		.map(hosts)
		.unwrap_or_default())
}

/// The generated file as a document, `None` when it is not there or does not
/// parse.
fn document_in_file(path: &Path) -> Result<Option<serde_json::Value>, String> {
	let Some(bytes) = compose_read::read(path)? else {
		return Ok(None);
	};
	Ok(serde_json::from_slice::<serde_json::Value>(&bytes).ok())
}

/// The `ports:` list `document` carries, in the order it lists them.
pub(super) fn ports(document: &serde_json::Value) -> Vec<String> {
	mail_ports(document)
		.iter()
		.filter_map(serde_json::Value::as_str)
		.map(str::to_string)
		.collect()
}

/// The `ports:` list the generated file carries now, empty when it is not there
/// or does not parse.
pub(crate) fn ports_in_file(path: &Path) -> Result<Vec<String>, String> {
	Ok(document_in_file(path)?
		.as_ref()
		.map(ports)
		.unwrap_or_default())
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
			Some((kind, Some(address))) if kind == listener.kind => Some(address),
			// No address asked for and none in the map: every listener keeps
			// the form `init` wrote, except one that serves HTTP without TLS,
			// which stays on loopback behind the operator's proxy. Both
			// wildcards in the map are that same wide publication as the bare
			// form, so they narrow with it; an address the operator chose for
			// one of these listeners is their decision and stays.
			_ => narrow
				.get(&port)
				.copied()
				.filter(|address| {
					!plain_http(listener.kind) || !address.to_canonical().is_unspecified()
				})
				.or_else(|| plain_http_host(listener.kind)),
		};
		ports.push(entry(host, port));
	}
	ports
}

/// The mapping the generated file carries now, next to the one a change would
/// leave in it. A pair of the two, or `None` when there is no compose file.
type Mappings = Option<(Vec<String>, Vec<String>)>;

/// A publication a change takes off every address of the host, because the
/// listener behind it carries HTTP without TLS and belongs behind a TLS
/// terminator on loopback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Narrowed {
	/// The listener behind the publication, as the operator names it.
	pub(crate) service: &'static str,
	/// The port it answers on.
	pub(crate) port: u16,
	/// The mapping the file carries now, on every address of the host.
	pub(crate) before: String,
	/// The mapping the change writes.
	pub(crate) after: String,
}

impl std::fmt::Display for Narrowed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(
			f,
			"{} ({}) was published on {} on every address of the host; it carries HTTP without TLS, \
			 so it is now published on {}. To reach it from another host, publish its port in \
			 compose.override.yaml behind a TLS reverse proxy.",
			self.service, self.port, self.before, self.after
		)
	}
}

/// The publications that move off every address of the host between the two
/// maps. The bare `PORT:PORT` form and both wildcards are that same wide
/// publication, and a concrete address is not this rule: it belongs to the
/// operator.
pub(crate) fn narrowed(
	listeners: &[Listener],
	current: &[String],
	wanted: &[String],
) -> Vec<Narrowed> {
	let mut moved = Vec::new();
	for listener in listeners {
		if !plain_http(listener.kind) || listener.addr.to_canonical().is_loopback() {
			continue;
		}
		let port = listener
			.port
			.unwrap_or_else(|| listener.kind.default_port());
		let before = current.iter().find(|line| wide(line, port)).cloned();
		let after = wanted.iter().find(|line| on_loopback(line, port)).cloned();
		if let (Some(before), Some(after)) = (before, after) {
			moved.push(Narrowed {
				service: listener.kind.as_str(),
				port,
				before,
				after,
			});
		}
	}
	moved
}

/// Whether the two maps differ by nothing but those publications leaving every
/// address of the host. The command that writes them says what moved, so a
/// warning that the two files disagree would only repeat it wrongly.
fn only_narrowed(listeners: &[Listener], current: &[String], wanted: &[String]) -> bool {
	let moved = narrowed(listeners, current, wanted);
	let mut left: Vec<&str> = current
		.iter()
		.map(String::as_str)
		.filter(|line| !moved.iter().any(|one| one.before == **line))
		.collect();
	let mut right: Vec<&str> = wanted
		.iter()
		.map(String::as_str)
		.filter(|line| !moved.iter().any(|one| one.after == **line))
		.collect();
	left.sort_unstable();
	right.sort_unstable();
	left == right
}

/// Whether `line` publishes `port` on every address of the host, which the bare
/// form and both wildcards do.
fn wide(line: &str, port: u16) -> bool {
	matches!(parse(line), Some((host, published)) if published == port
		&& host.is_none_or(|address| address.to_canonical().is_unspecified()))
}

/// Whether `line` publishes `port` on loopback.
fn on_loopback(line: &str, port: u16) -> bool {
	matches!(parse(line), Some((Some(address), published))
		if published == port && address.to_canonical().is_loopback())
}

/// Say on stderr which publications a change takes off every address of the
/// host. Cutting a service off the public interfaces is not something to do
/// quietly, and the note is the only place the operator hears it.
pub(crate) fn announce_narrowed(moved: &[Narrowed], status: &mut impl Write) {
	for one in moved {
		crate::cli::style::warn_to(status, format_args!("{one}"));
	}
}

/// The generated file, its current mapping and the one the listeners ask for.
struct Map {
	path: PathBuf,
	original: Vec<u8>,
	document: serde_json::Value,
	current: Vec<String>,
	wanted: Vec<String>,
}

/// A read that failed, in the shape every other config read of this command
/// reports: the path it could not read and the reason.
pub(super) fn apply_read(path: &Path, error: String) -> ApplyError {
	ApplyError::ConfigRead(path.into(), std::io::Error::other(error))
}

/// Read the generated map once. `None` means the install has no compose file,
/// so there is no map to compare and none to write.
fn read_map(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Option<Map>, ApplyError> {
	let path = compose_file_path(data_dir);
	let existing = match compose_read::read(&path) {
		Ok(Some(bytes)) => bytes,
		Ok(None) => return Ok(None),
		Err(error) => return Err(apply_read(&path, error)),
	};
	let mut document: serde_json::Value = serde_json::from_slice(&existing)
		.map_err(|error| ApplyError::ConfigEncode(format!("invalid compose JSON: {error}")))?;
	mail_mut(&mut document)?;
	let current = ports(&document);
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

/// Say on stderr when the generated map and the configuration the command read
/// describe different ports. A hand edit of a port or a publication leaves one
/// behind, and so does a command killed between its two renames. The caller
/// holds the common lock and is about to bring the two together, so this is
/// where the operator hears about it.
pub(crate) fn announce_mixed_state(config: &Config, status: &mut impl Write) {
	let Ok(Some((current, wanted))) = preview(&config.data_dir, &config.listeners, None) else {
		return;
	};
	if current == wanted {
		return;
	}
	// A publication leaving every address of the host is named as what it is by
	// the command that writes it, so nothing is said about the two files
	// disagreeing when that is all they disagree about.
	if only_narrowed(&config.listeners, &current, &wanted) {
		return;
	}
	crate::cli::style::warn_to(
		status,
		format_args!(
			"the generated compose.yaml and mail.toml publish different ports \
		 (compose.yaml: [{}]; mail.toml: [{}]); this command brings the two together",
			current.join(", "),
			wanted.join(", ")
		),
	);
}

/// What a change to the generated map stages: the companion file, and the
/// publications the write takes off every address of the host.
pub(crate) struct Prepared {
	/// The staged file, `None` when the map does not move.
	pub(crate) companion: Option<crate::cli::config_edit::Companion>,
	/// The publications this write takes off every address of the host.
	pub(crate) narrowed: Vec<Narrowed>,
}

/// Render and validate a companion before the TOML can be replaced.
pub(crate) fn prepare(
	data_dir: &Path,
	listeners: &[Listener],
	publish: Option<(ListenerKind, Option<IpAddr>)>,
) -> Result<Prepared, ApplyError> {
	// A command killed between its two renames leaves its staged copies of
	// this file here. The caller holds the common lock, so whatever is left
	// belongs to a command that is not running.
	let generated = compose_file_path(data_dir);
	crate::cli::config_edit::announce_swept(&crate::cli::config_edit::sweep_orphans(
		generated.parent().unwrap_or(data_dir),
	));
	let Some(mut map) = read_map(data_dir, listeners, publish)? else {
		return Ok(Prepared {
			companion: None,
			narrowed: Vec::new(),
		});
	};
	if map.current == map.wanted {
		return Ok(Prepared {
			companion: None,
			narrowed: Vec::new(),
		});
	}
	let moved = narrowed(listeners, &map.current, &map.wanted);
	mail_mut(&mut map.document)?.insert("ports".into(), serde_json::json!(map.wanted));
	let candidate = render_document(&map.document)?.into_bytes();
	Ok(Prepared {
		companion: Some(crate::cli::config_edit::Companion {
			path: map.path,
			original: map.original,
			candidate,
		}),
		narrowed: moved,
	})
}

/// Whether the operator's override already publishes one of `ports` for `mail`.
/// Every stack invocation passes `compose.override.yaml` after
/// `compose.yaml` (`epistle stack` builds that argv), so a mapping in it is
/// merged with the generated one, or replaces it, and the operator has to hear
/// that.
///
/// The override is YAML and no YAML parser ships in the binary, so this scans
/// the `mail` block for the numbers a `ports:` item carries. A mapping
/// publishes `[ADDRESS:]PORT:PORT`, so `143` in an item names the port; other
/// values in the block (a memory limit, an image tag) are not ports and do not
/// match. The block is found in the block form (`mail:` on its own line), in
/// flow style (`mail: {ports: [...]}`) and with the key quoted. A file this
/// scan cannot make sense of reports `false`: the warning is advice, and
/// refusing a valid change over it would be worse. What the scan can not see is
/// a `ports` key it does not reach: one behind an anchor, an alias, or a value
/// a template fills in at run time.
pub(crate) fn override_publishes(data_dir: &Path, ports: &[u16]) -> bool {
	let path = compose_file_path(data_dir).with_file_name("compose.override.yaml");
	let Ok(text) = compose_read::read(&path).map(|read| read.unwrap_or_default()) else {
		return false;
	};
	let Ok(text) = String::from_utf8(text) else {
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
			let Some(value) = value_of(body, "mail") else {
				continue;
			};
			// `mail: {ports: [...]}` carries the block on one line, so there
			// is nothing to indent into: the answer comes from the line.
			match value.trim().strip_prefix('{') {
				Some(flow) => {
					if flow_publishes(flow, ports) {
						return true;
					}
				}
				None => {
					if value.trim().is_empty() {
						mail_at = Some(indent);
					}
				}
			}
			continue;
		}
		// The list can sit on this line (`ports: ["143:143"]`) or on
		// the lines below it, indented (`ports: !override` plus items).
		let Some(value) = value_of(body, "ports") else {
			continue;
		};
		if publishes(value, ports) {
			return true;
		}
		list_at = Some(indent);
	}
	false
}

/// The value of `key: value` in one line of the override, with the key
/// unquoted. `None` when the line does not open that key.
fn value_of<'a>(line: &'a str, key: &str) -> Option<&'a str> {
	let (name, value) = line.split_once(':')?;
	(name.trim().trim_matches(['"', '\'']) == key).then_some(value)
}

/// Whether a flow-style block names one of `ports` in a `ports` key. The
/// braces are already off the value, so each item is one mapping entry and
/// only the one that opens `ports` carries the numbers.
fn flow_publishes(block: &str, ports: &[u16]) -> bool {
	flow_items(block)
		.into_iter()
		.filter_map(|item| value_of(item.trim(), "ports"))
		.any(|value| publishes(value, ports))
}

/// The comma-separated items of a flow block. A comma inside a nested list or
/// mapping separates values, not entries, so only the ones at the outermost
/// level end an item.
fn flow_items(block: &str) -> Vec<&str> {
	let (mut items, mut start, mut depth) = (Vec::new(), 0, 0usize);
	for (at, character) in block.char_indices() {
		match character {
			'[' | '{' => depth += 1,
			']' | '}' => depth = depth.saturating_sub(1),
			',' if depth == 0 => {
				items.push(&block[start..at]);
				start = at + character.len_utf8();
			}
			_ => {}
		}
	}
	items.push(&block[start..]);
	items
}

/// Whether a `ports:` value names one of `ports`. A mapping is
/// `[ADDRESS:]PORT:PORT` and an item may be a range of them, so the numbers
/// and the ranges are the ports; `!override`, a comment, a key and an empty
/// value carry none and never match.
fn publishes(value: &str, ports: &[u16]) -> bool {
	value
		.split(|c: char| {
			c.is_whitespace() || matches!(c, ':' | ',' | '[' | ']' | '{' | '}' | '"' | '\'')
		})
		.map(|field| field.trim().trim_matches(['"', '\'']))
		.any(|field| ports.iter().any(|port| names(field, *port)))
}

/// Whether one item of a `ports:` list names `port`, either as the number
/// itself or as a range of numbers that carries it.
fn names(item: &str, port: u16) -> bool {
	match item.split_once('-') {
		Some((from, to)) => match (from.parse::<u16>(), to.parse::<u16>()) {
			(Ok(from), Ok(to)) => (from..=to).contains(&port),
			_ => false,
		},
		None => item.parse::<u16>().is_ok_and(|named| named == port),
	}
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

#[cfg(test)]
#[path = "compose_publish_http_tests.rs"]
mod tests_http;
