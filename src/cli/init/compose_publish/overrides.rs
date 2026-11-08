//! What the operator's override does with the generated map.
//!
//! Every stack invocation passes `compose.override.yaml` after
//! `compose.yaml` (`epistle stack` builds that argv), so a mapping in it is
//! merged with the generated one, or replaces it where it carries
//! `!override`. A command that writes the generated map has to know which of
//! the two it is: an override that replaces it decides where a port is
//! published, and the generated entry is never used.
//!
//! The override is YAML and no YAML parser ships in the binary, so this scans
//! the `mail` block for the numbers a `ports:` item carries. A mapping
//! publishes `[ADDRESS:]PORT:PORT`, so `143` in an item names the port; other
//! values in the block (a memory limit, an image tag) are not ports and do not
//! match. The block is found in the block form (`mail:` on its own line), in
//! flow style (`mail: {ports: [...]}`) and with the key quoted. What the scan
//! can not see is a `ports` key it does not reach: one behind an anchor, an
//! alias, or a value a template fills in at run time.

use std::net::IpAddr;
use std::path::Path;

use super::super::compose::compose_file_path;
use super::super::compose_read;
use super::parse;

/// What the operator's override does with the `ports:` list of the `mail`
/// service.
#[derive(Debug, Clone, Default)]
pub(crate) struct OverridePorts {
	/// Whether the override replaces the generated list instead of adding to
	/// it: the `!override` tag on the list, or on the service that carries
	/// it.
	pub(crate) replaces: bool,
	/// The entries that name one of the ports asked about, in the order the
	/// file lists them.
	pub(crate) entries: Vec<OverrideEntry>,
}

impl OverridePorts {
	/// Whether the override publishes one of the ports asked about.
	pub(crate) fn publishes(&self) -> bool {
		!self.entries.is_empty()
	}

	/// The first entry that names `port`.
	pub(crate) fn entry(&self, port: u16) -> Option<&OverrideEntry> {
		self.entries
			.iter()
			.find(|entry| entry.ports.contains(&port))
	}
}

/// One entry of the operator's override that names a port the stack
/// publishes.
#[derive(Debug, Clone)]
pub(crate) struct OverrideEntry {
	/// The line the entry is on, counted from one.
	pub(crate) line: usize,
	/// The text of the entry, as the operator wrote it.
	pub(crate) text: String,
	/// The ports of the ones asked about that the entry names.
	pub(crate) ports: Vec<u16>,
	/// The host address the entry publishes the port on, `None` when it
	/// publishes on every address of the host.
	pub(crate) address: Option<IpAddr>,
}

/// What the operator's override does with the `ports:` list of the `mail`
/// service, and the entries of that list that name one of `ports`.
pub(crate) fn override_ports(data_dir: &Path, ports: &[u16]) -> OverridePorts {
	let path = compose_file_path(data_dir).with_file_name("compose.override.yaml");
	let Ok(text) = compose_read::read(&path).map(|read| read.unwrap_or_default()) else {
		return OverridePorts::default();
	};
	let Ok(text) = String::from_utf8(text) else {
		return OverridePorts::default();
	};
	scan(&text, ports)
}

/// The `ports:` list of the `mail` service in the override, with the tag it
/// carries and the entries that name a port.
fn scan(text: &str, ports: &[u16]) -> OverridePorts {
	let mut found = OverridePorts::default();
	let mut mail_at: Option<usize> = None;
	let mut service_replaces = false;
	let mut list_at: Option<usize> = None;
	for (number, line) in text.lines().enumerate() {
		let indent = indent(line);
		let body = line.trim();
		if body.is_empty() || body.starts_with('#') {
			continue;
		}
		if mail_at.is_some_and(|at| indent <= at) {
			mail_at = None;
			service_replaces = false;
		}
		if list_at.is_some_and(|at| indent <= at) {
			list_at = None;
		}
		if list_at.is_some() {
			// An item of the list.
			found
				.entries
				.extend(entry(number + 1, body.trim_start_matches('-'), ports));
			continue;
		}
		if mail_at.is_none() {
			let Some(value) = value_of(body, "mail") else {
				continue;
			};
			let (value, tagged) = strip_tag(value);
			match value.trim().strip_prefix('{') {
				Some(flow) => {
					// `mail: {ports: [...]}` carries the block on one line,
					// so there is nothing to indent into: the answer comes
					// from the line.
					let flow = flow.strip_suffix('}').unwrap_or(flow);
					let (replaces, entries) = flow_ports(flow, ports, number + 1);
					found.replaces |= replaces || tagged;
					found.entries.extend(entries);
				}
				None => {
					if value.trim().is_empty() {
						mail_at = Some(indent);
						service_replaces = tagged;
					}
				}
			}
			continue;
		}
		// The list can sit on this line (`ports: ["143:143"]`) or on the
		// lines below it, indented (`ports: !override` plus items).
		let Some(value) = value_of(body, "ports") else {
			continue;
		};
		let (value, tagged) = strip_tag(value);
		if tagged || service_replaces {
			found.replaces = true;
		}
		found.entries.extend(list_entries(value, ports, number + 1));
		list_at = Some(indent);
	}
	found
}

/// The `ports:` entries of a flow-style `mail:` block, and whether the block
/// replaces the generated list.
fn flow_ports(block: &str, ports: &[u16], line: usize) -> (bool, Vec<OverrideEntry>) {
	let mut replaces = false;
	let mut entries = Vec::new();
	for item in flow_items(block) {
		let Some(value) = value_of(item.trim(), "ports") else {
			continue;
		};
		let (value, tagged) = strip_tag(value);
		replaces |= tagged;
		entries.extend(list_entries(value, ports, line));
	}
	(replaces, entries)
}

/// The entries of a `ports:` value that name one of `ports`. The value is
/// either a list on one line (`["143:143"]`) or the tag of a list that
/// follows (`!override`).
fn list_entries(value: &str, ports: &[u16], line: usize) -> Vec<OverrideEntry> {
	let value = value.trim();
	let Some(flow) = value.strip_prefix('[') else {
		// A value that is not a list names the port on its own.
		return entry(line, value, ports);
	};
	let flow = flow.strip_suffix(']').unwrap_or(flow);
	flow_items(flow)
		.into_iter()
		.flat_map(|item| entry(line, item.trim(), ports))
		.collect()
}

/// One entry of a `ports:` list, with the ports it names and the address it
/// publishes them on. An entry that names none of the ports asked about is
/// not one of them.
fn entry(line: usize, item: &str, ports: &[u16]) -> Vec<OverrideEntry> {
	let text = item.trim();
	let named = named_ports(text, ports);
	if named.is_empty() {
		return Vec::new();
	}
	let mapping = text.trim_matches(['"', '\'']);
	let address = parse(mapping)
		.and_then(|(address, _)| address)
		.filter(|address| !address.to_canonical().is_unspecified());
	vec![OverrideEntry {
		line,
		text: text.to_string(),
		ports: named,
		address,
	}]
}

/// The value of `key: value` in one line of the override, with the key
/// unquoted. `None` when the line does not open that key.
fn value_of<'a>(line: &'a str, key: &str) -> Option<&'a str> {
	let (name, value) = line.split_once(':')?;
	(name.trim().trim_matches(['"', '\'']) == key).then_some(value)
}

/// The value of a YAML key without the `!override` tag it may carry, and
/// whether it carried one.
fn strip_tag(value: &str) -> (&str, bool) {
	let value = value.trim();
	let Some(rest) = value.strip_prefix("!override") else {
		return (value, false);
	};
	let word = rest.starts_with(|character: char| {
		character.is_alphanumeric() || character == '_' || character == '-'
	});
	if word {
		return (value, false);
	}
	(rest.trim(), true)
}

/// The ports of `ports` that a `ports:` value names. A mapping is
/// `[ADDRESS:]PORT:PORT` and an item may be a range of them, so the numbers
/// and the ranges are the ports; `!override`, a comment, a key and an empty
/// value carry none and never match.
fn named_ports(value: &str, ports: &[u16]) -> Vec<u16> {
	let mut named: Vec<u16> = value
		.split(|character: char| {
			character.is_whitespace()
				|| matches!(character, ':' | ',' | '[' | ']' | '{' | '}' | '"' | '\'')
		})
		.map(|field| field.trim().trim_matches(['"', '\'']))
		.flat_map(|field| ports.iter().copied().filter(|port| names(field, *port)))
		.collect();
	named.sort_unstable();
	named.dedup();
	named
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

/// The column a line is indented by.
fn indent(line: &str) -> usize {
	line.len() - line.trim_start().len()
}
