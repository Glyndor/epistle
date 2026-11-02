//! The rows `podup ps --format json` prints and the table `epistle stack ps`
//! renders from them. Split from `mod.rs`.

use serde::{Deserialize, Serialize};

/// One row in the JSON podup prints. Only the fields the table
/// renders are decoded; anything else is left in `extra` so a future
/// podup release that adds columns does not break the parser. The
/// `deny_unknown_fields` default is intentionally *not* set here.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct PsEntry {
	/// Service name from the compose file.
	#[serde(rename = "Service")]
	pub(super) service: String,
	/// Podman state string (`"running"`, `"exited"`, ...).
	#[serde(rename = "State")]
	pub(super) state: String,
	/// Healthcheck status. `""` when the container has no healthcheck.
	#[serde(rename = "Health", default)]
	pub(super) health: String,
	/// Last observed process exit code.
	#[serde(rename = "ExitCode")]
	pub(super) exit_code: i64,
	/// Image the container was started from.
	#[serde(rename = "Image")]
	pub(super) image: String,
	/// Published ports: one entry per `host:port -> target/proto`
	/// mapping. Empty for services that publish nothing.
	#[serde(rename = "Publishers", default)]
	pub(super) publishers: Vec<Publisher>,
}

/// One published port mapping.
#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Publisher {
	/// `host:port` the operator connects to. Empty for
	/// `network_mode: host` mappings.
	#[serde(rename = "URL", default)]
	pub(super) url: String,
	/// Port the process inside the container listens on.
	#[serde(rename = "TargetPort")]
	pub(super) target_port: u16,
	/// Port the host actually binds (may differ from `URL` after
	/// `0:0` random allocation). podup 5.10.10 emits `null` when
	/// the port is exposed inside the container network but has no
	/// host binding; treating it as a plain `u16` would reject the
	/// whole service array, so the field is optional.
	#[serde(rename = "PublishedPort")]
	pub(super) published_port: Option<u16>,
	/// Protocol: `tcp` or `udp`.
	#[serde(rename = "Protocol")]
	pub(super) protocol: String,
}

/// Print the parsed `ps` rows as an aligned table to `out`. Three
/// columns: service, state, then `health (or -) / ports` so a
/// non-empty row stays one line. The "published ports" cell is the
/// one a human reaches for, so it gets a separate helper. A write
/// failure is returned so the caller can map it to a non-zero exit
/// (redirecting the table to a full disk must not pass silently).
pub(super) fn print_table(
	entries: &[PsEntry],
	out: &mut impl std::io::Write,
) -> std::io::Result<()> {
	for entry in entries {
		let health = if entry.health.is_empty() {
			"-"
		} else {
			&entry.health
		};
		let ports = format_ports(&entry.publishers);
		writeln!(
			out,
			"{service}\t{state}\t{health}\t{ports}",
			service = entry.service,
			state = entry.state,
			health = health,
			ports = ports
		)?;
	}
	Ok(())
}

/// Render one cell's worth of published ports: every mapping becomes
/// `host:port->target/proto` and they are joined with a comma. A
/// mapping that podup reports without a host binding (the
/// `PublishedPort: null` case) drops the `host:port->` prefix and
/// renders as `target/proto` so the cell still carries the protocol
/// the operator needs to recognise the service. An empty list
/// renders as `-` so the table does not carry blank cells.
pub(super) fn format_ports(publishers: &[Publisher]) -> String {
	if publishers.is_empty() {
		return "-".to_string();
	}
	let parts: Vec<String> = publishers
		.iter()
		.map(|p| match p.published_port {
			Some(published) => format!(
				"{host}:{published}->{target}/{proto}",
				host = p.url,
				published = published,
				target = p.target_port,
				proto = p.protocol
			),
			None => format!(
				"{target}/{proto}",
				target = p.target_port,
				proto = p.protocol
			),
		})
		.collect();
	parts.join(",")
}
