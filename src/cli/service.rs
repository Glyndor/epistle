//! Listener administration without regenerating the installation configuration.

use std::collections::BTreeMap;
use std::io::Write;

use super::term::table::Table;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use serde::Serialize;

use crate::config::{Config, ListenerKind};

/// Listener administration actions.
#[derive(Debug, Subcommand)]
pub enum ServiceCli {
	/// Show enabled and disabled services with their listener sockets.
	List {
		/// Print service records as JSON.
		#[arg(long)]
		json: bool,
	},
	/// Enable one service listener.
	Enable {
		/// Service to enable.
		#[arg(value_enum)]
		name: ServiceName,
	},
	/// Disable one optional service listener.
	Disable {
		/// Service to disable. SMTP is required for inbound mail.
		#[arg(value_enum)]
		name: ServiceName,
	},
	/// Move one enabled service listener to another address, port, or both.
	Set {
		/// Service to move. It has to be enabled already.
		#[arg(value_enum)]
		name: ServiceName,
		/// Address the host reaches the service on. On a stack install this
		/// is the host side of the generated compose mapping.
		#[arg(long, value_name = "ADDRESS")]
		bind: Option<IpAddr>,
		/// Port the service answers on.
		#[arg(long, value_name = "PORT")]
		port: Option<u16>,
	},
}

/// Operator names for independently managed listeners.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ServiceName {
	/// Inbound SMTP on port 25, always required.
	Smtp,
	/// IMAP with STARTTLS on port 143.
	Imap,
	/// IMAP with implicit TLS on port 993.
	Imaps,
	/// Submission with STARTTLS on port 587.
	Submission,
	/// Submission with implicit TLS on port 465.
	Submissions,
	/// POP3 with implicit TLS on port 995.
	Pop3,
	/// ManageSieve on port 4190.
	Managesieve,
	/// WebDAV on port 8090.
	Webdav,
	/// Management API on loopback port 8025.
	Api,
}

impl ServiceName {
	pub(super) fn kind(self) -> ListenerKind {
		match self {
			Self::Smtp => ListenerKind::Smtp,
			Self::Imap => ListenerKind::Imap,
			Self::Imaps => ListenerKind::Imaps,
			Self::Submission => ListenerKind::Submission,
			Self::Submissions => ListenerKind::Submissions,
			Self::Pop3 => ListenerKind::Pop3s,
			Self::Managesieve => ListenerKind::ManageSieve,
			Self::Webdav => ListenerKind::WebDav,
			Self::Api => ListenerKind::Api,
		}
	}

	pub(super) fn as_str(self) -> &'static str {
		match self {
			Self::Pop3 => "pop3",
			Self::Managesieve => "managesieve",
			Self::Webdav => "webdav",
			other => other.kind().as_str(),
		}
	}
}

#[derive(Serialize)]
struct Row {
	name: &'static str,
	enabled: bool,
	port: u16,
	bind: IpAddr,
	/// Host address the generated compose map publishes this service on.
	/// Left out of the JSON when no stack fixes one, so a host install and a
	/// stack nobody narrowed still print the records they printed before.
	#[serde(skip_serializing_if = "Option::is_none")]
	host: Option<IpAddr>,
}

impl Row {
	fn new(
		name: &'static str,
		enabled: bool,
		port: u16,
		bind: IpAddr,
		hosts: &BTreeMap<u16, IpAddr>,
	) -> Self {
		Self {
			name,
			enabled,
			port,
			bind,
			host: enabled.then(|| hosts.get(&port).copied()).flatten(),
		}
	}
}

/// The bind a listener gets when a command enables it: the one SMTP already
/// answers on, except for the listeners that serve HTTP without TLS. Mail
/// certificates do not encrypt those, so they start closed and the operator
/// opens them with `epistle service set <name> --bind 127.0.0.1`.
pub(super) fn default_bind(config: &Config, kind: ListenerKind) -> IpAddr {
	if super::init::serves_plain_http(kind) {
		IpAddr::V4(Ipv4Addr::LOCALHOST)
	} else {
		config
			.listeners
			.iter()
			.find(|listener| listener.kind == ListenerKind::Smtp)
			.map(|listener| listener.addr)
			.unwrap_or(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
	}
}

pub(super) fn list(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
	let hosts =
		super::init::published_host_addresses(&super::init::compose_file_path(&config.data_dir));
	let mut rows = Vec::new();
	let names = ServiceName::value_variants();
	for &name in names {
		let kind = name.kind();
		let matches: Vec<_> = config
			.listeners
			.iter()
			.filter(|listener| listener.kind == kind)
			.collect();
		if matches.is_empty() {
			rows.push(Row::new(
				name.as_str(),
				false,
				kind.default_port(),
				default_bind(config, kind),
				&hosts,
			));
		} else {
			for listener in matches {
				rows.push(Row::new(
					name.as_str(),
					true,
					listener.socket_addr().port(),
					listener.addr,
					&hosts,
				));
			}
		}
	}
	for listener in &config.listeners {
		if !names.iter().any(|name| name.kind() == listener.kind) {
			rows.push(Row::new(
				listener.kind.as_str(),
				true,
				listener.socket_addr().port(),
				listener.addr,
				&hosts,
			));
		}
	}
	// The host column earns its place only where a stack pins the host side
	// of a mapping; without one the listing is the four columns it always was.
	let host_column = rows.iter().any(|row| row.host.is_some());
	if json {
		serde_json::to_writer(&mut *out, &rows).map_err(|e| e.to_string())?;
		writeln!(out).map_err(|e| e.to_string())?;
	} else if let Some(decor) = super::term::stdout(json) {
		let mut table = Table::new(headers(host_column)).state_col(1);
		for row in rows {
			let mut cells = cells(&row, host_column);
			cells[1] = if row.enabled { "enabled" } else { "disabled" }.into();
			table.push(cells);
		}
		table.write(decor, out).map_err(|e| e.to_string())?;
	} else {
		writeln!(out, "{}", line_head(host_column)).map_err(|e| e.to_string())?;
		for row in rows {
			let state = if row.enabled { "enabled" } else { "disabled" };
			let host = row
				.host
				.map_or_else(|| "-".to_string(), |host| host.to_string());
			if host_column {
				writeln!(
					out,
					"{:<13} {:<9} {:<6} {:<20} {}",
					row.name, state, row.port, row.bind, host
				)
			} else {
				writeln!(
					out,
					"{:<13} {:<9} {:<6} {}",
					row.name, state, row.port, row.bind
				)
			}
			.map_err(|e| e.to_string())?;
		}
	}
	Ok(())
}

/// The column names of the listing, with the host address only where the
/// generated compose map pins one.
fn headers(host_column: bool) -> &'static [&'static str] {
	if host_column {
		&["SERVICE", "STATE", "PORT", "BIND", "HOST"]
	} else {
		&["SERVICE", "STATE", "PORT", "BIND"]
	}
}

/// One listing row, unpadded: the table measures its own columns.
fn cells(row: &Row, host_column: bool) -> Vec<String> {
	let mut cells = vec![
		row.name.to_string(),
		String::new(),
		row.port.to_string(),
		row.bind.to_string(),
	];
	if host_column {
		cells.push(
			row.host
				.map_or_else(|| "-".to_string(), |host| host.to_string()),
		);
	}
	cells
}

/// The header of the plain listing, padded the way the rows below it are.
fn line_head(host_column: bool) -> String {
	if host_column {
		format!(
			"{:<13} {:<9} {:<6} {:<20} {}",
			"SERVICE", "STATE", "PORT", "BIND", "HOST"
		)
	} else {
		format!("{:<13} {:<9} {:<6} {}", "SERVICE", "STATE", "PORT", "BIND")
	}
}

pub(super) fn run(path: &Path, action: ServiceCli, dry_run: bool, json: bool) -> ExitCode {
	match execute(path, action, dry_run, json) {
		Ok(code) => code,
		Err(error) => {
			super::style::error(error.to_string());
			ExitCode::FAILURE
		}
	}
}

fn execute(
	path: &Path,
	action: ServiceCli,
	dry_run: bool,
	json: bool,
) -> Result<ExitCode, super::resource::ResourceError> {
	execute_with(
		path,
		action,
		dry_run,
		json,
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	)
}

fn execute_with(
	path: &Path,
	action: ServiceCli,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, super::stack::StackAction) -> ExitCode,
) -> Result<ExitCode, super::resource::ResourceError> {
	let (name, enabled) = match action {
		ServiceCli::List { json: leaf } => {
			let config = Config::load(path)
				.map_err(|e| super::resource::ResourceError::Failure(e.to_string()))?;
			list(&config, leaf || json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		ServiceCli::Enable { name } => (name, true),
		ServiceCli::Disable { name } => (name, false),
		ServiceCli::Set { name, bind, port } => {
			let request = super::service_set::Request { name, bind, port };
			return super::service_set::run(path, request, dry_run, json, out, err, restart);
		}
	};
	let _held = if dry_run {
		None
	} else {
		Some(super::service_lock::acquire(path)?)
	};
	// A command killed between its two renames leaves the configuration and
	// the generated map describing different stacks. This one reconciles
	// them, so it is where the operator hears about it.
	if !dry_run && let Ok(current) = Config::load(path) {
		super::init::announce_mixed_state(&current, err);
	}
	let document = super::service_edit::listener_document(path, name.kind(), enabled)?;
	let action = if enabled { "enable" } else { "disable" };
	let fields = serde_json::json!({ "service": name.as_str(), "enabled": enabled });
	let failure =
		|error: std::io::Error| super::resource::ResourceError::Failure(error.to_string());
	if dry_run {
		let diff = document.dry_run()?;
		if json {
			let object = super::json_out::dry_run_object(action, fields, diff);
			return writeln!(out, "{object}")
				.map(|()| ExitCode::SUCCESS)
				.map_err(failure);
		}
		write!(out, "{diff}").map_err(failure)?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	// Both files are staged and validated before either is replaced, the same
	// way `set` does it: a generated file that does not parse must not leave a
	// listener enabled in `mail.toml` and a port published nowhere.
	let companion = super::init::prepare_published_ports(&config.data_dir, &config.listeners, None)
		.map_err(|error| super::resource::ResourceError::Failure(error.to_string()))?;
	let outcome = super::config_edit::commit_pair(document, companion)?;
	let state = if enabled { "enabled" } else { "disabled" };
	if outcome == super::config_edit::Outcome::Unchanged {
		writeln!(
			err,
			"{} is already {state}; nothing changed.",
			name.as_str()
		)
		.map_err(|e| super::resource::ResourceError::Failure(e.to_string()))?;
		if json {
			let object = super::json_out::change_object(
				action,
				false,
				fields,
				Some(super::json_out::Reload::None),
			);
			writeln!(out, "{object}").map_err(failure)?;
		}
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(err, "{} {state}.", name.as_str())
		.map_err(|e| super::resource::ResourceError::Failure(e.to_string()))?;
	let (code, reload) =
		super::config_edit::after_ports_change_reporting(&config, outcome, err, restart)?;
	if json {
		let object = super::json_out::change_object(action, true, fields, Some(reload));
		writeln!(out, "{object}").map_err(failure)?;
	}
	Ok(code)
}

#[cfg(test)]
#[path = "service_tests_command.rs"]
mod tests_command;

#[cfg(test)]
#[path = "service_tests_http.rs"]
mod tests_http;
