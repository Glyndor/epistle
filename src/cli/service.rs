//! Listener administration without regenerating the installation configuration.

use std::io::Write;
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
	fn kind(self) -> ListenerKind {
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

	fn as_str(self) -> &'static str {
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
}

pub(super) fn default_bind(config: &Config, kind: ListenerKind) -> IpAddr {
	if kind == ListenerKind::Api {
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

fn list(config: &Config, json: bool, out: &mut impl Write) -> Result<(), String> {
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
			rows.push(Row {
				name: name.as_str(),
				enabled: false,
				port: kind.default_port(),
				bind: default_bind(config, kind),
			});
		} else {
			for listener in matches {
				rows.push(Row {
					name: name.as_str(),
					enabled: true,
					port: listener.socket_addr().port(),
					bind: listener.addr,
				});
			}
		}
	}
	for listener in &config.listeners {
		if !names.iter().any(|name| name.kind() == listener.kind) {
			rows.push(Row {
				name: listener.kind.as_str(),
				enabled: true,
				port: listener.socket_addr().port(),
				bind: listener.addr,
			});
		}
	}
	if json {
		serde_json::to_writer(&mut *out, &rows).map_err(|e| e.to_string())?;
		writeln!(out).map_err(|e| e.to_string())?;
	} else {
		writeln!(out, "SERVICE       STATE     PORT   BIND").map_err(|e| e.to_string())?;
		for row in rows {
			writeln!(
				out,
				"{:<13} {:<9} {:<6} {}",
				row.name,
				if row.enabled { "enabled" } else { "disabled" },
				row.port,
				row.bind
			)
			.map_err(|e| e.to_string())?;
		}
	}
	Ok(())
}

pub(super) fn run(path: &Path, action: ServiceCli, dry_run: bool) -> ExitCode {
	match execute(path, action, dry_run) {
		Ok(code) => code,
		Err(error) => {
			super::style::error(error);
			ExitCode::FAILURE
		}
	}
}

fn execute(path: &Path, action: ServiceCli, dry_run: bool) -> Result<ExitCode, String> {
	execute_with(
		path,
		action,
		dry_run,
		&mut std::io::stdout().lock(),
		&mut super::style::stderr(),
		super::stack::run,
	)
}

fn execute_with(
	path: &Path,
	action: ServiceCli,
	dry_run: bool,
	out: &mut impl Write,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, super::stack::StackAction) -> ExitCode,
) -> Result<ExitCode, String> {
	let (name, enabled) = match action {
		ServiceCli::List { json } => {
			let config = Config::load(path).map_err(|e| e.to_string())?;
			list(&config, json, out)?;
			return Ok(ExitCode::SUCCESS);
		}
		ServiceCli::Enable { name } => (name, true),
		ServiceCli::Disable { name } => (name, false),
	};
	let document = super::service_edit::listener_document(path, name.kind(), enabled)?;
	if dry_run {
		write!(out, "{}", document.dry_run()?).map_err(|error| error.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config()?;
	let outcome = document.commit()?;
	let state = if enabled { "enabled" } else { "disabled" };
	if outcome == super::config_edit::Outcome::Unchanged {
		writeln!(
			err,
			"{} is already {state}; nothing changed.",
			name.as_str()
		)
		.map_err(|e| e.to_string())?;
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(err, "{} {state}.", name.as_str()).map_err(|e| e.to_string())?;
	super::init::update_listener_ports(&config.data_dir, &config.listeners)
		.map_err(|error| error.to_string())?;
	super::config_edit::after_ports_change_with(&config, outcome, err, restart)
}

#[cfg(test)]
#[path = "service_tests_command.rs"]
mod tests_command;
