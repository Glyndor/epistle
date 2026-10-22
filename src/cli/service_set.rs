//! `epistle service set`: move an enabled listener to another address, port,
//! or both, without editing files by hand.
//!
//! The edit engine is the one `enable` and `disable` use, so the change keeps
//! every other value, the formatting `init` writes and the loader validation.
//! What differs is where the requested address lands:
//!
//! - Without a compose file the bind in `mail.toml` is the address the server
//!   binds, so it takes the requested address.
//! - With one, the listener keeps an unspecified bind inside the container (a
//!   loopback or private address there is not one the pasta mapping reaches)
//!   and the requested address becomes the host side of the generated
//!   `ports:` entry. The container bind is still what the loader validates,
//!   so a mapping the engine can not bind stays a refusal.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::process::ExitCode;

use super::config_edit::{ConfigDocument, Outcome};
use super::resource::ResourceError;
use super::service::ServiceName;
use super::{init, json_out, stack};
use crate::config::{Config, ListenerKind};

/// Any address of the IPv4 family, standing for "every address" when the
/// question is whether two listeners can answer on the same port.
const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// A socket as the operator reads it: an IPv6 address in brackets, so the port
/// behind the colon is not read as part of the address.
fn host_port(address: IpAddr, port: u16) -> String {
	match address {
		IpAddr::V6(_) => format!("[{address}]:{port}"),
		IpAddr::V4(_) => format!("{address}:{port}"),
	}
}

/// What the operator asked `set` to move.
pub(super) struct Request {
	/// Service to move.
	pub(super) name: ServiceName,
	/// Address the host reaches it on, when the operator named one.
	pub(super) bind: Option<IpAddr>,
	/// Port it answers on, when the operator named one.
	pub(super) port: Option<u16>,
}

/// Apply `set` and report what it did.
pub(super) fn run(
	path: &Path,
	request: Request,
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	err: &mut impl Write,
	restart: impl FnOnce(&Config, stack::StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	let Request {
		name,
		bind,
		port: requested_port,
	} = request;
	if bind.is_none() && requested_port.is_none() {
		return Err(ResourceError::Refusal(
			"nothing to change: pass --bind, --port, or both".into(),
		));
	}
	let _held = if dry_run {
		None
	} else {
		Some(super::service_lock::acquire(path).map_err(text)?)
	};
	let mut document = ConfigDocument::open(path).map_err(text)?;
	let config = document.config().map_err(text)?;
	let kind = name.kind();
	let current = config
		.listeners
		.iter()
		.find(|listener| listener.kind == kind)
		.ok_or_else(|| {
			ResourceError::Refusal(format!(
				"{} is not enabled: run `epistle service enable {}` first",
				name.as_str(),
				name.as_str()
			))
		})?
		.clone();
	let port = match requested_port {
		Some(0) => {
			return Err(ResourceError::Refusal(
				"port 0 is not a listener port: pick one between 1 and 65535".into(),
			));
		}
		Some(port) => port,
		None => current.socket_addr().port(),
	};
	let stack = init::compose_file_path(&config.data_dir).exists();
	let narrow = init::published_host_addresses(&init::compose_file_path(&config.data_dir));
	// The host-visible address after the change: the one asked for, else the
	// one the generated map already pins for this port, else the bind the
	// listener has today. On a host install there is no map, so it is the
	// bind or the address asked for.
	let published_host = match stack {
		true => bind.or_else(|| narrow.get(&current.socket_addr().port()).copied()),
		false => bind,
	};
	let host = published_host.unwrap_or(current.addr);
	free_port(&config, kind, &narrow, host, port, stack)?;
	http_prerequisites(kind, host)?;
	let mut fields: Vec<(&str, toml_edit::Value)> = Vec::new();
	match (stack, bind) {
		// A published mapping needs an address the container owns inside;
		// everywhere else the bind is what the operator asked for.
		(true, Some(_)) => fields.push(("addr", init::CONTAINER_BIND.to_string().into())),
		(false, Some(address)) => fields.push(("addr", address.to_string().into())),
		_ => {}
	}
	if let Some(port) = requested_port {
		fields.push(("port", toml_edit::Value::from(i64::from(port))));
	}
	document
		.upsert_element("listeners", "kind", kind.as_str(), &fields)
		.map_err(text)?;
	let fields = serde_json::json!({
		"service": name.as_str(),
		"bind": host.to_string(),
		"port": port,
	});
	// A bind in the config is set to an address; a mapping on a stack is
	// published on one, because the address the host uses is not the one the
	// container binds.
	let (verb, place) = if stack {
		("published", "on")
	} else {
		("set", "to")
	};
	let socket = host_port(host, port);
	if dry_run {
		let diff = document.dry_run().map_err(text)?;
		if json {
			let object = json_out::dry_run_object("set", fields, diff);
			return writeln!(out, "{object}")
				.map(|()| ExitCode::SUCCESS)
				.map_err(text);
		}
		write!(out, "{diff}").map_err(text)?;
		// The mapping that moves is the part of a stack change the config
		// diff does not carry, and a dry run that printed nothing for it
		// would read as "this does nothing".
		let candidate = document.config().map_err(text)?;
		if let Some((current, wanted)) = init::preview_published_ports(
			&candidate.data_dir,
			&candidate.listeners,
			Some((kind, published_host)),
		)
		.map_err(|error| ResourceError::Failure(error.to_string()))?
			&& current != wanted
		{
			writeln!(out, "compose.yaml ports:").map_err(text)?;
			for line in current.iter().filter(|line| !wanted.contains(line)) {
				writeln!(out, "- {line}").map_err(text)?;
			}
			for line in wanted.iter().filter(|line| !current.contains(line)) {
				writeln!(out, "+ {line}").map_err(text)?;
			}
		}
		return Ok(ExitCode::SUCCESS);
	}
	let config = document.config().map_err(text)?;
	let companion = init::prepare_published_ports(
		&config.data_dir,
		&config.listeners,
		Some((kind, published_host)),
	)
	.map_err(text)?;
	let outcome = super::config_edit::commit_pair(document, companion).map_err(text)?;
	if outcome == Outcome::Unchanged {
		writeln!(
			err,
			"{} is already {verb} {place} {socket}; nothing changed.",
			name.as_str()
		)
		.map_err(text)?;
		if json {
			let object =
				json_out::change_object("set", false, fields, Some(json_out::Reload::None));
			writeln!(out, "{object}").map_err(text)?;
		}
		return Ok(ExitCode::SUCCESS);
	}
	writeln!(err, "{} {verb} {place} {socket}.", name.as_str()).map_err(text)?;
	if stack
		&& init::operator_override_publishes(
			&config.data_dir,
			&[port, current.socket_addr().port()],
		) {
		writeln!(
			err,
			"compose.override.yaml publishes a port for mail, and it wins over the generated map."
		)
		.map_err(text)?;
	}
	let (code, reload) =
		super::config_edit::after_ports_change_reporting(&config, outcome, err, restart)?;
	if json {
		let object = json_out::change_object("set", true, fields, Some(reload));
		writeln!(out, "{object}").map_err(text)?;
	}
	Ok(code)
}

/// Refuse a host-visible socket another enabled listener already answers on.
/// A wildcard address covers every address of its family, so it conflicts with
/// a specific one on the same port, the same way the bind itself would.
fn free_port(
	config: &Config,
	kind: ListenerKind,
	narrow: &BTreeMap<u16, IpAddr>,
	address: IpAddr,
	port: u16,
	stack: bool,
) -> Result<(), ResourceError> {
	for listener in &config.listeners {
		let their_port = listener.socket_addr().port();
		if listener.kind == kind || their_port != port {
			continue;
		}
		let their = match stack && !listener.addr.to_canonical().is_loopback() {
			true => narrow.get(&their_port).copied().unwrap_or(ANY),
			false => listener.addr,
		};
		if their == address || their.is_unspecified() || address.is_unspecified() {
			return Err(ResourceError::Refusal(format!(
				"port {port} is already used by {} on {}",
				listener.kind.as_str(),
				host_port(their, their_port)
			)));
		}
	}
	Ok(())
}

/// Mail certificates do not change the transport of these HTTP listeners.
/// Keep their host-visible address on loopback behind a TLS terminator.
fn http_prerequisites(kind: ListenerKind, address: IpAddr) -> Result<(), ResourceError> {
	if matches!(
		kind,
		ListenerKind::Api | ListenerKind::WebDav | ListenerKind::Autoconfig
	) && !address.to_canonical().is_loopback()
	{
		return Err(ResourceError::Refusal(format!(
			"the {} listener serves HTTP without TLS; keep {address} on loopback behind a TLS reverse proxy, [tls] does not encrypt this listener",
			kind.as_str()
		)));
	}
	Ok(())
}

/// Any diagnostic, from the loader or from a failed write, as a command
/// failure.
fn text(error: impl std::fmt::Display) -> ResourceError {
	ResourceError::Failure(error.to_string())
}

#[cfg(test)]
#[path = "service_tests_set.rs"]
mod tests;
