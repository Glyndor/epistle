//! Render the compose file again with the current code, for `epistle stack
//! update`.
//!
//! `epistle init` does not keep its answers, so the inputs come from the two
//! files that do: the existing compose file (whether the stack has a
//! database, the operator's own `mail` image, the DNS token it forwards, the
//! config path `mail` serves) and the config (`data_dir` and the listeners,
//! which decide the published ports). Everything else in the compose file is
//! the current code's: images, hardening, healthchecks and services that a
//! newer release added. Operator changes belong in `compose.override.yaml`,
//! which is never read or written here.

use std::path::{Path, PathBuf};

use serde_json::Value;

use super::answers::{DnsAnswers, Mode, Services};
use super::compose::{ComposeFile, panel_package, render_document};
use super::compose_publish::{hosts, narrowed, ports, published};
use crate::cli::init::Answers;
use crate::config::{Listener, ListenerKind};

/// A re-rendered compose file.
#[derive(Debug)]
pub(crate) struct Regenerated {
	/// The compose file the current code writes for this install.
	pub(crate) text: String,
	/// What the operator should know about how it was derived.
	pub(crate) notes: Vec<String>,
	/// The config path the `mail` service serves.
	pub(crate) config_path: PathBuf,
}

/// Re-render `existing` for an install whose config has `data_dir` and
/// `listeners`. Fails when the existing file is not one `epistle init`
/// wrote, rather than guessing.
pub(crate) fn regenerate(
	data_dir: &Path,
	listeners: &[Listener],
	existing: &str,
) -> Result<Regenerated, String> {
	regenerate_with(data_dir, listeners, existing, None)
}

/// [`regenerate`], with the certificates container turned on or off when
/// `certs` says so instead of kept as the existing file has it.
pub(crate) fn regenerate_with(
	data_dir: &Path,
	listeners: &[Listener],
	existing: &str,
	certs: Option<bool>,
) -> Result<Regenerated, String> {
	regenerate_in(
		data_dir,
		listeners,
		existing,
		certs,
		Path::new(panel_package::MANIFEST),
	)
}

/// [`regenerate_with`], reading the panel package's pin file at `manifest`.
pub(super) fn regenerate_in(
	data_dir: &Path,
	listeners: &[Listener],
	existing: &str,
	certs: Option<bool>,
	manifest: &Path,
) -> Result<Regenerated, String> {
	let document: Value = serde_json::from_str(existing)
		.map_err(|error| format!("compose.yaml is not the JSON epistle init writes: {error}"))?;
	let mail = document
		.get("services")
		.and_then(|services| services.get("mail"))
		.filter(|mail| mail.is_object())
		.ok_or("compose.yaml has no `mail` service, so epistle init did not write it")?;
	let config_path = served_config(mail)?;
	let database = document["services"].get("db").is_some();
	let managed = document
		.get("x-epistle-managed-image")
		.and_then(Value::as_bool)
		.unwrap_or(false);
	let image = if managed {
		None
	} else {
		let image = mail["image"]
			.as_str()
			.ok_or("compose.yaml names no image for `mail`")?;
		Some(image.to_string())
	};
	let resources = match document.get("x-epistle-resources") {
		Some(value) => serde_json::from_value(value.clone()).map_err(|error| {
			format!("compose.yaml has an x-epistle-resources epistle init did not write: {error}")
		})?,
		None => Default::default(),
	};
	let config_dir = config_path.parent().unwrap_or(Path::new("/")).to_path_buf();
	// The DNS credential is mounted where the zone is written from: `certs`
	// when the stack runs it, `mail` otherwise.
	let running_certs = document["services"]
		.get("certs")
		.filter(|certs| certs.is_object());
	let forwarding = dns_forwarding(running_certs.unwrap_or(mail), &config_dir, data_dir);
	let mut answers = Answers {
		mode: Mode::Manual,
		hostname: String::new(),
		domains: Vec::new(),
		public_ipv4: None,
		public_ipv6: None,
		data_dir: data_dir.to_path_buf(),
		config_path,
		acme: None,
		dns: forwarding,
		services: Services {
			imap: false,
			submission: false,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database,
			certs: certs.unwrap_or(running_certs.is_some()),
			// A stack that runs no clamav on purpose keeps running none.
			antivirus: document
				.get("x-epistle-antivirus")
				.and_then(Value::as_bool)
				.filter(|on| !on),
			// The operator's choice survives the update; whether the panel runs
			// is decided below from the package and the listeners.
			panel: document.get("x-epistle-panel").and_then(Value::as_bool),
			panel_image: None,
		},
		image,
		first_account: None,
		resources,
	};
	let serves_api = listeners
		.iter()
		.any(|listener| listener.kind == ListenerKind::Api);
	let panel_notes = panel_package::resolve(&mut answers, manifest, serves_api, false)?;
	// The host address `epistle service set` narrowed one mapping to is the
	// operator's decision, not a function of the listeners, so the existing
	// file is the only place it lives. Regenerating without it would put
	// that listener back on every host address of the machine.
	let narrow = hosts(&document);
	// The configuration the stack serves decides whether port 80 is
	// published: only the HTTP-01 challenge is answered there, so a
	// configuration that renews with `dns-01` or `tls-alpn-01` does not
	// publish it. The file is the one the apply phase wrote, so it already
	// carries the section init adds.
	let challenge = super::compose::challenge::in_config(&answers.config_path);
	let published_ports = published(listeners, &narrow, None, challenge);
	let composed = ComposeFile::build(&answers, published_ports.clone(), database);
	let mut text = render_document(&composed).map_err(|error| error.to_string())?;
	let mut notes = panel_notes;
	// A publication this release takes off every address of the host is named
	// in the notes: the operator loses reachability on this upgrade and the
	// note is where they read which port went.
	for one in narrowed(listeners, &ports(&document), &published_ports) {
		notes.push(one.to_string());
	}
	if let Some(running) = document["services"]["db"]["image"].as_str() {
		let pinned = super::images::postgres();
		let (from, to) = (super::images::major(running), super::images::major(pinned));
		if from != to {
			// A new major cannot read the old cluster: swapping the image
			// would start an empty database. Keep the running one until
			// the operator runs the dump and restore.
			text = text.replace(&format!("\"{pinned}\""), &format!("\"{running}\""));
			notes.push(format!(
				"this release pins PostgreSQL {} and the stack runs {}; the db image was kept, \
				 run `sudo epistle db upgrade` to move the data to the new major",
				to.map_or("?".to_string(), |major| major.to_string()),
				from.map_or("?".to_string(), |major| major.to_string()),
			));
		}
	}
	notes.push(format!(
		"rendered compose.yaml with this release's code; the database, the mail image, the DNS \
		 token and the config path came from the existing compose.yaml, and the published ports \
		 from the listeners in {}",
		answers.config_path.display()
	));
	Ok(Regenerated {
		text,
		notes,
		config_path: answers.config_path,
	})
}

/// The config path `mail` serves: the argument after `--config` in its
/// command.
fn served_config(mail: &Value) -> Result<PathBuf, String> {
	let command: Vec<&str> = mail["command"]
		.as_array()
		.map(|items| items.iter().filter_map(Value::as_str).collect())
		.unwrap_or_default();
	command
		.windows(2)
		.find(|pair| pair[0] == "--config")
		.map(|pair| PathBuf::from(pair[1]))
		.ok_or_else(|| "the `mail` service in compose.yaml has no `--config` in its command".into())
}

/// The DNS token the existing `service` forwards: an environment variable
/// passed through as `${NAME}`, or a file bound read-only at its own path
/// that is neither the config directory, the host binary nor a directory a
/// split stack shares.
fn dns_forwarding(service: &Value, config_dir: &Path, data_dir: &Path) -> Option<DnsAnswers> {
	let mail = service;
	// The directories `certs` shares with `mail` and owns are bound at their
	// own path too; they are not a token.
	let shared = [
		crate::acme::renew::pair_dir(data_dir),
		crate::dns::tlsa::state_path(data_dir)
			.parent()
			.map(Path::to_path_buf)
			.unwrap_or_default(),
		crate::cli::init::compose_file_path(data_dir)
			.parent()
			.map(Path::to_path_buf)
			.unwrap_or_default(),
	];
	let token_env = mail["environment"].as_object().and_then(|environment| {
		environment
			.iter()
			.find(|(name, value)| value.as_str() == Some(&format!("${{{name}}}")))
			.map(|(name, _)| name.clone())
	});
	let token_file = mail["volumes"].as_array().and_then(|volumes| {
		volumes.iter().find_map(|volume| {
			let source = volume["source"].as_str()?;
			let relabelled = volume.get("bind").is_some();
			let read_only = volume["read_only"].as_bool() == Some(true);
			(relabelled
				&& read_only
				&& volume["target"].as_str() == Some(source)
				&& Path::new(source) != config_dir
				&& !shared.iter().any(|dir| dir == Path::new(source)))
			.then(|| PathBuf::from(source))
		})
	});
	(token_env.is_some() || token_file.is_some()).then(|| DnsAnswers {
		token_env,
		token_file,
		..DnsAnswers::default()
	})
}

#[cfg(test)]
mod tests;

/// The compose file `epistle init` writes for a stack with a database under
/// `data_dir`, with `image` as the operator's mail image when given; for the
/// tests of the commands that read it.
#[cfg(test)]
pub(crate) fn rendered_for_tests(data_dir: &Path, image: Option<&str>) -> String {
	let mut answers = super::compose::stack_answers();
	answers.data_dir = data_dir.to_path_buf();
	answers.image = image.map(str::to_string);
	super::compose::render_for(&answers, true).expect("render")
}
