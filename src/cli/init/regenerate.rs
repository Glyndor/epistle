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
use super::compose::{ComposeFile, published_ports_for_listeners, render_document};
use crate::cli::init::Answers;
use crate::config::Listener;

/// A re-rendered compose file.
#[derive(Debug)]
pub(crate) struct Regenerated {
	/// The compose file the current code writes for this install.
	pub(crate) text: String,
	/// What the operator should know about how it was derived.
	pub(crate) notes: Vec<String>,
}

/// Re-render `existing` for an install whose config has `data_dir` and
/// `listeners`. Fails when the existing file is not one `epistle init`
/// wrote, rather than guessing.
pub(crate) fn regenerate(
	data_dir: &Path,
	listeners: &[Listener],
	existing: &str,
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
	let config_dir = config_path.parent().unwrap_or(Path::new("/")).to_path_buf();
	let answers = Answers {
		mode: Mode::Manual,
		hostname: String::new(),
		domains: Vec::new(),
		public_ipv4: None,
		public_ipv6: None,
		data_dir: data_dir.to_path_buf(),
		config_path,
		acme: None,
		dns: dns_forwarding(mail, &config_dir),
		services: Services {
			imap: false,
			submission: false,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database,
		},
		image,
	};
	let composed = ComposeFile::build(&answers, published_ports_for_listeners(listeners), database);
	let text = render_document(&composed).map_err(|error| error.to_string())?;
	let notes = vec![format!(
		"rendered compose.yaml with this release's code; the database, the mail image, the DNS \
		 token and the config path came from the existing compose.yaml, and the published ports \
		 from the listeners in {}",
		answers.config_path.display()
	)];
	Ok(Regenerated { text, notes })
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

/// The DNS token the existing `mail` service forwards: an environment
/// variable passed through as `${NAME}`, or a file bound read-only at its
/// own path that is neither the config directory nor the host binary.
fn dns_forwarding(mail: &Value, config_dir: &Path) -> Option<DnsAnswers> {
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
				&& read_only && volume["target"].as_str() == Some(source)
				&& Path::new(source) != config_dir)
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
#[path = "regenerate_tests.rs"]
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
