//! `dns provider set`: the configuration, and the generated compose file that
//! carries the credential into the container.
//!
//! The configuration says where the token lives; the generated compose file
//! says what the container can see. A `set` that only writes the first leaves
//! a `mail` service that reads a path it does not have, and the provider
//! never builds: the container crash-loops on every ACME challenge. So both
//! files are written here, under the common lock, and the compose file is
//! staged before either is replaced.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::super::config_edit::{ConfigDocument, Outcome, after_ports_change_reporting};
use super::super::resource::{self, ResourceError};
use super::super::stack::StackAction;
use super::compose::TokenSource;
use crate::config::Config;

/// Save the provider, and make its credential reachable inside the container.
pub(super) fn run(
	path: &Path,
	selection: (&str, &super::ProviderArgs),
	dry_run: bool,
	json: bool,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, StackAction) -> ExitCode,
) -> Result<ExitCode, ResourceError> {
	let (provider, args) = selection;
	// This command rewrites `mail.toml` and the generated compose file, so it
	// reads both under the same lock every other writer of them takes, and it
	// stages the compose file before either is replaced.
	let _held = if dry_run {
		None
	} else {
		Some(super::super::service_lock::acquire(path)?)
	};
	let mut document = ConfigDocument::open(path)?;
	let current = document.config()?;
	// `--store-token` moves the token to the secrets directory; the other
	// sources stay where the operator put them.
	let destination = store_destination(&current, args);
	let source = token_source(args, destination.as_deref());
	let mut saved = args.clone();
	if let Some(destination) = &destination {
		saved.token_env = None;
		saved.token_file = Some(destination.display().to_string());
	}
	let fields = super::set::fields(provider, &saved)?;
	// The token to move is read without printing it, and only when there is
	// one to move.
	let token = match &destination {
		Some(_) => Some(super::secret::token(&current, args)?),
		None => None,
	};
	document.set_table_fields(&["dns"], &fields)?;
	let config = document.config()?;
	// The credential the configuration carried before leaves the container
	// with it: a container that keeps the old token mounted still exposes it.
	let dropped: Vec<&str> = current
		.dns
		.as_ref()
		.and_then(|dns| dns.token_env.as_deref())
		.into_iter()
		.chain(args.token_env.as_deref())
		.collect();
	let compose = super::compose::with_token(&current, source, &dropped)?;
	let edit = resource::Edit {
		label: "dns provider",
		action: "provider set",
		fields: serde_json::json!({ "provider": provider }),
		json,
	};
	if dry_run {
		let change = compose.as_ref().map(|update| resource::CompanionChange {
			companion: &update.companion,
			lines: &update.lines,
		});
		return resource::preview(&document, change, &edit, out);
	}
	if let (Some(destination), Some(token)) = (&destination, &token) {
		super::secret::store(destination, token)?;
	}
	// The compose file is staged and validated before the config is replaced,
	// and a refused replacement restores the one that was there: the running
	// container keeps the forwarding it had.
	let outcome =
		crate::cli::config_edit::commit_pair(document, compose.map(|update| update.companion))
			.map_err(ResourceError::from)?;
	let changed = outcome == Outcome::Changed;
	writeln!(
		status,
		"dns provider {}",
		if changed { "saved" } else { "unchanged" }
	)
	.map_err(|error| error.to_string())?;
	let (code, reload) = after_ports_change_reporting(&config, outcome, status, restart)?;
	if json {
		let object =
			super::super::json_out::change_object(edit.action, changed, edit.fields, Some(reload));
		writeln!(out, "{object}").map_err(|error| error.to_string())?;
	}
	Ok(code)
}

/// Where `--store-token` puts the token: the secrets directory beside
/// `data_dir`, where the storage and OAuth keys live.
fn store_destination(config: &Config, args: &super::ProviderArgs) -> Option<PathBuf> {
	if !args.store_token {
		return None;
	}
	Some(super::super::init::host_secrets::dir(&config.data_dir).join("dns_provider_token"))
}

/// Where the container reads the token from: the file the command stores it
/// in, the file the operator named, or the environment variable they named.
fn token_source<'a>(
	args: &'a super::ProviderArgs,
	destination: Option<&'a Path>,
) -> Option<TokenSource<'a>> {
	if let Some(destination) = destination {
		return Some(TokenSource::File(destination));
	}
	if let Some(file) = args.token_file.as_deref() {
		return Some(TokenSource::File(Path::new(file)));
	}
	args.token_env.as_deref().map(TokenSource::Env)
}
