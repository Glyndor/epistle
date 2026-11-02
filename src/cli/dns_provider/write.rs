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

use toml_edit::TableLike;

use super::super::config_edit::{
	ConfigDocument, FieldChange, Outcome, after_ports_change_reporting,
};
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
		Some(super::super::service::lock::acquire(path)?)
	};
	let mut document = ConfigDocument::open(path)?;
	let current = document.config()?;
	// The entry this command adds or replaces is the one for its zone; the
	// other entries, their tokens and their mounts are left alone.
	let zone = args.zone.as_deref().ok_or("--zone is required")?;
	let zone = resource::dns_name("--zone", zone)?;
	// `--store-token` moves the token to the secrets directory; the other
	// sources stay where the operator put them.
	let destination = store_destination(&current, args, &zone);
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
		Some(_) => Some(super::secret::token(&current, args, &zone)?),
		None => None,
	};
	set_entry(&mut document, &current, &zone, &fields)?;
	let config = document.config()?;
	// The credential the configuration carried before leaves the container
	// with it: a container that keeps the old token mounted still exposes it.
	let dropped: Vec<&str> = current
		.dns
		.for_zone(&zone)
		.and_then(|dns| dns.token_env.as_deref())
		.into_iter()
		.chain(args.token_env.as_deref())
		.collect();
	let compose = super::compose::with_token(&current, &zone, source, &dropped)?;
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

/// Write the fields of the entry for `zone`.
///
/// A configuration with no entry, or with one `[dns]` table for this same
/// zone, is edited in place, as it always was. Any other zone becomes an
/// element of `[[dns]]`: a lone `[dns]` table is promoted to the first
/// element, and the entry for the zone is added or replaced by its zone.
fn set_entry(
	document: &mut ConfigDocument,
	current: &Config,
	zone: &str,
	fields: &[FieldChange<'_>],
) -> Result<(), String> {
	let in_place = current.dns.is_empty()
		|| (document.is_table("dns") && current.dns.for_zone(zone).is_some());
	if in_place {
		return document.set_table_fields(&["dns"], fields);
	}
	document.promote_table_to_array("dns")?;
	document.upsert_where("dns", &|table: &dyn TableLike| is_zone(table, zone), fields)
}

/// Whether the `[[dns]]` element `table` is the one for `zone`.
pub(super) fn is_zone(table: &dyn TableLike, zone: &str) -> bool {
	table
		.get("zone")
		.and_then(toml_edit::Item::as_str)
		.is_some_and(|own| own.trim_end_matches('.').eq_ignore_ascii_case(zone))
}

/// Where `--store-token` puts the token: the secrets directory beside
/// `data_dir`, where the storage and OAuth keys live. The only zone keeps the
/// historical name; with other zones configured each token has its own file,
/// so replacing one never overwrites another.
pub(super) fn store_destination(
	config: &Config,
	args: &super::ProviderArgs,
	zone: &str,
) -> Option<PathBuf> {
	if !args.store_token {
		return None;
	}
	let alone = config
		.dns
		.iter()
		.all(|dns| dns.zone.trim_end_matches('.').eq_ignore_ascii_case(zone));
	let name = if alone {
		"dns_provider_token".to_string()
	} else {
		format!("dns_provider_token_{}", zone.replace('.', "_"))
	};
	Some(super::super::init::host_secrets::dir(&config.data_dir).join(name))
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
