//! Move a provider token to the host secrets directory and update mail's mount.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use super::super::resource::{self, ResourceError};
use super::super::stack::StackAction;
use crate::cli::config_edit::{ConfigDocument, Outcome, after_ports_change_reporting};
use crate::config::Config;
use crate::dns::provider::ScopedSecret;

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
	let destination =
		super::super::init::host_secrets::dir(&current.data_dir).join("dns_provider_token");
	let mut saved = args.clone();
	saved.token_env = None;
	saved.token_file = Some(destination.display().to_string());
	let fields = super::set::fields(provider, &saved)?;
	document.set_table_fields(&["dns"], &fields)?;
	let config = document.config()?;
	let token = token(&current, args)?;
	let compose = companion_compose(&current, args, &destination)?;
	let edit = resource::Edit {
		label: "dns provider",
		action: "provider set",
		fields: serde_json::json!({"provider": provider}),
		json,
	};
	if dry_run {
		return resource::finish(document, true, edit, out, status, restart);
	}
	store(&destination, &token)?;
	// The compose file is staged and validated before the config is replaced,
	// and a refused replacement restores the one that was there: the running
	// container keeps the forwarding it had.
	let outcome =
		crate::cli::config_edit::commit_pair(document, compose).map_err(ResourceError::from)?;
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

fn token(config: &Config, args: &super::ProviderArgs) -> Result<String, String> {
	if args.token_env.is_some() && args.token_file.is_some() {
		return Err("choose one of --token-env and --token-file".into());
	}
	let dns = config.dns.as_ref();
	let (inline, env, file) = if args.token_env.is_some() || args.token_file.is_some() {
		(
			None,
			args.token_env.as_ref(),
			args.token_file.as_deref().map(Path::new),
		)
	} else {
		(
			dns.and_then(|dns| dns.token.as_deref()),
			dns.and_then(|dns| dns.token_env.as_ref()),
			dns.and_then(|dns| dns.token_file.as_deref()),
		)
	};
	if let Some(token) = inline.filter(|value| !value.trim().is_empty()) {
		return Ok(token.to_string());
	}
	if let Some(env) = env {
		return std::env::var(env)
			.ok()
			.filter(|value| !value.trim().is_empty())
			.map(|value| value.trim().to_string())
			.ok_or_else(|| "DNS token environment variable is unset or empty".into());
	}
	if let Some(file) = file {
		return ScopedSecret::from_file("", file)
			.map(|secret| secret.token().to_string())
			.map_err(|_| {
				"cannot read DNS token file; use a non-empty private file with mode 0600".into()
			});
	}
	Err("no DNS token to store; supply --token-env or --token-file".into())
}

fn store(path: &Path, token: &str) -> Result<(), String> {
	match fs::symlink_metadata(path) {
		Ok(metadata) => {
			if !metadata.is_file() {
				return Err("DNS secret destination must be a regular file".into());
			}
			let existing = ScopedSecret::from_file("", path)
				.map_err(|_| "DNS secret destination must be readable and private (0600)")?;
			if existing.token() != token {
				return Err("DNS secret destination already contains a different token; move it aside before retrying".into());
			}
			return Ok(());
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
		Err(_) => return Err("cannot inspect DNS secret destination".into()),
	}
	let dir = path
		.parent()
		.ok_or("DNS secret destination needs a parent")?;
	fs::create_dir_all(dir).map_err(|_| "cannot create DNS secrets directory")?;
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
			.map_err(|_| "cannot restrict DNS secrets directory to 0700")?;
	}
	crate::storage::write_secret(path, token.as_bytes())
		.map_err(|_| "cannot write DNS secret file".into())
}

type ComposeUpdate = (PathBuf, Vec<u8>, Vec<u8>);

/// The staged compose file with the DNS token mount, ready to be committed
/// together with `mail.toml`. `None` when the install has no generated
/// compose file, and `None` when the file already carries the mount: a
/// candidate identical to the file on disk is not a change.
fn companion_compose(
	config: &Config,
	args: &super::ProviderArgs,
	token_path: &Path,
) -> Result<Option<crate::cli::config_edit::Companion>, String> {
	let Some((path, original, updated)) = updated_compose(config, args, token_path)? else {
		return Ok(None);
	};
	if original == updated {
		return Ok(None);
	}
	Ok(Some(crate::cli::config_edit::Companion {
		path,
		original,
		candidate: updated,
	}))
}

fn updated_compose(
	config: &Config,
	args: &super::ProviderArgs,
	token_path: &Path,
) -> Result<Option<ComposeUpdate>, String> {
	let path = super::super::init::compose_file_path(&config.data_dir);
	// The read happens with the common lock in hand, so it goes through the
	// reader that refuses a fifo instead of waiting for a writer that may
	// never come and holding the lock while it does.
	let Some(bytes) = super::super::init::compose_read::read(&path)? else {
		return Ok(None);
	};
	let mut document: serde_json::Value = serde_json::from_slice(&bytes)
		.map_err(|_| "compose.yaml must be generated Compose JSON")?;
	let mail = document
		.get_mut("services")
		.and_then(|services| services.get_mut("mail"))
		.and_then(serde_json::Value::as_object_mut)
		.ok_or("compose.yaml has no mail service")?;
	if let Some(env) = mail.get_mut("environment") {
		let env = env
			.as_object_mut()
			.ok_or("mail environment must be an object")?;
		for name in [
			config.dns.as_ref().and_then(|dns| dns.token_env.as_ref()),
			args.token_env.as_ref(),
		]
		.into_iter()
		.flatten()
		{
			env.remove(name);
		}
	}
	let volumes = mail
		.entry("volumes")
		.or_insert_with(|| serde_json::json!([]))
		.as_array_mut()
		.ok_or("mail volumes must be an array")?;
	let previous = config.dns.as_ref().and_then(|dns| dns.token_file.as_ref());
	volumes.retain(|mount| {
		let source = mount["source"].as_str().map(Path::new);
		source != Some(token_path) && !previous.is_some_and(|path| source == Some(path.as_path()))
	});
	volumes.push(serde_json::json!({
		"type": "bind", "source": token_path, "target": token_path,
		"read_only": true, "bind": {"selinux": "Z"}
	}));
	let mut updated =
		serde_json::to_vec_pretty(&document).map_err(|_| "cannot encode compose.yaml")?;
	updated.push(b'\n');
	Ok(Some((path, bytes, updated)))
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;

	#[test]
	fn existing_destination_is_reused_but_never_replaced_with_another_token() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("secrets/dns_provider_token");
		store(&path, "original-token").unwrap();
		store(&path, "original-token").unwrap();
		let error = store(&path, "replacement-token").unwrap_err();
		assert!(error.contains("different token"));
		assert!(!error.contains("original-token") && !error.contains("replacement-token"));
		assert!(fs::read_to_string(path).unwrap() == "original-token");
	}
}
