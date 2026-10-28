//! The generated compose file, with the DNS credential the configuration
//! names reachable inside the `mail` container.
//!
//! A host path is not visible inside the container unless the generated
//! compose file mounts it, and the generated compose file is the only place
//! that says what the container sees: `stack update` re-renders it from the
//! file itself (`init::regenerate`), so a credential that never reaches the
//! compose file is a credential the container never has.
//!
//! The file is rewritten in the order this tool writes it, the way
//! `stack resources set` rewrites it, so the change is reported in words:
//! what the container read before and what it reads after.

use std::path::Path;

use crate::cli::config_edit::Companion;
use crate::config::Config;

/// Where the container reads the provider token from.
#[derive(Debug, Clone, Copy)]
pub(super) enum TokenSource<'a> {
	/// An environment variable, forwarded to the container as `${NAME}`.
	Env(&'a str),
	/// A file, mounted read-only at the same path it has on the host.
	File(&'a Path),
}

/// The generated compose file with the credential inside, and what that
/// changes in it.
pub(super) struct TokenUpdate {
	/// The file to write beside the configuration.
	pub(super) companion: Companion,
	/// The lines that say what changes in it.
	pub(super) lines: Vec<String>,
}

/// The generated compose file with `source` reachable inside `mail`.
///
/// The credential the configuration carried before leaves the container with
/// it: a container that keeps the old token mounted still exposes it.
///
/// `dropped` names the environment variables that are not read any more: the
/// one the configuration carried and the one the command was given.
///
/// `None` when the install has no generated compose file, and `None` when the
/// file already carries the source: a candidate identical to the file on disk
/// is not a change.
pub(super) fn with_token(
	config: &Config,
	source: Option<TokenSource<'_>>,
	dropped: &[&str],
) -> Result<Option<TokenUpdate>, String> {
	let path = crate::cli::init::compose_file_path(&config.data_dir);
	// The read happens with the common lock in hand, so it goes through the
	// reader that refuses a fifo instead of waiting for a writer that may
	// never come and holding the lock while it does.
	let Some(bytes) = crate::cli::init::compose_read::read(&path)? else {
		return Ok(None);
	};
	let mut document: serde_json::Value = serde_json::from_slice(&bytes)
		.map_err(|_| "compose.yaml must be generated Compose JSON")?;
	let mail = document
		.get_mut("services")
		.and_then(|services| services.get_mut("mail"))
		.and_then(serde_json::Value::as_object_mut)
		.ok_or("compose.yaml has no mail service")?;
	// What the container reads now, before the change: the variable the
	// compose file forwards and the mount it carries.
	let forwarded = forwarded(mail, dropped);
	let previous_file = config
		.dns
		.as_ref()
		.and_then(|dns| dns.token_file.as_deref());
	let mounted = previous_file.and_then(|path| mount_index(mail, path));
	// The mount the compose file carries is the one the change replaces. A
	// configuration that names a file the compose file does not mount has
	// nothing to replace, and nothing to take away.
	let carried = mounted.and(previous_file);
	if let Some(environment) = mail
		.get_mut("environment")
		.and_then(serde_json::Value::as_object_mut)
	{
		for name in dropped {
			environment.remove(*name);
		}
	}
	if let Some(TokenSource::Env(name)) = source {
		let environment = mail
			.entry("environment")
			.or_insert_with(|| serde_json::json!({}));
		let environment = environment
			.as_object_mut()
			.ok_or("mail environment must be an object")?;
		environment.insert(name.to_string(), format!("${{{name}}}").into());
	}
	let volumes = mail
		.entry("volumes")
		.or_insert_with(|| serde_json::json!([]))
		.as_array_mut()
		.ok_or("mail volumes must be an array")?;
	// The mount of the token file takes the place of the one it replaces, so
	// the order of the other mounts does not change and the file the
	// operator reads keeps the shape it had.
	match source {
		Some(TokenSource::File(file)) => {
			let mount = serde_json::json!({
				"type": "bind", "source": file, "target": file,
				"read_only": true, "bind": {"selinux": "Z"}
			});
			match mounted {
				Some(index) => volumes[index] = mount,
				None => volumes.push(mount),
			}
		}
		None => {
			if let Some(index) = mounted {
				volumes.remove(index);
			}
		}
		Some(TokenSource::Env(_)) => {}
	}
	let mut updated =
		serde_json::to_vec_pretty(&document).map_err(|_| "cannot encode compose.yaml")?;
	updated.push(b'\n');
	if bytes == updated {
		return Ok(None);
	}
	let lines = lines(&path, carried, forwarded, source);
	Ok(Some(TokenUpdate {
		companion: Companion {
			path,
			original: bytes,
			candidate: updated,
		},
		lines,
	}))
}

/// The index of the mount of `path` in the `mail` service, when it carries
/// one: a read-only bind at the same path it has on the host.
fn mount_index(mail: &serde_json::Map<String, serde_json::Value>, path: &Path) -> Option<usize> {
	mail["volumes"].as_array().and_then(|volumes| {
		volumes.iter().position(|mount| {
			mount["source"].as_str().map(Path::new) == Some(path)
				&& mount["target"].as_str().map(Path::new) == Some(path)
				&& mount["read_only"].as_bool() == Some(true)
		})
	})
}

/// The variable the `mail` service forwards to the container, out of the ones
/// the command drops.
fn forwarded<'a>(
	mail: &serde_json::Map<String, serde_json::Value>,
	dropped: &[&'a str],
) -> Option<&'a str> {
	let environment = mail
		.get("environment")
		.and_then(serde_json::Value::as_object)?;
	dropped.iter().copied().find(|name| {
		environment.get(*name).and_then(serde_json::Value::as_str) == Some(&format!("${{{name}}}"))
	})
}

/// What the change means for the container: the file it mounts, and the
/// variable it forwards.
fn lines(
	file: &Path,
	previous_file: Option<&Path>,
	previous_env: Option<&str>,
	source: Option<TokenSource<'_>>,
) -> Vec<String> {
	let mut lines = Vec::new();
	let (after_file, after_env) = match source {
		Some(TokenSource::File(file)) => (Some(file), None),
		Some(TokenSource::Env(name)) => (None, Some(name)),
		None => (None, None),
	};
	match (previous_file, after_file) {
		(None, Some(after)) => {
			lines.push(format!(
				"{}: mail mounts {} read-only",
				file.display(),
				after.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: mail no longer mounts {}",
				file.display(),
				before.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: mail mounts {} read-only instead of {}",
				file.display(),
				after.display(),
				before.display()
			));
		}
		_ => {}
	}
	match (previous_env, after_env) {
		(None, Some(after)) => {
			lines.push(format!(
				"{}: mail forwards {after} to the container",
				file.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: mail no longer forwards {before} to the container",
				file.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: mail forwards {after} to the container instead of {before}",
				file.display()
			));
		}
		_ => {}
	}
	lines
}
