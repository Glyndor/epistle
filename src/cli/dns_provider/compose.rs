//! The generated compose file, with the DNS credential the configuration
//! names reachable inside the container that writes the zone: `certs` when
//! the stack runs the certificates container, `mail` otherwise.
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

/// The service of the generated stack that holds the DNS credential.
pub(crate) fn credential_service(document: &serde_json::Value) -> &'static str {
	if document["services"].get("certs").is_some() {
		"certs"
	} else {
		"mail"
	}
}

/// The lock that guards a rewrite of the generated compose file.
///
/// It is taken after the common lock, never before it: a command that
/// holds the common lock and waits for this one, and a command that holds
/// this one and waits for the common one, would wait for each other. Every
/// command that writes the generated file takes the two locks in that
/// order, so a rewrite of the file never loses the change another writer
/// made.
///
/// `None` when the install has no generated file (a host install): there is
/// nothing to guard, and the command writes no file.
pub(super) fn lock_compose(
	config: &Config,
) -> Result<Option<crate::storage::lock::FileLock>, String> {
	let path = crate::cli::init::compose_file_path(&config.data_dir);
	if !path.exists() {
		return Ok(None);
	}
	let lock = crate::storage::locked::lock_path(&path);
	Ok(Some(crate::cli::compose::lock::acquire(&lock)?))
}

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
	/// The services whose definition in the file this change touches. The
	/// container of each one has to be recreated for the change to take
	/// effect: a container that keeps the mount it had still has the
	/// credential.
	pub(super) changed: Vec<&'static str>,
}

/// What a change to the credential does to the generated compose file.
pub(super) struct TokenChange {
	/// The file to write, `None` when the change leaves it as it is.
	pub(super) update: Option<TokenUpdate>,
	/// What the operator has to know about it. The override the operator
	/// keeps beside the generated file is merged with it, so a credential
	/// it hands back to `mail` is a credential the container that takes
	/// SMTP still has, and nothing in the generated file says so.
	pub(super) warnings: Vec<String>,
	/// The service of the generated stack that holds the credential, when
	/// the install has a generated compose file.
	pub(super) service: Option<&'static str>,
}

/// The generated compose file with `source` reachable inside the container
/// that holds the credential.
///
/// The credential the configuration carried before leaves the container with
/// it: a container that keeps the old token mounted still exposes it.
///
/// `zone` is the entry being set. The credential of every other entry stays
/// where it is: a mount or a variable another entry still reads is never
/// taken away, and one file shared by two entries is mounted once.
///
/// `dropped` names the environment variables that are not read any more: the
/// one the configuration carried and the one the command was given.
///
/// The credential goes to the service that holds it: `certs` when the stack
/// runs the certificates container, `mail` otherwise. The service the split
/// took it away from never keeps it: with the certificates container
/// running, `mail` must not mount the token nor forward its variable, or
/// the split promises nothing.
///
/// The change is empty when the install has no generated compose file, and
/// when the file already carries the source: a candidate identical to the
/// file on disk is not a change.
pub(super) fn with_token(
	config: &Config,
	zone: &str,
	source: Option<TokenSource<'_>>,
	dropped: &[&str],
) -> Result<TokenChange, String> {
	let path = crate::cli::init::compose_file_path(&config.data_dir);
	// The read happens with the common lock in hand, so it goes through the
	// reader that refuses a fifo instead of waiting for a writer that may
	// never come and holding the lock while it does.
	let Some(bytes) = crate::cli::init::compose_read::read(&path)? else {
		return Ok(TokenChange {
			update: None,
			warnings: Vec::new(),
			service: None,
		});
	};
	let mut document: serde_json::Value = serde_json::from_slice(&bytes)
		.map_err(|_| "compose.yaml must be generated Compose JSON")?;
	let previous = config.dns.for_zone(zone);
	let others: Vec<&crate::config::Dns> = config
		.dns
		.iter()
		.filter(|dns| previous.is_none_or(|own| !std::ptr::eq(*dns, own)))
		.collect();
	let dropped: Vec<&str> = dropped
		.iter()
		.copied()
		.filter(|name| {
			!others
				.iter()
				.any(|dns| dns.token_env.as_deref() == Some(*name))
		})
		.collect();
	let dropped = dropped.as_slice();
	// The service that holds the credential: `certs` when the stack runs the
	// certificates container, `mail` otherwise.
	let holder = credential_service(&document);
	// What the container reads now, before the change: the variable the
	// compose file forwards and the mount it carries.
	let forwarded = forwarded(&document, holder, dropped);
	let previous_file = previous
		.and_then(|dns| dns.token_file.as_deref())
		.filter(|file| {
			!others
				.iter()
				.any(|dns| dns.token_file.as_deref() == Some(*file))
		});
	// The file the change puts in place, when the credential is a file.
	let source_file = match source {
		Some(TokenSource::File(file)) => Some(file),
		_ => None,
	};
	// The mount the compose file carries is the one the change replaces. A
	// configuration that names a file the compose file does not mount has
	// nothing to replace, and nothing to take away.
	let mounted = previous_file.and_then(|file| mount_index(&document, holder, file));
	let already = source_file.and_then(|file| mount_index(&document, holder, file));
	let carried = previous_file.filter(|_| mounted.is_some());
	// The service the split took the credential away from, and what it still
	// carries of it.
	let other = other_service(&document, holder);
	let other_forwarded =
		other.map_or_else(Vec::new, |other| forwarded_all(&document, other, dropped));
	// The definition of each service before the change, to tell afterwards
	// which one the change touched.
	let holder_before = document["services"][holder].clone();
	let other_before = other.map(|other| document["services"][other].clone());
	// The credential goes to the service that holds it.
	{
		let service = service_mut(&mut document, holder)?;
		drop_environment(service, dropped);
		if let Some(TokenSource::Env(name)) = source {
			let environment = service
				.entry("environment")
				.or_insert_with(|| serde_json::json!({}));
			let environment = environment
				.as_object_mut()
				.ok_or_else(|| format!("the {holder} environment must be an object"))?;
			environment.insert(name.to_string(), format!("${{{name}}}").into());
		}
		set_mount(service, holder, source_file, mounted, already)?;
	}
	// The service the split took the credential away from does not keep it:
	// a container that still mounts the token is a container the operator
	// believes is out of it.
	let mut removed = Vec::new();
	if let Some(other) = other {
		let service = service_mut(&mut document, other)?;
		drop_environment(service, dropped);
		for file in [previous_file, source_file].into_iter().flatten() {
			if remove_mount(service, file) {
				removed.push(file);
			}
		}
	}
	// The credential the override could hand back to `mail`: the path it
	// travels as and the variable it is read from.
	let mut needles: Vec<String> = Vec::new();
	for file in [previous_file, source_file].into_iter().flatten() {
		needles.push(file.display().to_string());
	}
	for name in dropped {
		needles.push((*name).to_string());
	}
	if let Some(TokenSource::Env(name)) = source {
		needles.push(name.to_string());
	}
	// The operator's override is merged with the file this writes, so a
	// credential it hands back to `mail` is a credential the container that
	// takes SMTP still has, and nothing in the generated file says so.
	let warnings =
		if holder == "certs" && !needles.is_empty() && override_carries(&config.data_dir, &needles)
		{
			vec![format!(
				"{} gives mail the DNS credential; the certificates container holds it, so the \
			 override has to stop mounting it",
				override_path(&config.data_dir).display()
			)]
		} else {
			Vec::new()
		};
	let mut updated =
		serde_json::to_vec_pretty(&document).map_err(|_| "cannot encode compose.yaml")?;
	updated.push(b'\n');
	if bytes == updated {
		return Ok(TokenChange {
			update: None,
			warnings,
			service: Some(holder),
		});
	}
	// The services the change touched: the container of each one has to be
	// recreated, or it keeps the mount it had.
	let mut changed = Vec::new();
	if document["services"][holder] != holder_before {
		changed.push(holder);
	}
	if let (Some(other), Some(before)) = (other, other_before)
		&& document["services"][other] != before
	{
		changed.push(other);
	}
	let mut lines = holder_lines(&path, holder, carried, forwarded, source);
	if let Some(other) = other {
		lines.extend(other_lines(&path, other, &removed, &other_forwarded));
	}
	Ok(TokenChange {
		update: Some(TokenUpdate {
			companion: Companion {
				path,
				original: bytes,
				candidate: updated,
			},
			lines,
			changed,
		}),
		warnings,
		service: Some(holder),
	})
}

/// The service of the generated compose file, as the object to edit.
fn service_mut<'a>(
	document: &'a mut serde_json::Value,
	name: &str,
) -> Result<&'a mut serde_json::Map<String, serde_json::Value>, String> {
	document
		.get_mut("services")
		.and_then(|services| services.get_mut(name))
		.and_then(serde_json::Value::as_object_mut)
		.ok_or_else(|| format!("compose.yaml has no {name} service"))
}

/// The service that must not keep the credential: the one the split took it
/// away from, when the compose file has it. A stack without the
/// certificates container has none: `mail` holds the credential there.
fn other_service(document: &serde_json::Value, holder: &str) -> Option<&'static str> {
	if holder != "certs" {
		return None;
	}
	document
		.get("services")
		.and_then(|services| services.get("mail"))
		.map(|_| "mail")
}

/// The operator's override file, beside the generated one.
fn override_path(data_dir: &Path) -> std::path::PathBuf {
	crate::cli::init::compose_file_path(data_dir).with_file_name("compose.override.yaml")
}

/// Whether the operator's override hands the credential back to `mail`.
///
/// Every stack invocation passes the override after the generated file
/// (`epistle stack` builds that argv), so a mount in it is merged with the
/// generated one, and a credential there is a credential the container that
/// takes SMTP has, whatever the generated file says.
///
/// The override is YAML and no YAML parser ships in the binary, so this
/// scans the `mail` block for the path or the variable the credential
/// travels as. A file the scan cannot make sense of reports `false`: the
/// warning is advice, and refusing a valid change over it would be worse.
/// What the scan cannot see is a credential behind an anchor, an alias, or
/// a value a template fills in at run time.
fn override_carries(data_dir: &Path, needles: &[String]) -> bool {
	let path = override_path(data_dir);
	let Ok(bytes) =
		crate::cli::init::compose_read::read(&path).map(|read| read.unwrap_or_default())
	else {
		return false;
	};
	let Ok(text) = String::from_utf8(bytes) else {
		return false;
	};
	mail_block(&text)
		.iter()
		.any(|line| needles.iter().any(|needle| line.contains(needle)))
}

/// The lines of the `mail` block of the override, without their indentation.
///
/// The block is found in the block form (`mail:` on its own line) and in the
/// flow form (`mail: {volumes: [...]}`), which carries the whole block in
/// one line.
fn mail_block(text: &str) -> Vec<&str> {
	let mut block = Vec::new();
	let mut indent: Option<usize> = None;
	for line in text.lines() {
		let body = line.trim();
		if body.is_empty() || body.starts_with('#') {
			continue;
		}
		let here = line.len() - line.trim_start().len();
		if let Some(at) = indent {
			if here <= at {
				break;
			}
			block.push(body);
			continue;
		}
		let Some((name, value)) = body.split_once(':') else {
			continue;
		};
		if name.trim() != "mail" {
			continue;
		}
		let value = value.trim();
		if value.is_empty() {
			indent = Some(here);
		} else {
			block.push(value);
		}
	}
	block
}

/// The index of the mount of `path` in the `service` of `document`, when it
/// carries one: a read-only bind at the same path it has on the host.
fn mount_index(document: &serde_json::Value, service: &str, path: &Path) -> Option<usize> {
	document["services"][service]["volumes"]
		.as_array()
		.and_then(|volumes| volumes.iter().position(|mount| is_mount_of(mount, path)))
}

/// Whether the mount is a read-only bind of `path` at the same path it has
/// on the host.
fn is_mount_of(mount: &serde_json::Value, path: &Path) -> bool {
	mount["source"].as_str().map(Path::new) == Some(path)
		&& mount["target"].as_str().map(Path::new) == Some(path)
		&& mount["read_only"].as_bool() == Some(true)
}

/// Remove the variables `names` from the environment of the service.
fn drop_environment(service: &mut serde_json::Map<String, serde_json::Value>, names: &[&str]) {
	if let Some(environment) = service
		.get_mut("environment")
		.and_then(serde_json::Value::as_object_mut)
	{
		for name in names {
			environment.remove(*name);
		}
	}
}

/// Remove the mount of `path` from the service, and say whether it carried
/// one.
fn remove_mount(service: &mut serde_json::Map<String, serde_json::Value>, path: &Path) -> bool {
	let Some(volumes) = service
		.get_mut("volumes")
		.and_then(serde_json::Value::as_array_mut)
	else {
		return false;
	};
	let Some(index) = volumes.iter().position(|mount| is_mount_of(mount, path)) else {
		return false;
	};
	volumes.remove(index);
	true
}

/// The mount the service carries after the change.
///
/// The mount of the token file takes the place of the one it replaces, so
/// the order of the other mounts does not change and the file the operator
/// reads keeps the shape it had.
fn set_mount(
	service: &mut serde_json::Map<String, serde_json::Value>,
	name: &str,
	file: Option<&Path>,
	mounted: Option<usize>,
	already: Option<usize>,
) -> Result<(), String> {
	let volumes = service
		.entry("volumes")
		.or_insert_with(|| serde_json::json!([]))
		.as_array_mut()
		.ok_or_else(|| format!("the {name} volumes must be an array"))?;
	match file {
		Some(file) => {
			let mount = serde_json::json!({
				"type": "bind", "source": file, "target": file,
				"read_only": true, "bind": {"selinux": "Z"}
			});
			match (mounted, already) {
				// The file the change names is mounted already, at another
				// place: the mount it replaces goes.
				(Some(index), Some(other)) if index != other => {
					volumes.remove(index);
				}
				(Some(index), _) => volumes[index] = mount,
				(None, Some(_)) => {}
				(None, None) => volumes.push(mount),
			}
		}
		// The credential the configuration carried before leaves the
		// container with it: a container that keeps the old token mounted
		// still exposes it, and the configuration no longer names the
		// path, so a later edit cannot find the mount to take away.
		None => {
			if let Some(index) = mounted {
				volumes.remove(index);
			}
		}
	}
	Ok(())
}

/// The variable the `service` forwards to the container, out of the ones the
/// command drops.
fn forwarded<'a>(
	document: &serde_json::Value,
	service: &str,
	dropped: &[&'a str],
) -> Option<&'a str> {
	forwarded_all(document, service, dropped).into_iter().next()
}

/// Every variable the `service` forwards to the container, out of the ones
/// the command drops.
fn forwarded_all<'a>(
	document: &serde_json::Value,
	service: &str,
	dropped: &[&'a str],
) -> Vec<&'a str> {
	let Some(environment) = document["services"][service]["environment"].as_object() else {
		return Vec::new();
	};
	dropped
		.iter()
		.copied()
		.filter(|name| {
			environment.get(*name).and_then(serde_json::Value::as_str)
				== Some(&format!("${{{name}}}"))
		})
		.collect()
}

/// What the change means for the container that holds the credential: the
/// file it mounts, and the variable it forwards.
fn holder_lines(
	compose: &Path,
	holder: &str,
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
				"{}: {holder} mounts {} read-only",
				compose.display(),
				after.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: {holder} no longer mounts {}",
				compose.display(),
				before.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: {holder} mounts {} read-only instead of {}",
				compose.display(),
				after.display(),
				before.display()
			));
		}
		_ => {}
	}
	match (previous_env, after_env) {
		(None, Some(after)) => {
			lines.push(format!(
				"{}: {holder} forwards {after} to the container",
				compose.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: {holder} no longer forwards {before} to the container",
				compose.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: {holder} forwards {after} to the container instead of {before}",
				compose.display()
			));
		}
		_ => {}
	}
	lines
}

/// What the change means for the service the split took the credential away
/// from: the operator has to know the token left the container that takes
/// SMTP.
fn other_lines(compose: &Path, other: &str, removed: &[&Path], forwarded: &[&str]) -> Vec<String> {
	let mut lines = Vec::new();
	for path in removed {
		lines.push(format!(
			"{}: {other} no longer mounts {}",
			compose.display(),
			path.display()
		));
	}
	for name in forwarded {
		lines.push(format!(
			"{}: {other} no longer forwards {name} to the container",
			compose.display()
		));
	}
	lines
}
