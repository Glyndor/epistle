//! Coordinate one credential change across the generated stack.

use crate::cli::config_edit::Companion;
use crate::config::Config;

use super::describe::{holder_lines, other_lines};
use super::overrides::{override_carries, override_path};
use super::services::{
	drop_environment, forwarded, forwarded_all, mount_index, other_service, remove_mount,
	service_mut, set_mount,
};
use super::{TokenChange, TokenSource, TokenUpdate, credential_service};

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
pub(in crate::cli::dns_provider) fn with_token(
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
