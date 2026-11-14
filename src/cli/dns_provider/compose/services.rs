//! Service selection and credential environment/mount edits.

use std::path::Path;

/// The service of the generated stack that holds the DNS credential.
pub(crate) fn credential_service(document: &serde_json::Value) -> &'static str {
	if document["services"].get("certs").is_some() {
		"certs"
	} else {
		"mail"
	}
}

/// The service of the generated compose file, as the object to edit.
pub(super) fn service_mut<'a>(
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
pub(super) fn other_service(document: &serde_json::Value, holder: &str) -> Option<&'static str> {
	if holder != "certs" {
		return None;
	}
	document
		.get("services")
		.and_then(|services| services.get("mail"))
		.map(|_| "mail")
}

/// The index of the mount of `path` in the `service` of `document`, when it
/// carries one: a read-only bind at the same path it has on the host.
pub(super) fn mount_index(
	document: &serde_json::Value,
	service: &str,
	path: &Path,
) -> Option<usize> {
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
pub(super) fn drop_environment(
	service: &mut serde_json::Map<String, serde_json::Value>,
	names: &[&str],
) {
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
pub(super) fn remove_mount(
	service: &mut serde_json::Map<String, serde_json::Value>,
	path: &Path,
) -> bool {
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
pub(super) fn set_mount(
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
pub(super) fn forwarded<'a>(
	document: &serde_json::Value,
	service: &str,
	dropped: &[&'a str],
) -> Option<&'a str> {
	forwarded_all(document, service, dropped).into_iter().next()
}

/// Every variable the `service` forwards to the container, out of the ones
/// the command drops.
pub(super) fn forwarded_all<'a>(
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
