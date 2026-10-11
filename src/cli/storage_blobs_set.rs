//! Validation and field set for `storage blobs set`.

use std::path::Path;

use toml_edit::Value;

use super::{Backend, S3Args};
use crate::cli::config_edit::FieldChange;
use crate::config::{BlobBackendConfig, Config};

/// What `set` will write, and whether it strands blobs in the old backend.
pub(super) struct Plan {
	pub fields: Vec<FieldChange<'static>>,
	pub leaves_blobs_behind: bool,
}

/// Whether any file exists under `root`. An unreadable directory is an error
/// so the check fails closed instead of reporting an empty store.
pub(super) fn has_files(root: &Path) -> Result<bool, String> {
	let entries = match std::fs::read_dir(root) {
		Ok(entries) => entries,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
		Err(error) => return Err(format!("cannot inspect {}: {error}", root.display())),
	};
	for entry in entries {
		let entry = entry.map_err(|error| format!("cannot inspect {}: {error}", root.display()))?;
		let kind = entry
			.file_type()
			.map_err(|error| format!("cannot inspect {}: {error}", root.display()))?;
		if !kind.is_dir() || has_files(&entry.path())? {
			return Ok(true);
		}
	}
	Ok(false)
}

fn check_env(name: &str) -> Result<(), String> {
	let mut chars = name.chars();
	let valid = chars
		.next()
		.is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
		&& chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
	if valid {
		Ok(())
	} else {
		Err(format!(
			"--secret-env \"{name}\" is not an environment variable name"
		))
	}
}

fn check_s3(args: &S3Args) -> Result<(), String> {
	let url = args
		.endpoint
		.strip_prefix("https://")
		.or_else(|| args.endpoint.strip_prefix("http://"))
		.ok_or("--endpoint must start with https:// or http://")?;
	let host = url.split(['/', '?', '#']).next().unwrap_or("");
	if host.is_empty() || host.contains('@') || args.endpoint.chars().any(char::is_whitespace) {
		return Err("--endpoint must be a URL without credentials or spaces".into());
	}
	let bucket = &args.bucket;
	let edge = |c: Option<char>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
	if !(3..=63).contains(&bucket.len())
		|| !bucket
			.chars()
			.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '.'))
		|| !edge(bucket.chars().next())
		|| !edge(bucket.chars().last())
	{
		return Err(format!(
			"--bucket \"{bucket}\" is not a valid bucket name (3 to 63 lowercase letters, digits, '-' and '.')"
		));
	}
	let region = &args.region;
	if region.is_empty()
		|| region.len() > 64
		|| !region
			.chars()
			.all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
	{
		return Err(format!("--region \"{region}\" is not a valid region name"));
	}
	if args.access_key_id.is_empty()
		|| args
			.access_key_id
			.chars()
			.any(|c| c.is_whitespace() || c.is_control())
	{
		return Err("--access-key-id must not be empty or contain whitespace".into());
	}
	match (&args.secret_env, &args.secret_file) {
		(None, None) => {
			Err("s3 needs --secret-env or --secret-file for the secret access key".into())
		}
		(Some(_), Some(_)) => Err("choose one of --secret-env and --secret-file".into()),
		(Some(name), None) => check_env(name),
		(None, Some(path)) if path.starts_with('/') && !path.chars().any(char::is_control) => {
			Ok(())
		}
		(None, Some(_)) => Err("--secret-file must be an absolute path".into()),
	}
}

pub(super) fn plan(current: &Config, backend: &Backend) -> Result<Plan, String> {
	let existing = current.storage.as_ref().and_then(|s| s.blobs.as_ref());
	let local = matches!(existing, None | Some(BlobBackendConfig::Fs));
	let text = |value: &str| Some(Value::from(value));
	match backend {
		Backend::Fs => Ok(Plan {
			fields: vec![
				("backend", text("fs")),
				("endpoint", None),
				("bucket", None),
				("region", None),
				("access_key_id", None),
				("secret_access_key_env", None),
				("secret_access_key_file", None),
			],
			leaves_blobs_behind: matches!(existing, Some(BlobBackendConfig::S3(_))),
		}),
		Backend::S3(args) => {
			check_s3(args)?;
			let stranded = local && has_files(&current.data_dir.join("blobs"))?;
			if stranded && !args.force {
				return Err(format!(
					"blobs already exist under {}; they are not migrated and would stop being served. Pass --force to switch anyway",
					current.data_dir.join("blobs").display()
				));
			}
			let changed = match existing {
				Some(BlobBackendConfig::S3(s3)) => {
					s3.endpoint != args.endpoint || s3.bucket != args.bucket
				}
				_ => true,
			};
			Ok(Plan {
				fields: vec![
					("backend", text("s3")),
					("endpoint", text(&args.endpoint)),
					("bucket", text(&args.bucket)),
					("region", text(&args.region)),
					("access_key_id", text(&args.access_key_id)),
					(
						"secret_access_key_env",
						args.secret_env.as_deref().and_then(text),
					),
					(
						"secret_access_key_file",
						args.secret_file.as_deref().and_then(text),
					),
				],
				leaves_blobs_behind: changed,
			})
		}
	}
}
