//! The token `--store-token` moves: where it comes from and where it goes.
//!
//! The destination is the secrets directory beside `data_dir`, the place the
//! storage and OAuth keys live, with mode `0600` and a directory the other
//! accounts cannot enter.

use std::fs;
use std::path::Path;

use crate::config::Config;
use crate::dns::provider::ScopedSecret;

/// The token to store: the one the command was given, or the one the
/// configuration carried.
pub(super) fn token(
	config: &Config,
	args: &super::ProviderArgs,
	zone: &str,
) -> Result<String, String> {
	if args.token_env.is_some() && args.token_file.is_some() {
		return Err("choose one of --token-env and --token-file".into());
	}
	let dns = config.dns.for_zone(zone);
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

/// Write the token to the destination, or refuse to replace a different one.
pub(super) fn store(path: &Path, token: &str) -> Result<(), String> {
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

#[cfg(test)]
mod tests;
