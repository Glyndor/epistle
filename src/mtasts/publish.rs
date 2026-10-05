//! Render and atomically publish the policy advertised in DNS.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};

use crate::config::Config;

/// Policy bytes and their content-derived DNS identifier.
pub struct Publication {
	/// UTF-8 policy document, including its final newline.
	pub content: String,
	/// First 128 bits of SHA-256, encoded as 32 hexadecimal characters.
	pub id: String,
}

/// Derive the policy and DNS identifier from the configured MX hostname.
pub fn publication(config: &Config) -> Publication {
	let content = format!(
		"version: STSv1\nmode: {}\nmx: {}\nmax_age: {}\n",
		config.mta_sts.mode.as_str(),
		config.hostname,
		config.mta_sts.max_age,
	);
	let digest = ring::digest::digest(&ring::digest::SHA256, content.as_bytes());
	let id = digest.as_ref()[..16]
		.iter()
		.fold(String::new(), |mut out, byte| {
			use std::fmt::Write;
			let _ = write!(out, "{byte:02x}");
			out
		});
	Publication { content, id }
}

/// Replace the configured public policy with a complete, mode-0644 document.
/// An unset policy directory leaves the filesystem untouched.
pub fn write_policy(config: &Config) -> io::Result<()> {
	let Some(dir) = &config.mta_sts.policy_dir else {
		return Ok(());
	};
	let policy = publication(config);
	fs::create_dir_all(dir)?;
	let temporary = dir.join(format!(".mta-sts-{}.tmp", uuid::Uuid::now_v7().simple()));
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.mode(0o600);
	}
	let mut file = options.open(&temporary)?;
	let result = (|| {
		file.write_all(policy.content.as_bytes())?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			file.set_permissions(fs::Permissions::from_mode(0o644))?;
		}
		file.sync_all()?;
		fs::rename(&temporary, dir.join("mta-sts.txt"))
	})();
	if result.is_err() {
		let _ = fs::remove_file(&temporary);
	}
	result
}

#[cfg(test)]
#[path = "publish_tests.rs"]
mod tests;
