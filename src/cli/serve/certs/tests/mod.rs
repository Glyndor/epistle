use super::*;

mod renewal;
mod requirements;

/// A configuration whose `[acme]` uses `challenge`, with a Cloudflare
/// `[dns]` entry for `example.org` when `dns` is set. The token file is
/// written under `dir` with a value minted at run time.
pub(super) fn config(dir: &std::path::Path, challenge: Option<&str>, dns: bool) -> Config {
	let mut text = format!(
		"hostname = 'mail.example.org'\ndata_dir = '{}'\n",
		dir.join("data").display()
	);
	if let Some(challenge) = challenge {
		text.push_str(&format!(
			"[acme]\ndirectory_url = 'https://acme.invalid/dir'\ndomains = ['mail.example.org']\nchallenge = '{challenge}'\n"
		));
	}
	if dns {
		let token = dir.join("dns_token");
		std::fs::write(&token, uuid::Uuid::new_v4().to_string()).expect("token file");
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))
				.expect("token mode");
		}
		text.push_str(&format!(
			"[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\ntoken_file = '{}'\n",
			token.display()
		));
	}
	toml::from_str(&text).expect("config")
}
