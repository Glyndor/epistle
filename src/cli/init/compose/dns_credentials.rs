//! The DNS credentials the generated compose file hands to the `mail` service.

use std::path::{Path, PathBuf};

use super::Answers;

/// The token variable and token file of every DNS entry the container reads.
///
/// `init` writes one `[dns]`. When the configuration on disk already holds a
/// list of `[[dns]]` tables (one credential per zone, which `init` leaves
/// alone), the container needs the credential of each of them, so they come
/// from that file and not from the single entry of the answers.
pub(super) fn of(answers: &Answers) -> Vec<(Option<String>, Option<PathBuf>)> {
	if let Some(kept) = kept_dns_list(&answers.config_path) {
		return kept;
	}
	answers
		.dns
		.iter()
		.map(|dns| (dns.token_env.clone(), dns.token_file.clone()))
		.collect()
}

/// The credentials of the `[[dns]]` list in the configuration at `path`, or
/// `None` when the file is absent or its `dns` is not a list.
fn kept_dns_list(path: &Path) -> Option<Vec<(Option<String>, Option<PathBuf>)>> {
	let text = crate::cli::regular::read::read_to_string(path).ok()?;
	let value: toml::Value = toml::from_str(&text).ok()?;
	let list = value.get("dns")?.as_array()?;
	Some(
		list.iter()
			.map(|entry| {
				let text = |key: &str| entry.get(key).and_then(toml::Value::as_str);
				(
					text("token_env").map(str::to_string),
					text("token_file").map(PathBuf::from),
				)
			})
			.collect(),
	)
}
