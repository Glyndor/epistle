//! The images the generated stack runs, read at build time from
//! `deploy/images/Dockerfile`, the file Dependabot watches.

use std::collections::BTreeMap;
use std::sync::OnceLock;

/// The manifest, as it was when this binary was built.
const MANIFEST: &str = include_str!("../../../../deploy/images/Dockerfile");

/// Parse the manifest into `stage name -> image reference`. Every
/// reference must carry a tag and a sha256 digest.
pub(crate) fn parse(text: &str) -> Result<BTreeMap<String, String>, String> {
	let mut images = BTreeMap::new();
	for line in text.lines().map(str::trim) {
		if line.is_empty() || line.starts_with('#') {
			continue;
		}
		let words: Vec<&str> = line.split_whitespace().collect();
		let [from, reference, as_word, name] = words.as_slice() else {
			return Err(format!("{line:?} is not `FROM <image> AS <service>`"));
		};
		if !from.eq_ignore_ascii_case("FROM") || !as_word.eq_ignore_ascii_case("AS") {
			return Err(format!("{line:?} is not `FROM <image> AS <service>`"));
		}
		if !pinned(reference) {
			return Err(format!(
				"{reference} is not pinned as <image>:<tag>@sha256:<digest>"
			));
		}
		images.insert((*name).to_string(), (*reference).to_string());
	}
	Ok(images)
}

/// Whether `reference` carries both a tag and a full sha256 digest.
fn pinned(reference: &str) -> bool {
	let Some((name, digest)) = reference.split_once("@sha256:") else {
		return false;
	};
	let tagged = tag(name).is_some();
	tagged && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The tag of a reference without its digest: what follows the last `:`
/// after the last `/`, so a registry port is not taken for a tag.
fn tag(name: &str) -> Option<&str> {
	let last = name.rsplit('/').next()?;
	last.split_once(':').map(|(_, tag)| tag)
}

fn all() -> &'static BTreeMap<String, String> {
	static IMAGES: OnceLock<BTreeMap<String, String>> = OnceLock::new();
	IMAGES.get_or_init(|| {
		// The manifest is compiled in, and images_tests parses this exact
		// text, so a build whose manifest does not parse fails its tests.
		parse(MANIFEST).unwrap_or_default()
	})
}

fn image(name: &str) -> &'static str {
	all().get(name).map(String::as_str).unwrap_or_default()
}

/// The PostgreSQL image of the `db` service.
pub(crate) fn postgres() -> &'static str {
	image("postgres")
}

/// The ClamAV image of the `clamav` and `freshclam` services.
pub(crate) fn clamav() -> &'static str {
	image("clamav")
}

/// The base the default `mail` service runs the host binary on.
pub(crate) fn mail_base() -> &'static str {
	image("mail")
}

/// The major version in a reference's tag: `18` for `postgres:18@sha256:...`
/// and for `postgres:18.6-alpine`. `None` without a numeric tag.
pub(crate) fn major(reference: &str) -> Option<u32> {
	let name = reference.split('@').next()?;
	let digits: String = tag(name)?
		.chars()
		.take_while(char::is_ascii_digit)
		.collect();
	digits.parse().ok()
}

#[cfg(test)]
mod tests;
