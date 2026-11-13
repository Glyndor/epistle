//! The pin file the `epistle-panel` package installs, and what `init` and
//! `stack update` make of it.
//!
//! The package ships no application code. It installs one file holding the
//! image reference of the panel release it belongs to, and epistle renders the
//! `panel` service itself from that reference. The file is the only gate:
//! `dpkg-query` spawns a process inside a rootless re-execution and answers
//! "installed" for a removed package that kept its configuration, whereas the
//! file disappears with `apt remove`.
//!
//! The reference is a tag with no digest, because the digest does not exist
//! when the package is built. [`parse`] makes up for the missing digest by
//! fixing the repository: a file that names any other image is refused, so the
//! file can choose a version of the panel and nothing else.

use std::path::Path;

use crate::cli::init::Answers;

/// Where the package installs its pin file. `glyndor-epistle` reads it, so it
/// must stay world-readable (`/usr/share` is).
pub(crate) const MANIFEST: &str = "/usr/share/glyndor/epistle-panel/image";

/// The only repository the pin file may name.
pub(crate) const REPOSITORY: &str = "ghcr.io/glyndor/epistle-panel";

/// The longest tag the OCI distribution specification allows.
const MAX_TAG: usize = 128;

/// Validate the content of the pin file and return the image reference it
/// holds: `ghcr.io/glyndor/epistle-panel:<tag>`, one line, optionally ended by
/// a single newline, with no digest.
///
/// [`crate::cli::init::images::parse`] requires a tag and a sha256 digest and
/// accepts any repository. This reads the other way round: the repository is
/// fixed and the digest is refused, because a `@sha256:` here would pin a
/// different artifact than the package version names.
pub(crate) fn parse(text: &str) -> Result<String, String> {
	let line = text.strip_suffix('\n').unwrap_or(text);
	if line.is_empty() {
		return Err("it is empty".to_string());
	}
	if line.chars().any(|c| c.is_whitespace() || c.is_control()) {
		return Err("it must hold one reference on one line, with no spaces".to_string());
	}
	let Some(tag) = line
		.strip_prefix(REPOSITORY)
		.and_then(|rest| rest.strip_prefix(':'))
	else {
		return Err(format!("{line:?} is not {REPOSITORY}:<tag>"));
	};
	if !valid_tag(tag) {
		return Err(format!(
			"the tag {tag:?} is not 1 to {MAX_TAG} of letters, digits, `_`, `.` and `-`, \
			 starting with a letter, a digit or `_`"
		));
	}
	Ok(line.to_string())
}

/// Whether `tag` follows the OCI grammar `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
/// An `@` or a `:` is outside it, so a digest or a second tag cannot ride in.
fn valid_tag(tag: &str) -> bool {
	let mut chars = tag.chars();
	let Some(first) = chars.next() else {
		return false;
	};
	tag.len() <= MAX_TAG
		&& (first.is_ascii_alphanumeric() || first == '_')
		&& chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The image reference in the pin file at `path`: `None` when the file does
/// not exist, which is what an uninstalled package looks like, and an error
/// naming the file when it exists but cannot be used.
///
/// A FIFO or a directory is an error and is never read from: the update holds
/// the stack lock while it reads, and a blocked read would hold it forever.
pub(crate) fn installed(path: &Path) -> Result<Option<String>, String> {
	let bytes = match crate::cli::regular::read::read(path) {
		Ok(bytes) => bytes,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
	};
	let text =
		String::from_utf8(bytes).map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
	parse(&text)
		.map(Some)
		.map_err(|why| format!("{} is not usable: {why}", path.display()))
}

/// Decide, from the override and the pin file at `manifest`, whether the stack
/// is to run the panel, and record the image in `answers.services`.
///
/// The panel needs the management API, so `api` says whether the stack serves
/// it. `strict` is set when the operator demanded the panel in the answers
/// file: a `services.panel = true` the package does not back is then an error.
/// Otherwise it is only a note, as during `stack update` and for a `true` that
/// an earlier `init` recorded, where refusing would leave an operator who
/// purged the package unable to update or to run `init` again.
/// Returns the notes the operator should read.
pub(crate) fn resolve(
	answers: &mut Answers,
	manifest: &Path,
	api: bool,
	strict: bool,
) -> Result<Vec<String>, String> {
	answers.services.panel_image = None;
	let asked = answers.services.panel;
	if asked == Some(false) {
		return Ok(Vec::new());
	}
	let Some(image) = installed(manifest)? else {
		if asked != Some(true) {
			return Ok(Vec::new());
		}
		let why = format!(
			"services.panel is true, but the epistle-panel package is not installed ({} is missing)",
			manifest.display()
		);
		return if strict { Err(why) } else { Ok(vec![why]) };
	};
	if !api {
		return Ok(vec![
			"the epistle-panel package is installed, but the management API is off and the panel \
			 needs it, so the stack runs no panel; turn the API on to add it"
				.to_string(),
		]);
	}
	answers.services.panel_image = Some(image);
	Ok(Vec::new())
}

#[cfg(test)]
mod tests;
