//! Best-effort detection of credentials in operator overrides.

use std::path::Path;

/// The operator's override file, beside the generated one.
pub(super) fn override_path(data_dir: &Path) -> std::path::PathBuf {
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
pub(super) fn override_carries(data_dir: &Path, needles: &[String]) -> bool {
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
