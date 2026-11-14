//! The panel's admin id: the `{id}` of its admin area, `/app/{id}`.
//!
//! One UUID v4 per installation, kept as a file in the secrets directory with
//! the panel's other files and read by the panel through
//! `EPISTLE_PANEL_ADMIN_ID_FILE`. It is not a cryptographic secret, since the
//! session and the admin role are the barrier, but it is not published either,
//! so it is stored, mounted and kept out of every report like one.
//!
//! The rule for what counts as an id is the panel's own (a UUID v4 in its
//! canonical lower-case form): the panel stops at start on anything else, so
//! a file this module accepted and the panel refused would turn an update into
//! a broken panel. An existing file is therefore kept when it is valid and is
//! an error when it is not, never overwritten: the operator may have put it
//! there on purpose, and a new id changes the address of the admin area.

use std::path::Path;

use ring::rand::SecureRandom;

use super::super::super::apply::{ApplyError, Report, ReportStep};
use super::held::{Held, trimmed};

/// What happens to the admin id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdminIdAction {
	/// A valid id is there and stays as it is.
	Reuse,
	/// There is none, so one is generated.
	Generate,
}

impl std::fmt::Display for AdminIdAction {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::Reuse => "reuse",
			Self::Generate => "generate",
		})
	}
}

/// Whether `text` is a UUID v4 in its canonical lower-case form: the shape
/// the panel accepts and nothing else.
pub(crate) fn is_admin_id(text: &str) -> bool {
	let bytes = text.as_bytes();
	bytes.len() == 36
		&& bytes.iter().enumerate().all(|(at, &byte)| match at {
			8 | 13 | 18 | 23 => byte == b'-',
			14 => byte == b'4',
			19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
			_ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
		})
}

/// The id held in `bytes`, once the line ending an editor may have added is
/// gone, or `None` when what is there is not an id.
pub(crate) fn parse(bytes: &[u8]) -> Option<&str> {
	std::str::from_utf8(trimmed(bytes))
		.ok()
		.filter(|text| is_admin_id(text))
}

/// A new id from `random` bytes: 122 of them are random, the rest are the
/// version and the variant.
fn format(mut random: [u8; 16]) -> String {
	random[6] = (random[6] & 0x0f) | 0x40;
	random[8] = (random[8] & 0x3f) | 0x80;
	let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
	format!(
		"{}-{}-{}-{}-{}",
		&hex[..8],
		&hex[8..12],
		&hex[12..16],
		&hex[16..20],
		&hex[20..]
	)
}

/// An existing file is kept when it holds an id and is an error otherwise.
/// The message names the path and what the panel wants, and never the
/// content: whatever is there may be a secret the operator put in the wrong
/// file.
pub(super) fn decide(held: &Held, path: &Path) -> Result<AdminIdAction, ApplyError> {
	match held {
		Held::Missing => Ok(AdminIdAction::Generate),
		Held::Present(bytes) if parse(bytes).is_some() => Ok(AdminIdAction::Reuse),
		Held::Present(_) => Err(ApplyError::ExistingSecretUnreadable(
			path.to_path_buf(),
			std::io::Error::other(
				"the panel needs a lower-case UUID v4 here (the file may end in a line \
				 break and holds nothing else); remove the file to have a new one \
				 generated, which changes the address of the admin area",
			),
		)),
	}
}

/// The id the panel will serve its admin area at, for the command that shows
/// it: `None` when there is no file yet. A file that is not an id is the same
/// error [`decide`] gives, so showing it and updating the stack agree.
pub(crate) fn read(data_dir: &Path) -> Result<Option<String>, ApplyError> {
	let path = super::admin_id_path(data_dir);
	match super::held::read(&path)? {
		Held::Missing => Ok(None),
		Held::Present(bytes) => match parse(&bytes) {
			Some(id) => Ok(Some(id.to_string())),
			None => decide(&Held::Present(bytes), &path).map(|_| None),
		},
	}
}

/// Carry out `action`. A kept file is narrowed to `0600` if it was wider: its
/// content is valid, so the mode is the only thing to correct.
pub(super) fn apply(
	action: AdminIdAction,
	path: &Path,
	report: &mut Report,
) -> Result<(), ApplyError> {
	if action == AdminIdAction::Reuse {
		narrow(path)?;
		report.steps.push(ReportStep::Reused(path.to_path_buf()));
		return Ok(());
	}
	let mut random = [0u8; 16];
	ring::rand::SystemRandom::new()
		.fill(&mut random)
		.map_err(|_| ApplyError::Rng("panel admin id".to_string()))?;
	crate::storage::write_secret(path, format(random).as_bytes())
		.map_err(|error| ApplyError::KeyWrite(path.to_path_buf(), error))?;
	report.steps.push(ReportStep::Wrote(path.to_path_buf()));
	Ok(())
}

fn narrow(path: &Path) -> Result<(), ApplyError> {
	use std::os::unix::fs::PermissionsExt;
	let write_error = |error: std::io::Error| ApplyError::KeyWrite(path.to_path_buf(), error);
	let mode = std::fs::metadata(path)
		.map_err(write_error)?
		.permissions()
		.mode();
	if mode & 0o777 != 0o600 {
		std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
			.map_err(write_error)?;
	}
	Ok(())
}
