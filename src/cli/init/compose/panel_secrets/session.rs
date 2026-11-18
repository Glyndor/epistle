//! The panel's session secret.

use std::path::Path;

use ring::rand::SecureRandom;

use super::super::super::apply::{ApplyError, Report, ReportStep};
use super::SESSION_SECRET_BYTES;
use super::held::{Held, trimmed};

/// What happens to the session secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionAction {
	/// A usable secret is there and stays as it is.
	Reuse,
	/// There is none, so one is generated.
	Generate,
}

impl std::fmt::Display for SessionAction {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			Self::Reuse => "reuse",
			Self::Generate => "generate",
		})
	}
}

/// An existing secret is kept unless it is shorter than the panel accepts,
/// which is an error: replacing it would sign every user out, and the operator
/// who put it there decides what to do about it.
pub(super) fn decide(held: &Held, path: &Path) -> Result<SessionAction, ApplyError> {
	match held {
		Held::Missing => Ok(SessionAction::Generate),
		Held::Present(bytes) if trimmed(bytes).len() >= 32 => Ok(SessionAction::Reuse),
		Held::Present(_) => Err(ApplyError::ExistingSecretUnreadable(
			path.to_path_buf(),
			std::io::Error::other(
				"the panel needs a session secret of at least 32 bytes; remove the file to \
				 have a new one generated, which signs every panel user out",
			),
		)),
	}
}

/// Carry out `action`.
pub(super) fn apply(
	action: SessionAction,
	path: &Path,
	report: &mut Report,
) -> Result<(), ApplyError> {
	if action == SessionAction::Reuse {
		report.steps.push(ReportStep::Reused(path.to_path_buf()));
		return Ok(());
	}
	let mut bytes = [0u8; SESSION_SECRET_BYTES];
	ring::rand::SystemRandom::new()
		.fill(&mut bytes)
		.map_err(|_| ApplyError::Rng("panel session secret".to_string()))?;
	let secret: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
	crate::storage::write_secret(path, secret.as_bytes())
		.map_err(|error| ApplyError::KeyWrite(path.to_path_buf(), error))?;
	report.steps.push(ReportStep::Wrote(path.to_path_buf()));
	Ok(())
}
