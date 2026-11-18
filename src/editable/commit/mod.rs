//! The one write path of a [`StateFile`]: under the cross-process lock of the
//! file, from a fresh read (or the seed, when the file does not exist yet),
//! checked against the configuration the server would load, and written
//! atomically and owner-only. A change that changes nothing writes nothing.

use std::path::PathBuf;

use crate::config::Config;
use crate::storage::locked::{EditError, edit_and_commit};

use super::StateFile;

/// The outcome of a [`commit`] or a [`preview`].
#[derive(Debug, Clone)]
pub struct Committed<S> {
	/// Whether the state changed.
	pub changed: bool,
	/// The state before the change.
	pub before: S,
	/// The state after it.
	pub after: S,
	/// The configuration the server loads with the new state.
	pub config: Config,
	/// The file the state lives in.
	pub path: PathBuf,
}

/// Why a change was not written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitError<E> {
	/// The change itself refused.
	Refused(E),
	/// The server would refuse the configuration the change leaves.
	Invalid(String),
	/// The file could not be locked, read or written.
	Io(String),
}

enum Stop<E> {
	Unchanged,
	Error(CommitError<E>),
}

/// The state `change` leaves `state` in, refused when the configuration the
/// server would load with it is not valid. `change` gets the configuration
/// the server runs with `state`.
fn next<S, E>(
	config: &Config,
	state: &S,
	change: impl FnOnce(&Config, &mut S) -> Result<(), E>,
) -> Result<S, CommitError<E>>
where
	S: StateFile,
{
	let current = S::apply(config, state);
	let mut next = state.clone();
	change(&current, &mut next).map_err(CommitError::Refused)?;
	if next != *state {
		S::apply(config, &next)
			.validate()
			.map_err(|error| CommitError::Invalid(error.to_string()))?;
	}
	Ok(next)
}

/// Apply `change` under the lock of `config`'s state file `S` and write the
/// result. `config` is the configuration as loaded.
pub fn commit<S, E>(
	config: &Config,
	change: impl FnOnce(&Config, &mut S) -> Result<(), E>,
) -> Result<Committed<S>, CommitError<E>>
where
	S: StateFile,
{
	let path = super::path::<S>(&config.data_dir);
	let mut before = None;
	let result = edit_and_commit(
		&path,
		S::parse,
		S::render,
		|| S::seed(config),
		|state: &mut S| {
			let original = state.clone();
			let updated = next(config, state, change).map_err(Stop::Error)?;
			before = Some(original.clone());
			if updated == original {
				return Err(Stop::Unchanged);
			}
			*state = updated;
			Ok(())
		},
		|state| state,
	);
	let io = |error: std::io::Error| CommitError::Io(format!("{}: {error}", path.display()));
	match result {
		Ok(after) => Ok(Committed {
			changed: true,
			config: S::apply(config, &after),
			before: before.unwrap_or_default(),
			after,
			path,
		}),
		Err(EditError::Mutate(Stop::Unchanged)) => {
			let state = before.unwrap_or_default();
			Ok(Committed {
				changed: false,
				config: S::apply(config, &state),
				before: state.clone(),
				after: state,
				path,
			})
		}
		Err(EditError::Mutate(Stop::Error(error))) => Err(error),
		Err(EditError::Io(error)) => Err(io(error)),
	}
}

/// What [`commit`] would do, without the lock and without writing: for a
/// dry run.
pub fn preview<S, E>(
	config: &Config,
	change: impl FnOnce(&Config, &mut S) -> Result<(), E>,
) -> Result<Committed<S>, CommitError<E>>
where
	S: StateFile,
{
	let path = super::path::<S>(&config.data_dir);
	let read = std::fs::read_to_string(&path);
	let before = match read {
		Ok(text) => S::parse(&text),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(S::seed(config)),
		Err(error) => Err(error),
	}
	.map_err(|error| CommitError::Io(format!("{}: {error}", path.display())))?;
	let after = next(config, &before, change)?;
	Ok(Committed {
		changed: after != before,
		config: S::apply(config, &after),
		before,
		after,
		path,
	})
}

/// Write the state file `S` from what the configuration file declares when it
/// does not exist yet. Returns whether it was written.
pub fn seed<S: StateFile>(config: &Config) -> std::io::Result<bool> {
	let path = super::path::<S>(&config.data_dir);
	if path.exists() {
		return Ok(false);
	}
	edit_and_commit(
		&path,
		S::parse,
		S::render,
		|| S::seed(config),
		|_: &mut S| Ok::<(), std::convert::Infallible>(()),
		|_| true,
	)
	.map_err(|error| match error {
		EditError::Io(error) => error,
		EditError::Mutate(never) => match never {},
	})
}
