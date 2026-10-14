//! Stage the files an operator names for a command that root re-executes
//! as the service account.
//!
//! The account cannot read a file the operator keeps for root (a password
//! file mode 0600, Mox's configuration), nor write where the operator asked
//! for output. So the root parent copies every input named on the command
//! line into a fresh private directory the account owns, points the
//! argument at the copy, and after the account's run moves each output to
//! where the operator asked for it. [`table`] lists which arguments name
//! paths and what is done with each. Nothing staged is ever printed or
//! logged; messages name paths only.

mod copy;
mod output;
mod shown;
mod stat;
pub(crate) mod table;

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub(crate) use copy::Chown;
pub(crate) use shown::{ENV as SHOWN_ENV, shown};
use table::{Kind, Staged};

/// The command line for the delegated run, with every staged argument
/// pointing into the staging directory, and what to do once it exits.
/// Dropping it removes the staging directory.
pub(crate) struct Stage {
	args: Vec<OsString>,
	dir: Option<StageDir>,
	outputs: Vec<Output>,
	shown: Vec<(PathBuf, PathBuf)>,
	/// The account's uid: everything moved back must be its own.
	account: u32,
	/// This process's uid (root): an export goes only into a directory it owns.
	root: u32,
}

struct StageDir {
	/// Where the delegated run finds it.
	path: PathBuf,
	/// The account's home, and the directory's name in it, for the removal.
	home: File,
	name: PathBuf,
	handle: File,
}

struct Output {
	/// Where the delegated run writes, inside the staging directory.
	rel: PathBuf,
	requested: PathBuf,
	kind: Kind,
}

impl Stage {
	/// Stage every operator-named path of `args` (the command line without
	/// the program name) under `home`, handing each copy to the account with
	/// `chown`; `account` is its uid. A command line that names no path is
	/// returned unchanged and creates nothing.
	pub(crate) fn prepare(
		args: &[OsString],
		home: &Path,
		account: u32,
		chown: Chown,
	) -> io::Result<Self> {
		Self::prepare_with(args, home, account, chown, table::STAGED)
	}

	/// [`Stage::prepare`] against `table` instead of [`table::STAGED`]; tests
	/// use it to stage with small size bounds.
	pub(crate) fn prepare_with(
		args: &[OsString],
		home: &Path,
		account: u32,
		chown: Chown,
		table: &[Staged],
	) -> io::Result<Self> {
		let mut stage = Self {
			args: args.to_vec(),
			dir: None,
			outputs: Vec::new(),
			shown: Vec::new(),
			account,
			// SAFETY: geteuid takes no arguments and cannot fail.
			root: unsafe { libc::geteuid() },
		};
		let found = table::find(args, table);
		if found.is_empty() {
			return Ok(stage);
		}
		for item in &found {
			check_output(&item.value, item.kind)?;
		}
		let dir = create(home)?;
		let (path, handle) = (dir.path.clone(), dir.handle.try_clone()?);
		stage.dir = Some(dir);
		for (index, item) in found.iter().enumerate() {
			let slot = PathBuf::from(index.to_string());
			let slot_dir = copy::make_dir(&handle, &slot)?;
			let (rel, shown_rel, requested) =
				stage_one(&item.value, item.kind, &slot_dir, &slot, chown)?;
			chown(&slot_dir, &slot)?;
			let mut token = item.prefix.clone().unwrap_or_default();
			token.push(path.join(&rel));
			stage.args[item.token] = token;
			stage.shown.push((path.join(shown_rel), requested));
			if matches!(item.kind, Kind::WriteFile | Kind::WriteDir) {
				stage.outputs.push(Output {
					rel,
					requested: item.value.clone(),
					kind: item.kind,
				});
			}
		}
		chown(&handle, Path::new(""))?;
		Ok(stage)
	}

	/// The command line for the delegated run.
	pub(crate) fn args(&self) -> &[OsString] {
		&self.args
	}

	/// The staged paths and the paths the operator named, for the delegated
	/// run to print the operator's paths in its messages; `None` when
	/// nothing was staged.
	pub(crate) fn shown_env(&self) -> Option<String> {
		(!self.shown.is_empty()).then(|| shown::encode(&self.shown))
	}

	/// After the delegated run: on success move each output to the path the
	/// operator asked for; on failure leave nothing there. The staging
	/// directory goes either way, when `self` drops.
	pub(crate) fn finish(self, success: bool) -> io::Result<()> {
		if !success {
			return Ok(());
		}
		let Some(dir) = &self.dir else {
			return Ok(());
		};
		for output in &self.outputs {
			match output.kind {
				Kind::WriteFile => output::move_file(&dir.handle, output, self.account)?,
				Kind::WriteDir => output::move_dir(
					&dir.handle,
					output,
					self.account,
					self.root,
					output::free_room,
				)?,
				_ => {}
			}
		}
		Ok(())
	}
}

impl Drop for Stage {
	fn drop(&mut self) {
		let Some(dir) = self.dir.take() else {
			return;
		};
		let removed = copy::clear(&dir.handle)
			.and_then(|()| fs::remove_dir(copy::under(&dir.home, &dir.name)));
		if let Err(error) = removed {
			crate::cli::style::warn(format_args!(
				"could not remove the staging directory {}: {error}",
				dir.path.display()
			));
		}
	}
}

/// Refuse an output the delegated run could not deliver, before anything
/// runs: a password list never replaces an existing file, and an export
/// goes into a missing or empty directory.
fn check_output(requested: &Path, kind: Kind) -> io::Result<()> {
	let shown = requested.display();
	match kind {
		Kind::WriteFile => {
			if fs::symlink_metadata(requested).is_ok() {
				return Err(io::Error::other(format!(
					"{shown} already exists; the command writes a new file"
				)));
			}
			let parent = shown_parent(requested);
			if !fs::metadata(&parent).is_ok_and(|meta| meta.is_dir()) {
				return Err(io::Error::other(format!(
					"the directory of {shown} does not exist"
				)));
			}
		}
		Kind::WriteDir => match fs::symlink_metadata(requested) {
			Err(error) if error.kind() == io::ErrorKind::NotFound => {}
			Err(error) => return Err(io::Error::other(format!("reading {shown}: {error}"))),
			Ok(meta) if meta.is_dir() && fs::read_dir(requested)?.next().is_none() => {}
			Ok(_) => {
				return Err(io::Error::other(format!(
					"{shown} is not an empty directory; run as root, the export writes into \
					 a missing or empty one"
				)));
			}
		},
		_ => {}
	}
	Ok(())
}

/// The directory a named file is in, `.` for a bare file name.
fn shown_parent(path: &Path) -> PathBuf {
	match path.parent() {
		Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
		_ => PathBuf::from("."),
	}
}

/// A new private directory in `home`, made and owned by this process and
/// opened before anything goes in. The account owns `home` and could swap
/// the new name for a directory of its own: [`copy::make_dir`] accepts only
/// a directory this process owns.
fn create(home: &Path) -> io::Result<StageDir> {
	let token = crate::cli::util::generate_secret()
		.ok_or_else(|| io::Error::other("no randomness for the staging directory name"))?;
	let name = PathBuf::from(format!(".epistle-staging-{}", &token[..16]));
	let path = home.join(&name);
	let creating = |error: io::Error| {
		io::Error::new(
			error.kind(),
			format!("creating {}: {error}", path.display()),
		)
	};
	let home = OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_DIRECTORY)
		.open(home)
		.map_err(creating)?;
	let handle = copy::make_dir(&home, &name).map_err(creating)?;
	Ok(StageDir {
		path,
		home,
		name,
		handle,
	})
}

/// Copy one input into `slot`, or reserve the name an output is written
/// to. Returns the staged path for the argument, relative to the staging
/// directory, and the staged prefix that stands for an operator's path in
/// messages, with that path.
fn stage_one(
	value: &Path,
	kind: Kind,
	slot: &File,
	rel: &Path,
	chown: Chown,
) -> io::Result<(PathBuf, PathBuf, PathBuf)> {
	let same = |rel: PathBuf| (rel.clone(), rel, value.to_path_buf());
	let name = |path: &Path, fallback: &str| {
		path.file_name()
			.map(PathBuf::from)
			.unwrap_or_else(|| PathBuf::from(fallback))
	};
	match kind {
		Kind::ReadFile { limit, secret } => {
			let node = operator_node(value)?;
			if !node.meta.is_file() {
				return Err(io::Error::other(format!(
					"{} is not a file",
					value.display()
				)));
			}
			if secret && node.meta.mode() & 0o077 != 0 {
				crate::cli::style::warn(format_args!(
					"{} is readable by other users; keep password files mode 0600",
					value.display()
				));
			}
			let file = name(value, "input");
			let mut budget = copy::Budget::new(limit, value);
			copy::copy_file(
				node,
				value,
				slot,
				&file,
				&rel.join(&file),
				&mut budget,
				chown,
			)?;
			Ok(same(rel.join(file)))
		}
		Kind::ReadDir { limit } => {
			stage_dir(operator_node(value)?, value, slot, rel, limit, chown).map(same)
		}
		Kind::ReadDirOfFile { limit } => {
			let node = operator_node(value)?;
			if node.meta.is_dir() {
				return stage_dir(node, value, slot, rel, limit, chown).map(same);
			}
			let parent = shown_parent(value);
			let dir = stage_dir(operator_node(&parent)?, &parent, slot, rel, limit, chown)?;
			Ok((dir.join(name(value, "input")), dir, parent))
		}
		Kind::WriteFile | Kind::WriteDir => Ok(same(rel.join(name(value, "output")))),
	}
}

/// The path the operator named, opened without following it and checked.
fn operator_node(value: &Path) -> io::Result<copy::Node> {
	let node = copy::open_node(value, value)?;
	node.check(value, copy::Source::Operator)?;
	Ok(node)
}

/// Copy the directory open as `node` (the operator's `value`) into `slot`.
fn stage_dir(
	node: copy::Node,
	value: &Path,
	slot: &File,
	rel: &Path,
	limit: u64,
	chown: Chown,
) -> io::Result<PathBuf> {
	if !node.meta.is_dir() {
		return Err(io::Error::other(format!(
			"{} is not a directory",
			value.display()
		)));
	}
	let source = node.dir()?;
	let name = value
		.file_name()
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from("input"));
	let target = copy::make_dir(slot, &name)?;
	let rel = rel.join(&name);
	chown(&target, &rel)?;
	let mut budget = copy::Budget::new(limit, value);
	copy::copy_tree(&source, &target, value, &rel, &mut budget, chown)?;
	Ok(rel)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
