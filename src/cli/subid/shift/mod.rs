//! Shifting the owner of files from one subordinate id block to another.
//!
//! Rootless Podman stores a file that a container's uid `n` owns as host id
//! `start + n - 1`, where `start` is the account's subordinate block. When the
//! block moves, every such file has to move by the same offset, or the
//! container sees it as owned by the overflow id. The image layers, the
//! containers' upper directories and the named volumes (the database among
//! them) are all stored that way. Files the account itself owns (container
//! root, and the `mail` service under `keep-id`) are outside the block and
//! are left alone.

use std::fs::Metadata;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Move ids `from..from + count` to `to..to + count`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IdShift {
	/// The first id of the block being left.
	pub(crate) from: u32,
	/// The first id of the block being taken.
	pub(crate) to: u32,
	/// How many ids each block spans.
	pub(crate) count: u32,
}

impl IdShift {
	/// The id `id` becomes, or `None` when it is outside the block being left.
	pub(crate) fn map(self, id: u32) -> Option<u32> {
		let offset = id.checked_sub(self.from)?;
		(offset < self.count).then(|| self.to + offset)
	}

	/// The shift that undoes this one.
	pub(crate) fn reversed(self) -> Self {
		Self {
			from: self.to,
			to: self.from,
			count: self.count,
		}
	}
}

/// The uid and gid shifts applied together; either may be absent when only
/// one table moves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Shift {
	/// The uid move, if the subuid block moves.
	pub(crate) uid: Option<IdShift>,
	/// The gid move, if the subgid block moves.
	pub(crate) gid: Option<IdShift>,
}

impl Shift {
	/// The shift that undoes this one.
	pub(crate) fn reversed(self) -> Self {
		Self {
			uid: self.uid.map(IdShift::reversed),
			gid: self.gid.map(IdShift::reversed),
		}
	}

	/// The new `(uid, gid)` for a file, `None` for an id that stays; `None`
	/// overall when neither moves.
	fn target(self, meta: &Metadata) -> Option<(Option<u32>, Option<u32>)> {
		let uid = self.uid.and_then(|shift| shift.map(meta.uid()));
		let gid = self.gid.and_then(|shift| shift.map(meta.gid()));
		(uid.is_some() || gid.is_some()).then_some((uid, gid))
	}
}

/// What one walk saw and changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Tally {
	/// Entries examined, the root included.
	pub(crate) scanned: u64,
	/// Entries whose owner or group was in a moving block.
	pub(crate) changed: u64,
}

/// Shift the owner of every entry under `root` (the root included) whose
/// uid or gid lies in a moving block. Symbolic links are changed themselves
/// and never followed, and the walk does not descend into another
/// filesystem mounted below `root`. A missing root is an empty tree.
///
/// `chown` clears the set-user-id and set-group-id bits and drops the
/// `security.capability` attribute of a regular file, so both are put back.
pub(crate) fn shift_tree(root: &Path, shift: Shift) -> io::Result<Tally> {
	walk(root, shift, &mut apply)
}

/// Count the entries under `root` whose uid or gid lies in the given blocks,
/// without changing anything. A move refuses a target block that files
/// already use, because undoing the move would then take them along too.
pub(crate) fn count_owned(
	root: &Path,
	uid: Option<(u32, u32)>,
	gid: Option<(u32, u32)>,
) -> io::Result<u64> {
	let still = |block: Option<(u32, u32)>| {
		block.map(|(start, count)| IdShift {
			from: start,
			to: start,
			count,
		})
	};
	let probe = Shift {
		uid: still(uid),
		gid: still(gid),
	};
	walk(root, probe, &mut |_, _, _| Ok(())).map(|tally| tally.changed)
}

/// One entry of the walk: where it was found, the descriptor it was opened
/// as, and what `fstat` says about that descriptor.
pub(crate) struct Visit<'a> {
	/// The entry's path, for the callers that report or record it.
	#[cfg_attr(not(test), allow(dead_code))]
	pub(crate) path: &'a Path,
	/// The entry opened with `O_PATH | O_NOFOLLOW`; every change goes
	/// through it.
	pub(crate) fd: BorrowedFd<'a>,
	/// The metadata of that descriptor, before the change.
	pub(crate) meta: &'a Metadata,
}

/// The change applied to one entry, with the new uid and gid (`None` keeps
/// the current one).
type Apply<'a> = dyn FnMut(&Visit<'_>, Option<u32>, Option<u32>) -> io::Result<()> + 'a;

/// Walk `root` depth first without following links, calling `apply` on each
/// entry that [`Shift::target`] moves. Each entry is opened relative to the
/// root with symbolic links refused in the directories leading to it, so a
/// directory replaced by a link during the walk stops it with an error
/// instead of leading it elsewhere.
pub(crate) fn walk(root: &Path, shift: Shift, apply: &mut Apply<'_>) -> io::Result<Tally> {
	let mut tally = Tally::default();
	let Some(root_fd) = entry::open_root(root)? else {
		return Ok(tally);
	};
	let device = entry::stat(root_fd.as_fd())?.dev();
	let mut pending: Vec<PathBuf> = vec![PathBuf::new()];
	while let Some(relative) = pending.pop() {
		let path = if relative.as_os_str().is_empty() {
			root.to_path_buf()
		} else {
			root.join(&relative)
		};
		let fail =
			|error: io::Error| io::Error::new(error.kind(), format!("{}: {error}", path.display()));
		let fd = if relative.as_os_str().is_empty() {
			root_fd.try_clone()
		} else {
			entry::open_below(root_fd.as_fd(), &relative)
		}
		.map_err(fail)?;
		let meta = entry::stat(fd.as_fd()).map_err(fail)?;
		tally.scanned += 1;
		if let Some((uid, gid)) = shift.target(&meta) {
			let visit = Visit {
				path: &path,
				fd: fd.as_fd(),
				meta: &meta,
			};
			apply(&visit, uid, gid).map_err(fail)?;
			tally.changed += 1;
		}
		if meta.is_dir() && meta.dev() == device {
			for item in std::fs::read_dir(entry::proc_path(fd.as_fd()))? {
				pending.push(relative.join(item?.file_name()));
			}
		}
	}
	Ok(tally)
}

/// The real change: the owner, then the mode bits and file capabilities
/// that changing it cleared, all through the descriptor.
fn apply(visit: &Visit<'_>, uid: Option<u32>, gid: Option<u32>) -> io::Result<()> {
	let (fd, meta) = (visit.fd, visit.meta);
	let capabilities = if meta.is_file() {
		xattr::get(fd, CAPABILITY)?
	} else {
		None
	};
	entry::chown(fd, uid, gid)?;
	if !meta.file_type().is_symlink() && meta.mode() & 0o6000 != 0 {
		entry::chmod(fd, meta.mode() & 0o7777)?;
	}
	if let Some(value) = capabilities {
		xattr::set(fd, CAPABILITY, &value)?;
	}
	Ok(())
}

/// The extended attribute that carries a file's capabilities.
const CAPABILITY: &str = "security.capability";

mod entry;
mod xattr;

#[cfg(test)]
mod tests;
