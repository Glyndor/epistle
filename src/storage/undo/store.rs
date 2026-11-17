//! The directory of held submissions: `pending/` while the sender may still
//! cancel, `released/` for the short-lived record that one was handed on.
//!
//! A due message is claimed under the lock by renaming it into `inflight/`
//! before anything is handed on, so a cancel and a release cannot both win and
//! two releasers cannot hand on the same message.
//!
//! A pending file is named `<release_at>-<id>.held`, so which entries are
//! due is read from names alone, without opening a message. A file is
//! sealed through [`MessageCrypto`] like the spool's, bound to the id, and
//! is written with the spool's guarantees: owner-only, synced, renamed into
//! place. Every change that races a cancel takes one `flock` on `lock`.

use std::fs;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use super::frame::Held;
use crate::storage::MessageCrypto;
use crate::util::path_containment::contained_child;

/// How long the record of a released submission is kept: long enough to
/// answer "already sent" to a late cancel, short enough to hold no history.
pub const RELEASED_KEPT_SECS: u64 = 86_400;

/// Who asks to cancel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Canceller<'a> {
	/// The account that submitted the message: it may cancel its own only.
	Account(&'a str),
	/// The operator at the command line, who may cancel any.
	Operator,
}

/// Why a cancellation did not happen.
#[derive(Debug, thiserror::Error)]
pub enum CancelError {
	/// There is no such held submission for this caller. The same answer
	/// for an id that never existed and one that belongs to another account.
	#[error("no such held submission")]
	NotFound,
	/// The submission was already handed on (or is being) and cannot be
	/// taken back.
	#[error("the message was already handed on and cannot be cancelled")]
	AlreadySent,
	/// The store could not be read or written.
	#[error("held submission store: {0}")]
	Io(#[from] std::io::Error),
}

/// What a listing says about a held submission, never its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
	/// The submission id.
	pub id: Uuid,
	/// Epoch seconds before which it is not delivered.
	pub release_at: u64,
}

/// The held submissions under `<data_dir>/undo`.
#[derive(Debug, Clone)]
pub struct UndoStore {
	root: PathBuf,
	crypto: MessageCrypto,
}

#[derive(Clone, Copy)]
enum Dir {
	Pending,
	Inflight,
	Released,
}

impl Dir {
	fn name(self) -> &'static str {
		match self {
			Self::Pending => "pending",
			Self::Inflight => "inflight",
			Self::Released => "released",
		}
	}

	fn ext(self) -> &'static str {
		match self {
			Self::Pending => "held",
			Self::Inflight => "held",
			Self::Released => "done",
		}
	}
}

/// Make a removal durable: the directory that held the name is synced.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
	#[cfg(unix)]
	return fs::File::open(dir)?.sync_all();
	#[cfg(not(unix))]
	{
		let _ = dir;
		Ok(())
	}
}

/// `<epoch>-<id>.<ext>` read back into its two numbers.
fn parse_name(name: &str, ext: &str) -> Option<(u64, Uuid)> {
	let stem = name.strip_suffix(ext)?.strip_suffix('.')?;
	let (epoch, id) = stem.split_once('-')?;
	Some((epoch.parse().ok()?, Uuid::parse_str(id).ok()?))
}

impl UndoStore {
	/// Open (creating if needed) the store under `data_dir`.
	pub fn open(data_dir: &Path, crypto: MessageCrypto) -> std::io::Result<Self> {
		let root = data_dir.join("undo");
		for dir in [Dir::Pending, Dir::Inflight, Dir::Released] {
			crate::storage::create_private_dir(&root.join(dir.name()))?;
		}
		Ok(Self { root, crypto })
	}

	fn dir(&self, dir: Dir) -> PathBuf {
		self.root.join(dir.name())
	}

	/// The file of one held submission. The name is built from a number, an
	/// id and an extension only, and still goes through the containment check
	/// every join under the data dir uses, so it can only be a direct child of
	/// its directory.
	fn file(&self, dir: Dir, epoch: u64, id: Uuid) -> std::io::Result<PathBuf> {
		let name = format!("{epoch:020}-{id}.{}", dir.ext());
		contained_child(&self.dir(dir), &name)
	}

	fn lock(&self) -> std::io::Result<fs::File> {
		let file = fs::OpenOptions::new()
			.create(true)
			.truncate(false)
			.write(true)
			.open(self.root.join("lock"))?;
		file.lock()?;
		Ok(file)
	}

	/// The `(epoch, id)` of every file in `dir`, oldest first.
	fn names(&self, dir: Dir) -> std::io::Result<Vec<(u64, Uuid)>> {
		let mut found = Vec::new();
		for entry in crate::util::fs_walk::read_dir(self.dir(dir))? {
			let entry = entry?;
			if let Some(parsed) = entry
				.file_name()
				.to_str()
				.and_then(|name| parse_name(name, dir.ext()))
			{
				found.push(parsed);
			}
		}
		found.sort();
		Ok(found)
	}

	fn seal(&self, id: Uuid, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
		self.crypto.encode_with_aad(bytes, id.as_bytes())
	}

	fn open_bytes(&self, id: Uuid, stored: &[u8]) -> std::io::Result<Vec<u8>> {
		if !crate::storage::is_envelope(stored) {
			return Ok(stored.to_vec());
		}
		self.crypto
			.decode_with_aad(stored, id.as_bytes())
			.map_err(|error| std::io::Error::other(format!("held submission: {error}")))
	}

	/// Keep `held` until its release time. It is on disk, sealed, when this
	/// returns, so a crash from here on keeps it.
	pub fn hold(&self, held: &Held) -> std::io::Result<()> {
		let sealed = self.seal(held.id, &held.to_bytes()?)?;
		crate::storage::write_secret(&self.file(Dir::Pending, held.release_at, held.id)?, &sealed)
	}

	/// The held submission `id`, if it is still pending.
	fn load(&self, release_at: u64, id: Uuid) -> std::io::Result<Held> {
		self.load_in(Dir::Pending, release_at, id)
	}

	fn load_in(&self, dir: Dir, release_at: u64, id: Uuid) -> std::io::Result<Held> {
		let stored = crate::util::fs_walk::read(self.file(dir, release_at, id)?)?;
		Held::from_bytes(&self.open_bytes(id, &stored)?)
	}

	/// The ids of the submissions whose release time is `now` or before,
	/// the earliest first.
	pub fn due(&self, now: u64) -> std::io::Result<Vec<Pending>> {
		Ok(self
			.names(Dir::Pending)?
			.into_iter()
			.take_while(|(release_at, _)| *release_at <= now)
			.map(|(release_at, id)| Pending { id, release_at })
			.collect())
	}

	/// Every pending submission, with the account that made it, for the
	/// operator's listing. The content is never shown.
	pub fn pending(&self) -> std::io::Result<Vec<(Pending, String)>> {
		let mut found = Vec::new();
		for (release_at, id) in self.names(Dir::Pending)? {
			match self.load(release_at, id) {
				Ok(held) => found.push((Pending { id, release_at }, held.account)),
				Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
				Err(error) => return Err(error),
			}
		}
		Ok(found)
	}

	/// Claim one due submission for release: under the lock, move it from
	/// `pending/` to `inflight/` and read it. From then on a cancel is refused
	/// ([`CancelError::AlreadySent`]) and no other releaser can claim it.
	/// `None` when it is gone: cancelled, or claimed by another releaser.
	pub fn claim(&self, pending: &Pending) -> std::io::Result<Option<Held>> {
		let _guard = self.lock()?;
		let from = self.file(Dir::Pending, pending.release_at, pending.id)?;
		let to = self.file(Dir::Inflight, pending.release_at, pending.id)?;
		match fs::rename(&from, &to) {
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
			other => other?,
		}
		sync_dir(&self.dir(Dir::Pending))?;
		sync_dir(&self.dir(Dir::Inflight))?;
		self.load_in(Dir::Inflight, pending.release_at, pending.id)
			.map(Some)
	}

	/// Give a claimed submission back to `pending/` because the sink could
	/// not take it yet; it is due again at the next pass.
	pub fn requeue(&self, held: &Held) -> std::io::Result<()> {
		let _guard = self.lock()?;
		fs::rename(
			self.file(Dir::Inflight, held.release_at, held.id)?,
			self.file(Dir::Pending, held.release_at, held.id)?,
		)?;
		sync_dir(&self.dir(Dir::Pending))
	}

	/// Put every claimed submission back to `pending/`, due at once. Run when
	/// the releaser starts: a claim left by a process that died is retried,
	/// which hands the message on again if the crash came after the sink took
	/// it and before the record was written (at least once, never lost).
	pub fn recover(&self) -> std::io::Result<usize> {
		let _guard = self.lock()?;
		let mut moved = 0;
		for (at, id) in self.names(Dir::Inflight)? {
			fs::rename(
				self.file(Dir::Inflight, at, id)?,
				self.file(Dir::Pending, at, id)?,
			)?;
			moved += 1;
		}
		sync_dir(&self.dir(Dir::Pending))?;
		Ok(moved)
	}

	/// The account that made the pending submission `id` and when it is
	/// released, if it is pending.
	pub fn lookup(&self, id: Uuid) -> std::io::Result<Option<(String, u64)>> {
		let Some((release_at, _)) = self
			.names(Dir::Pending)?
			.into_iter()
			.find(|(_, found)| *found == id)
		else {
			return Ok(None);
		};
		match self.load(release_at, id) {
			Ok(held) => Ok(Some((held.account, held.release_at))),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(error),
		}
	}

	/// The account that made `id`, which was released and is still recorded
	/// as such.
	pub fn released_account(&self, id: Uuid) -> std::io::Result<Option<String>> {
		let Some((at, _)) = self
			.names(Dir::Released)?
			.into_iter()
			.find(|(_, found)| *found == id)
		else {
			return Ok(None);
		};
		let stored = crate::util::fs_walk::read(self.file(Dir::Released, at, id)?)?;
		String::from_utf8(self.open_bytes(id, &stored)?)
			.map(Some)
			.map_err(|error| std::io::Error::other(error.to_string()))
	}

	/// Take the submission back so that nothing of it is ever delivered.
	///
	/// Allowed only for the account that made it (or the operator), and only
	/// while `now` is before its release time. At or after it, or once it
	/// has been released, the answer is [`CancelError::AlreadySent`] for the
	/// account that made it and [`CancelError::NotFound`] for anyone else.
	pub fn cancel(&self, id: Uuid, by: Canceller<'_>, now: u64) -> Result<(), CancelError> {
		self.cancel_at(id, by, || now)
	}

	/// [`cancel`](Self::cancel) reading the clock once the lock is held, so a
	/// caller that waited for the lock is judged by the time it got it.
	pub fn cancel_now(&self, id: Uuid, by: Canceller<'_>) -> Result<(), CancelError> {
		self.cancel_at(id, by, crate::storage::delivery_log::now_epoch)
	}

	fn cancel_at(
		&self,
		id: Uuid,
		by: Canceller<'_>,
		now: impl FnOnce() -> u64,
	) -> Result<(), CancelError> {
		let _guard = self.lock()?;
		let now = now();
		let owns = |account: &str| match by {
			Canceller::Account(name) => name == account,
			Canceller::Operator => true,
		};
		if let Some((release_at, _)) = self
			.names(Dir::Pending)?
			.into_iter()
			.find(|(_, found)| *found == id)
		{
			let held = self.load(release_at, id)?;
			if !owns(&held.account) {
				return Err(CancelError::NotFound);
			}
			if now >= held.release_at {
				return Err(CancelError::AlreadySent);
			}
			fs::remove_file(self.file(Dir::Pending, release_at, id)?)?;
			sync_dir(&self.dir(Dir::Pending))?;
			return Ok(());
		}
		if let Some((at, _)) = self
			.names(Dir::Inflight)?
			.into_iter()
			.find(|(_, found)| *found == id)
		{
			let held = self.load_in(Dir::Inflight, at, id)?;
			return Err(if owns(&held.account) {
				CancelError::AlreadySent
			} else {
				CancelError::NotFound
			});
		}
		if let Some(account) = self.released_account(id)?
			&& owns(&account)
		{
			return Err(CancelError::AlreadySent);
		}
		Err(CancelError::NotFound)
	}

	/// Record that `held` was handed on and drop the pending file: a late
	/// cancel then says "already sent" instead of "not found".
	pub fn finish(&self, held: &Held, now: u64) -> std::io::Result<()> {
		let _guard = self.lock()?;
		let sealed = self.seal(held.id, held.account.as_bytes())?;
		crate::storage::write_secret(&self.file(Dir::Released, now, held.id)?, &sealed)?;
		match fs::remove_file(self.file(Dir::Inflight, held.release_at, held.id)?) {
			Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
			_ => {}
		}
		sync_dir(&self.dir(Dir::Inflight))
	}

	/// Forget the records of submissions released more than
	/// [`RELEASED_KEPT_SECS`] ago.
	pub fn prune(&self, now: u64) -> std::io::Result<()> {
		for (at, id) in self.names(Dir::Released)? {
			if now.saturating_sub(at) > RELEASED_KEPT_SECS {
				let _ = fs::remove_file(self.file(Dir::Released, at, id)?);
			}
		}
		Ok(())
	}
}
