//! Filesystem ownership inventory, including upload-only and legacy storage.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use super::{Hooks, TEMP_SUFFIX, Totals};
use crate::storage::{BlobAccount, EnvelopeKind, KeyOwner, MessageCrypto, envelope_kind};

/// The owners present on disk and the shared-pool payloads assigned to each.
/// The caller must hold the store lease from discovery through the last rewrite.
/// Mailbox files are collected per account, rather than all held in memory.
pub struct Inventory {
	data_dir: PathBuf,
	owners: BTreeSet<String>,
	shared: BTreeMap<String, Vec<PathBuf>>,
}

impl Inventory {
	/// Enumerate mailbox partitions, blob partitions and both legacy layouts.
	///
	/// # Errors
	/// Propagates directory/read errors and refuses encrypted shared blobs whose
	/// owner cannot be established, before any account is rewritten.
	pub fn load(data_dir: &Path) -> std::io::Result<Self> {
		let mut inventory = Self {
			data_dir: data_dir.to_path_buf(),
			owners: BTreeSet::new(),
			shared: BTreeMap::new(),
		};
		for root in ["accounts", "blobs/accounts"] {
			for entry in entries(&data_dir.join(root))? {
				if entry.file_type()?.is_dir()
					&& let Some(name) = entry.file_name().to_str()
					&& BlobAccount::new(name).is_some()
				{
					inventory.owners.insert(name.to_owned());
				}
			}
		}
		for path in shared_paths(data_dir)? {
			let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
				continue;
			};
			let payload = name
				.strip_prefix('.')
				.and_then(|name| name.strip_suffix(TEMP_SUFFIX))
				.unwrap_or(name);
			let Ok(id) = uuid::Uuid::parse_str(payload) else {
				continue;
			};
			if id.to_string() != payload {
				continue;
			}
			if let Some(owner) = shared_owner(data_dir, &path, id)? {
				inventory.owners.insert(owner.clone());
				inventory.shared.entry(owner).or_default().push(path);
			}
		}
		Ok(inventory)
	}

	/// Every owner in deterministic order, even without a mailbox directory.
	pub fn accounts(&self) -> impl Iterator<Item = &String> {
		self.owners.iter()
	}

	/// Rewrite an owner's mailbox, blob partition and assigned shared payloads.
	///
	/// # Errors
	/// Refuses invalid names and propagates traversal, authentication and write
	/// failures. The existing crash-safe file replacement is used for every copy.
	pub fn rekey_account(
		&self,
		crypto: &MessageCrypto,
		account: &str,
		target: &KeyOwner,
		dry_run: bool,
		hooks: &mut dyn Hooks,
	) -> std::io::Result<Totals> {
		if BlobAccount::new(account).is_none() {
			return Err(std::io::Error::other("invalid account name"));
		}
		let mut files = Vec::new();
		for root in super::roots(&self.data_dir, account) {
			super::collect(&root, &mut files)?;
		}
		if let Some(shared) = self.shared.get(account) {
			files.extend(shared.iter().cloned());
		}
		files.sort();
		files.dedup();
		super::rekey_paths(crypto, files, target, dry_run, hooks)
	}
}

fn entries(path: &Path) -> std::io::Result<Vec<std::fs::DirEntry>> {
	match std::fs::read_dir(path) {
		Ok(entries) => entries.collect(),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
		Err(error) => Err(error),
	}
}

fn shard(name: &OsStr) -> bool {
	name.to_str().is_some_and(|name| {
		name.len() == 2
			&& name
				.bytes()
				.all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
	})
}

/// Visit only the flat and two-shard layouts, never following links or the
/// account partition tree. Keep both physical copies when one shadows another.
fn shared_paths(data_dir: &Path) -> std::io::Result<Vec<PathBuf>> {
	let mut files = Vec::new();
	for entry in entries(&data_dir.join("blobs"))? {
		let kind = entry.file_type()?;
		if kind.is_file() {
			files.push(entry.path());
		} else if kind.is_dir() && shard(&entry.file_name()) {
			for inner in entries(&entry.path())? {
				if inner.file_type()?.is_dir() && shard(&inner.file_name()) {
					for payload in entries(&inner.path())? {
						if payload.file_type()?.is_file() {
							files.push(payload.path());
						}
					}
				}
			}
		}
	}
	files.sort();
	Ok(files)
}

fn shared_owner(data_dir: &Path, path: &Path, id: uuid::Uuid) -> std::io::Result<Option<String>> {
	// Older backfills can put the owner in the other supported layout. Prefer
	// the sidecar beside this physical copy, then use the reader's fallback.
	let adjacent = path.with_file_name(format!("{id}.owner"));
	let fallback = crate::api::jmap::blob_path::read_path(data_dir, id, ".owner");
	for candidate in [adjacent, fallback] {
		match std::fs::read_to_string(candidate) {
			Ok(owner) if BlobAccount::new(&owner).is_some() => return Ok(Some(owner)),
			Ok(_) => return Err(owner_error(path)),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => return Err(error),
		}
	}
	if envelope_kind(&std::fs::read(path)?) == EnvelopeKind::Plain {
		return Ok(None);
	}
	Err(owner_error(path))
}

fn owner_error(path: &Path) -> std::io::Error {
	std::io::Error::new(
		std::io::ErrorKind::InvalidData,
		format!(
			"cannot resolve owner of legacy shared blob {}; provide a valid .owner sidecar before migration",
			path.display(),
		),
	)
}
