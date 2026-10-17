//! Changing scripts by id, as JMAP does, and several changes as one step.
//!
//! The id is what a client holds, and the name it had a moment ago may
//! already be someone else's, so a change resolves the id and makes the
//! change under the same lock. [`ScriptStore::transact`] holds that lock
//! across a whole run of changes, and checks the state the caller expects
//! under it, so a request that says "only if nothing changed" is checked
//! where the change is made and not before.

use super::{ScriptInfo, ScriptStore, StoreError, Txn};

impl Txn {
	/// The name of the script with this id.
	pub(super) fn name_of(&self, id: &str) -> Option<String> {
		self.index
			.scripts
			.iter()
			.find(|(_, entry)| entry.id == id)
			.map(|(name, _)| name.clone())
	}

	/// The script called `name`, as listed.
	pub(super) fn info(&self, name: &str, active: Option<&str>) -> Option<ScriptInfo> {
		self.index.scripts.get(name).map(|entry| ScriptInfo {
			name: name.to_string(),
			active: active == Some(name),
			id: entry.id.clone(),
			rev: entry.rev,
		})
	}
}

/// The account's scripts under its lock: what [`ScriptStore::transact`] hands
/// to its closure. Nothing else touches the scripts until it returns.
pub struct Tx<'a> {
	store: &'a ScriptStore,
	txn: Txn,
}

impl Tx<'_> {
	/// The change counter as this run leaves it.
	pub fn state(&self) -> u64 {
		self.txn.index.state + u64::from(self.txn.changed)
	}

	/// The scripts, with their active flag, as they are now.
	pub fn scripts(&self) -> Vec<ScriptInfo> {
		let active = self.store.active_name();
		self.txn
			.index
			.scripts
			.keys()
			.filter_map(|name| self.txn.info(name, active.as_deref()))
			.collect()
	}

	/// The content of the script called `name`.
	pub fn content(&self, name: &str) -> Result<String, StoreError> {
		self.store.get(name)
	}

	/// Store a new script. A script of that name is [`StoreError::AlreadyExists`],
	/// never overwritten.
	pub fn create(&mut self, name: &str, content: &str) -> Result<ScriptInfo, StoreError> {
		ScriptStore::validate(content)?;
		self.store.write_in(&mut self.txn, name, content, true)?;
		let active = self.store.active_name();
		self.txn.info(name, active.as_deref()).ok_or(StoreError::Io)
	}

	/// Change the script `id`: give it `name`, replace its content, or both.
	/// The new name must be free and the new content must pass the same check
	/// as any other. Nothing changes if either is refused.
	pub fn update(
		&mut self,
		id: &str,
		name: Option<&str>,
		content: Option<&str>,
	) -> Result<ScriptInfo, StoreError> {
		if let Some(content) = content {
			ScriptStore::validate(content)?;
		}
		let Some(mut current) = self.txn.name_of(id) else {
			return Err(StoreError::NoSuchScript);
		};
		if let Some(new) = name.filter(|new| *new != current) {
			self.store.rename_in(&mut self.txn, &current, new)?;
			current = new.to_string();
		}
		if let Some(content) = content {
			self.store
				.write_in(&mut self.txn, &current, content, false)?;
		}
		let active = self.store.active_name();
		self.txn
			.info(&current, active.as_deref())
			.ok_or(StoreError::Io)
	}

	/// Delete the script `id`, unless it is the active one.
	pub fn destroy(&mut self, id: &str) -> Result<(), StoreError> {
		let name = self.txn.name_of(id).ok_or(StoreError::NoSuchScript)?;
		self.store.remove_in(&mut self.txn, &name)
	}

	/// Make the script `id` the active one, or none when `None`. From one
	/// script to another the live filter is replaced, never removed.
	pub fn set_active(&mut self, id: Option<&str>) -> Result<(), StoreError> {
		let name = match id {
			Some(id) => Some(self.txn.name_of(id).ok_or(StoreError::NoSuchScript)?),
			None => None,
		};
		self.store.set_active_in(&mut self.txn, name.as_deref())
	}
}

impl ScriptStore {
	/// Run `work` on the account's scripts as one step, under their lock. With
	/// `expected`, nothing runs unless the store is at that state: the check
	/// and the changes are made together, and a caller that lost the race gets
	/// [`StoreError::StateMismatch`] and changes nothing.
	pub fn transact<T>(
		&self,
		expected: Option<u64>,
		work: impl FnOnce(&mut Tx<'_>) -> T,
	) -> Result<T, StoreError> {
		let txn = self.write_txn()?;
		let mut tx = Tx { store: self, txn };
		if expected.is_some_and(|expected| expected != tx.state()) {
			return Err(StoreError::StateMismatch);
		}
		let out = work(&mut tx);
		tx.txn.finish(Ok(()))?;
		Ok(out)
	}

	/// Store a new script. A script of that name is [`StoreError::AlreadyExists`],
	/// never overwritten, however many callers race for the name.
	pub fn create(&self, name: &str, content: &str) -> Result<ScriptInfo, StoreError> {
		self.transact(None, |tx| tx.create(name, content))?
	}

	/// Change the script `id`; see [`Tx::update`].
	pub fn update(
		&self,
		id: &str,
		name: Option<&str>,
		content: Option<&str>,
	) -> Result<ScriptInfo, StoreError> {
		self.transact(None, |tx| tx.update(id, name, content))?
	}

	/// Delete the script `id`, unless it is the active one.
	pub fn destroy(&self, id: &str) -> Result<(), StoreError> {
		self.transact(None, |tx| tx.destroy(id))?
	}

	/// The content of version `rev` of the script `id`, read under the lock
	/// so it is exactly that version: a script rewritten since is gone as
	/// that version, not served as the new one.
	pub fn version_content(&self, id: &str, rev: u64) -> Result<String, StoreError> {
		let Some(txn) = self.read_txn()? else {
			return Err(StoreError::NoSuchScript);
		};
		let name = txn
			.index
			.scripts
			.iter()
			.find(|(_, entry)| entry.id == id && entry.rev == rev)
			.map(|(name, _)| name.clone())
			.ok_or(StoreError::NoSuchScript)?;
		let content = self.get(&name);
		txn.commit()?;
		content
	}
}
