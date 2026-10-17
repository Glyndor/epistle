//! Changing a script by its id, as JMAP does: the id is what a client holds,
//! and the name it had a moment ago may already be someone else's.
//!
//! Each call resolves the id and makes its change under the same lock, so
//! the script it changes is the one the id named.

use super::{ScriptInfo, ScriptStore, StoreError, Txn};

impl Txn {
	/// The name of the script with this id.
	fn name_of(&self, id: &str) -> Option<String> {
		self.index
			.scripts
			.iter()
			.find(|(_, entry)| entry.id == id)
			.map(|(name, _)| name.clone())
	}

	/// The script called `name`, as listed.
	fn info(&self, name: &str, active: Option<&str>) -> Option<ScriptInfo> {
		self.index.scripts.get(name).map(|entry| ScriptInfo {
			name: name.to_string(),
			active: active == Some(name),
			id: entry.id.clone(),
			rev: entry.rev,
		})
	}
}

impl ScriptStore {
	/// Store a new script. A script of that name is [`StoreError::AlreadyExists`],
	/// never overwritten, however many callers race for the name.
	pub fn create(&self, name: &str, content: &str) -> Result<ScriptInfo, StoreError> {
		Self::validate(content)?;
		let mut txn = self.write_txn()?;
		let outcome = self.write_in(&mut txn, name, content, true);
		let created = txn.info(name, self.active_name().as_deref());
		txn.finish(outcome)?;
		created.ok_or(StoreError::Io)
	}

	/// Change the script `id`: give it `name`, replace its content, or both.
	/// The new name must be free and the new content must pass the same check
	/// as any other. Nothing changes if either is refused.
	pub fn update(
		&self,
		id: &str,
		name: Option<&str>,
		content: Option<&str>,
	) -> Result<ScriptInfo, StoreError> {
		if let Some(content) = content {
			Self::validate(content)?;
		}
		let mut txn = self.write_txn()?;
		let Some(mut current) = txn.name_of(id) else {
			return Err(StoreError::NoSuchScript);
		};
		let mut outcome = Ok(());
		if let Some(new) = name.filter(|new| *new != current) {
			outcome = self.rename_in(&mut txn, &current, new);
			if outcome.is_ok() {
				current = new.to_string();
			}
		}
		if outcome.is_ok()
			&& let Some(content) = content
		{
			outcome = self.write_in(&mut txn, &current, content, false);
		}
		let updated = txn.info(&current, self.active_name().as_deref());
		txn.finish(outcome)?;
		updated.ok_or(StoreError::Io)
	}

	/// Delete the script `id`, unless it is the active one.
	pub fn destroy(&self, id: &str) -> Result<(), StoreError> {
		let mut txn = self.write_txn()?;
		let outcome = match txn.name_of(id) {
			Some(name) => self.remove_in(&mut txn, &name),
			None => Err(StoreError::NoSuchScript),
		};
		txn.finish(outcome)
	}
}
