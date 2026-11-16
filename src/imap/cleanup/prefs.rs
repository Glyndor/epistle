//! The account's own retention, `<account>/.cleanup`: one
//! `folder<TAB>days` per line, `folder` being `trash`, `junk`, `rejects` or
//! a folder name. It is a preference inside the operator's limits, never a
//! way past them ([`super::combine`]).

use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::util::path_component::AccountName;

const FILE: &str = ".cleanup";

/// What an account asked for, by [`super::rule_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Prefs {
	days: BTreeMap<String, u64>,
}

impl Prefs {
	/// The preferences of `account`; a missing or unreadable file asks for
	/// nothing.
	pub fn load(data_dir: &Path, account: &str) -> Prefs {
		let text = AccountName::new(account)
			.map_err(io::Error::from)
			.and_then(|name| name.root(data_dir))
			.and_then(|root| root.file(FILE))
			.and_then(std::fs::read_to_string)
			.unwrap_or_default();
		Prefs {
			days: text
				.lines()
				.filter_map(|line| line.split_once('\t'))
				.filter_map(|(folder, days)| {
					Some((super::policy::stored_key(folder), days.trim().parse().ok()?))
				})
				.collect(),
		}
	}

	/// The days the account asked for a folder with these keys, most
	/// specific key first.
	pub fn days_for(&self, keys: &[String]) -> Option<u64> {
		keys.iter().find_map(|key| self.days.get(key).copied())
	}

	/// Record `days` for `folder`, replacing what was there. `0` asks to keep
	/// for ever.
	pub fn set(data_dir: &Path, account: &str, folder: &str, days: u64) -> io::Result<()> {
		let mut prefs = Prefs::load(data_dir, account);
		prefs.days.insert(super::rule_key(folder), days);
		prefs.save(data_dir, account)
	}

	/// Forget what the account asked for `folder`.
	pub fn clear(data_dir: &Path, account: &str, folder: &str) -> io::Result<()> {
		let mut prefs = Prefs::load(data_dir, account);
		prefs.days.remove(&super::rule_key(folder));
		prefs.save(data_dir, account)
	}

	fn save(&self, data_dir: &Path, account: &str) -> io::Result<()> {
		let root = AccountName::new(account)?.root(data_dir)?;
		let path = root.file(FILE)?;
		if self.days.is_empty() {
			return match std::fs::remove_file(&path) {
				Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
				_ => Ok(()),
			};
		}
		let text: String = self
			.days
			.iter()
			.map(|(key, days)| {
				let folder = key
					.split_once(':')
					.map_or(key.as_str(), |(_, folder)| folder);
				format!("{folder}\t{days}\n")
			})
			.collect();
		let staged = root.file(&format!("{FILE}.{}.tmp", uuid::Uuid::now_v7()))?;
		std::fs::write(&staged, text)?;
		std::fs::rename(&staged, &path).inspect_err(|_| {
			let _ = std::fs::remove_file(&staged);
		})
	}
}
