//! What the operator asks of the warm-up, in `<data_dir>/warmup.json`.
//!
//! `epistle warmup …` is the only writer: whether the warm-up is on,
//! whether its schedule is paused, and the last order given for each group
//! (set a cap, skip ahead one step, start over). Orders carry a sequence
//! number; the server applies each one once, in order, and records the
//! last one applied in its state, so an order survives a restart that
//! happens before the server has read it and is never applied twice.
//!
//! A server with no such file has the warm-up off, which is what every
//! install that predates it gets. A file that cannot be trusted or read is
//! taken as the warm-up on and unpaused with no orders: the reading that
//! lets the least mail through (see [`Settings::distrusted`]).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::Group;
use super::policy::MAX_CAP;
use super::state::{ReadError, read_private};

/// The settings file under the data directory.
pub const SETTINGS_FILE: &str = "warmup.json";
/// The largest settings file read back.
pub const MAX_SETTINGS_BYTES: u64 = 64 * 1024;

/// One order to one group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
	/// Set the cap. Higher than the current one, it is a raise on trial.
	Set {
		/// Recipients a day.
		cap: u32,
	},
	/// Skip ahead one growth step, on trial like a raise.
	Next,
	/// Start the group over at its starting cap.
	Reset,
	/// Start the group at a stage derived from the address's age and
	/// volume (see [`super::stages`]): the cap is set as is, not on trial,
	/// unless the group's cap is higher or lifted by the time the server
	/// reads the order, which it keeps. `None` is no cap.
	Start {
		/// Recipients a day, or none.
		cap: Option<u32>,
	},
	/// [`Action::Start`] that lowers a higher or lifted cap too
	/// (`warmup start --force`).
	Force {
		/// Recipients a day, or none.
		cap: Option<u32>,
	},
}

/// An order with its place in the sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
	/// Its place in the sequence, from one.
	pub seq: u64,
	/// The group it is for.
	pub group: Group,
	/// What it asks.
	pub action: Action,
}

/// The operator's settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
	/// Whether caps apply at all.
	#[serde(default)]
	pub enabled: bool,
	/// Caps apply but do not move by themselves.
	#[serde(default)]
	pub paused: bool,
	/// The last order for each group, at most one per group.
	#[serde(default)]
	pub orders: Vec<Order>,
}

impl Settings {
	/// The settings that replace a file that cannot be trusted.
	pub fn distrusted() -> Self {
		Settings {
			enabled: true,
			paused: false,
			orders: Vec::new(),
		}
	}

	/// Check what a file may say: one order per group, caps in range.
	pub fn validate(&self) -> Result<(), String> {
		let mut groups = std::collections::BTreeSet::new();
		for order in &self.orders {
			if !groups.insert(order.group) {
				return Err(format!("more than one order for {}", order.group));
			}
			let cap = match order.action {
				Action::Set { cap }
				| Action::Start { cap: Some(cap) }
				| Action::Force { cap: Some(cap) } => Some(cap),
				_ => None,
			};
			if let Some(cap) = cap
				&& !(1..=MAX_CAP).contains(&cap)
			{
				return Err(format!("cap {cap} is not between 1 and {MAX_CAP}"));
			}
			if order.seq == 0 {
				return Err("an order's sequence starts at 1".into());
			}
		}
		Ok(())
	}

	/// Replace the order for `group` with `action`, after every order so far.
	pub fn order(&mut self, group: Group, action: Action) -> Order {
		let seq = self.last_seq().saturating_add(1);
		self.orders.retain(|order| order.group != group);
		let order = Order { seq, group, action };
		self.orders.push(order);
		order
	}

	/// The highest sequence number given.
	pub fn last_seq(&self) -> u64 {
		self.orders.iter().map(|order| order.seq).max().unwrap_or(0)
	}

	/// Parse and check the text of a settings file.
	pub fn parse(text: &str) -> Result<Self, String> {
		let settings: Settings = serde_json::from_str(text).map_err(|error| error.to_string())?;
		settings.validate()?;
		Ok(settings)
	}
}

/// The settings file under `data_dir`.
pub fn path(data_dir: &Path) -> PathBuf {
	data_dir.join(SETTINGS_FILE)
}

/// Read the settings under `data_dir`; `None` when there is no file.
pub fn load(data_dir: &Path) -> Result<Option<Settings>, ReadError> {
	let file = path(data_dir);
	let Some(bytes) = read_private(&file, MAX_SETTINGS_BYTES)? else {
		return Ok(None);
	};
	let shown = file.display().to_string();
	let text = String::from_utf8(bytes)
		.map_err(|_| ReadError::Corrupt(shown.clone(), "not UTF-8".into()))?;
	Settings::parse(&text)
		.map(Some)
		.map_err(|error| ReadError::Corrupt(shown, error))
}

/// Write `settings` under `data_dir`, replacing the file atomically at
/// mode `0600`.
pub fn save(data_dir: &Path, settings: &Settings) -> std::io::Result<()> {
	let bytes = serde_json::to_vec_pretty(settings).map_err(std::io::Error::other)?;
	crate::storage::write_secret(&path(data_dir), &bytes)
}

#[cfg(test)]
mod tests;
