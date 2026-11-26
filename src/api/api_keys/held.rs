//! A key that 0.14.0 has no scope for, written so that 0.14.0 refuses it.
//!
//! After a rollback 0.14.0 reads the file 0.15.0 wrote. It refuses a file with a
//! scope name it does not know and reads an empty `scopes` as every scope, so a
//! key that holds only scopes 0.14.0 never had (`ban`) cannot be written with
//! nothing and cannot be written with a name that gives it a reach it did not
//! have. It is written with a placeholder scope and with an `ip_cidr` that
//! 0.14.0 checks and no address passes, which 0.14.0 loads and cannot use. The
//! real `ip_cidr` is kept in a table 0.14.0 ignores, and 0.15.0 puts it back
//! when it reads the file. If 0.14.0 rewrote the file in between, the table is
//! gone and the key stays refused until it is made again.

use serde::{Deserialize, Serialize};

use super::{ApiKey, ApiKeyFile};

/// The `ip_cidr` of a held key. It is not a network, so neither 0.14.0 nor
/// 0.15.0 admits a request against it.
pub const HELD: &str = "held-until-0.15";

/// What the file holds besides the keys.
#[derive(Serialize, Deserialize)]
pub(super) struct FileWire {
	#[serde(default)]
	keys: Vec<ApiKey>,
	/// The `ip_cidr` each held key had. 0.14.0 ignores this table.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	rollback_hold: Vec<Hold>,
}

#[derive(Serialize, Deserialize)]
struct Hold {
	label: String,
	#[serde(default, skip_serializing_if = "Option::is_none")]
	ip_cidr: Option<String>,
}

impl From<ApiKeyFile> for FileWire {
	fn from(file: ApiKeyFile) -> Self {
		let mut rollback_hold = Vec::new();
		let keys = file
			.keys
			.into_iter()
			.map(|mut key| {
				if key.unusable_in_v014() {
					rollback_hold.push(Hold {
						label: key.label.clone(),
						ip_cidr: key.ip_cidr.take(),
					});
					key.ip_cidr = Some(HELD.to_string());
				}
				key
			})
			.collect();
		FileWire {
			keys,
			rollback_hold,
		}
	}
}

impl From<FileWire> for ApiKeyFile {
	fn from(wire: FileWire) -> Self {
		let FileWire {
			mut keys,
			rollback_hold,
		} = wire;
		for key in &mut keys {
			if key.ip_cidr.as_deref() != Some(HELD) {
				continue;
			}
			if let Some(hold) = rollback_hold.iter().find(|hold| hold.label == key.label) {
				key.ip_cidr = hold.ip_cidr.clone();
			}
		}
		ApiKeyFile { keys }
	}
}
