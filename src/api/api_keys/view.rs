//! A key as it is shown: never its secret, never its hash.

use super::{ApiKey, ApiKeySummary};

impl ApiKeySummary {
	/// The summary of `key`.
	pub fn of(key: &ApiKey) -> Self {
		ApiKeySummary {
			label: key.label.clone(),
			expires_at: key.expires_at,
			ip_cidr: key.ip_cidr.clone(),
			scopes: key.scopes.clone(),
			grants: key.grants.clone(),
			domains: key.domains.clone(),
			account: key.account.clone(),
			auto_submitted: key.auto_submitted,
		}
	}

	/// The object `epistle api-key list --json` prints for the key: the
	/// `auto_submitted` field only when it is on, so a key that never set it
	/// keeps the shape it always had.
	pub fn json(&self) -> serde_json::Value {
		let mut object = serde_json::json!({
			"label": self.label,
			"expires_at": self.expires_at,
			"ip_cidr": self.ip_cidr,
			"scopes": super::display_names(&self.scopes, &self.grants),
			"domains": self.domains,
			"account": self.account,
		});
		if self.auto_submitted {
			object["auto_submitted"] = true.into();
		}
		object
	}
}
