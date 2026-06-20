//! Privilege-drop configuration.
//!
//! Binding the mail ports (25, 465, 587, 993, 143, 995, 80) requires root.
//! Once they are bound the server should run as an unprivileged account so a
//! later compromise cannot act as root. `[privileges]` names that account.

use serde::Deserialize;

/// User (and optional group) to drop to after privileged ports are bound.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Privileges {
	/// Unprivileged user name to switch to. Must exist on the host.
	pub user: String,
	/// Group name to switch to. Absent uses the user's primary group.
	pub group: Option<String>,
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_user_only() {
		let privileges: Privileges = toml::from_str(r#"user = "glyndor-mail""#).expect("parse");
		assert_eq!(privileges.user, "glyndor-mail");
		assert!(privileges.group.is_none());
	}

	#[test]
	fn parses_user_and_group() {
		let privileges: Privileges =
			toml::from_str("user = \"mail\"\ngroup = \"mail\"").expect("parse");
		assert_eq!(privileges.group.as_deref(), Some("mail"));
	}

	#[test]
	fn rejects_unknown_keys() {
		assert!(toml::from_str::<Privileges>("user = \"mail\"\nuid = 1000").is_err());
	}

	#[test]
	fn requires_user() {
		assert!(toml::from_str::<Privileges>(r#"group = "mail""#).is_err());
	}
}
