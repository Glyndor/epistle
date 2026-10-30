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
mod tests;
