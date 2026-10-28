//! Values an older release let an operator write that a newer one refuses.
//!
//! A configuration that exists must not stop the server from starting after
//! an upgrade, because then the commands that would repair it (`stack
//! rollback`, `backup`, `restore`, `status`) fail on the same file. Each value
//! here is ignored when the file loads, with a line naming the value in the
//! file, what is done with it and what to do, which the log, `epistle
//! config-check` and `epistle status` print. `epistle init` and the commands
//! that write the file still refuse the same values.

use super::Config;
use super::{non_global_ipv4_reason, non_global_ipv6_reason};

/// The value as it is shown in a line: cut to a fixed length and with control
/// characters escaped.
fn shown(value: &str) -> String {
	format!("{:?}", crate::util::address_reason::shorten(value))
}

impl Config {
	/// Ignore a `public_ipv4` / `public_ipv6` that is not a global unicast
	/// address, and a `list_id` the list headers cannot carry, saying so.
	/// Without the address the server resolves the host name as it does when
	/// the field is not set; without the `list_id` the alias is a plain alias
	/// with no list headers.
	pub(super) fn ignore_legacy_values(&mut self) -> Vec<String> {
		let mut notes = Vec::new();
		if let Some(ip) = self.public_ipv4
			&& let Some(why) = non_global_ipv4_reason(ip)
		{
			notes.push(ignored_address("public_ipv4", ip, why));
			self.public_ipv4 = None;
		}
		if let Some(ip) = self.public_ipv6
			&& let Some(why) = non_global_ipv6_reason(ip)
		{
			notes.push(ignored_address("public_ipv6", ip, why));
			self.public_ipv6 = None;
		}
		for alias in &mut self.alias {
			if let Some(list_id) = &alias.list_id
				&& !super::usable_list_id(list_id)
			{
				notes.push(format!(
					"alias {}: list_id {} in the file cannot go between the angle brackets of a \
					 List-Id field (it needs to be a dot-atom such as \"team.example.org\"), so \
					 it is ignored and the alias sends no list headers. Write a valid list_id or \
					 remove the line",
					shown(&alias.address),
					shown(list_id),
				));
				alias.list_id = None;
			}
		}
		notes
	}
}

fn ignored_address<T: std::fmt::Display>(field: &str, ip: T, why: &str) -> String {
	format!(
		"{field} \"{ip}\" in the file is {why}, so it is ignored and the server acts as if \
		 {field} were not set. Write a global unicast address there, or remove the line"
	)
}

#[cfg(test)]
mod tests;
