//! `epistle account set <name> --default-class <class>`.

use std::path::Path;
use std::process::ExitCode;

use crate::evidence::MailClass;

/// Bind `class` (or clear the binding with `none`) as the default class of
/// the account `name`.
pub(super) fn set(config_path: &Path, name: &str, class: &str) -> ExitCode {
	let class = match class {
		"none" => None,
		other => match crate::evidence::class::parse_arg(other) {
			Ok(class) => Some(class),
			Err(error) => return super::exit::refused(format_args!("account {name}: {error}")),
		},
	};
	if let Err(code) = super::account::prepare(config_path, name) {
		return code;
	}
	let data_dir = match crate::config::Config::load(config_path) {
		Ok(config) => config.data_dir,
		Err(error) => {
			super::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	match bind(&data_dir, name, class) {
		Ok(()) => {
			match class {
				Some(class) => println!("default class set to {class}"),
				None => println!("default class cleared"),
			}
			ExitCode::SUCCESS
		}
		Err(error) => {
			super::style::error(format_args!("account {name}: {error}"));
			ExitCode::FAILURE
		}
	}
}

/// Write the binding of `name` under `data_dir`.
pub(crate) fn bind(data_dir: &Path, name: &str, class: Option<MailClass>) -> std::io::Result<()> {
	crate::evidence::bindings::update(data_dir, |bindings| {
		let key = name.to_ascii_lowercase();
		match class {
			Some(class) => bindings.accounts.insert(key, class),
			None => bindings.accounts.remove(&key),
		};
	})
}

#[cfg(test)]
#[path = "account_class_tests.rs"]
mod tests;
