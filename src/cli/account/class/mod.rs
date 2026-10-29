//! `epistle account set <name> --default-class <class>`.

use std::path::Path;
use std::process::ExitCode;

use crate::evidence::MailClass;

/// Bind `class` (or clear the binding with `none`) as the default class of
/// the account `name`.
pub(super) fn set(
	config_path: &Path,
	name: &str,
	class: &str,
	json: bool,
	out: &mut dyn std::io::Write,
) -> ExitCode {
	let class = match class {
		"none" => None,
		other => match crate::evidence::class::parse_arg(other) {
			Ok(class) => Some(class),
			Err(error) => {
				return crate::cli::exit::refused(format_args!("account {name}: {error}"));
			}
		},
	};
	if let Err(code) = super::prepare(config_path, name) {
		return code;
	}
	let data_dir = match crate::config::Config::load(config_path) {
		Ok(config) => config.data_dir,
		Err(error) => {
			crate::cli::style::error(error);
			return ExitCode::FAILURE;
		}
	};
	match bind(&data_dir, name, class) {
		Ok(()) => {
			let mut report = crate::cli::json_out::Report::new(out, json);
			report.line(match class {
				Some(class) => format!("default class set to {class}"),
				None => "default class cleared".to_string(),
			});
			let fields = serde_json::json!({
				"account": name,
				"default_class": class.map(|class| class.to_string()),
			});
			report.change("set", true, fields, None)
		}
		Err(error) => {
			crate::cli::style::error(format_args!("account {name}: {error}"));
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
mod tests;
