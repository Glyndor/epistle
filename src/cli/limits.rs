//! Server-wide numeric limits in the configuration file.

#[path = "limits_values.rs"]
mod values;

#[cfg(test)]
#[path = "limits_tests_values.rs"]
mod tests_values;

#[path = "limits_keys.rs"]
mod keys;
pub use keys::Key;

use crate::config::Config;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

fn change_config(path: &Path, key: Key, value: Option<&str>) -> Result<Option<Config>, String> {
	let value = value
		.map(|input| values::parse_value(input, key.unit(), key.max()))
		.transpose()
		.map_err(|error| format!("{}: {error}", key.name()))?;
	let existing = super::init::read_config(path)
		.map_err(|error| error.to_string())?
		.ok_or_else(|| format!("config file {} does not exist", path.display()))?;
	let mut tree: toml::Table = toml::from_str(&existing.text)
		.map_err(|_| "cannot parse configuration TOML".to_string())?;
	let changed = match value {
		Some(value) => super::init::merge_key(
			&mut tree,
			key.field().into(),
			toml::Value::Integer(value as i64),
		),
		None => tree.remove(key.field()).is_some(),
	};
	if !changed {
		existing.validate(path).map_err(|error| error.to_string())?;
		return Ok(None);
	}
	let candidate = toml::to_string(&tree).map_err(|error| error.to_string())?;
	super::init::write_validated_config(path, &candidate).map_err(|error| error.to_string())?;
	Config::load(path)
		.map(Some)
		.map_err(|error| error.to_string())
}

fn show(config: &Config, out: &mut impl Write) -> std::io::Result<()> {
	for key in Key::ALL {
		let configured = key.value(config);
		let default = configured.is_none() || configured == key.default_value();
		let value = match configured.or(key.default_value()) {
			Some(value) => match key.unit() {
				values::Unit::Size => format!("{value} bytes"),
				values::Unit::Duration => format!("{value} seconds"),
				values::Unit::Count => value.to_string(),
			},
			None if matches!(key, Key::MaxConnectionsPerListener) => "protocol defaults".into(),
			None => "disabled".into(),
		};
		let source = if default { "default" } else { "configured" };
		writeln!(out, "{}\t{value}\t{source}", key.name())?;
	}
	Ok(())
}

#[cfg(test)]
#[path = "limits_tests_config.rs"]
mod tests_config;

/// Operations on the server-wide limits.
#[derive(Debug, clap::Subcommand)]
pub enum Action {
	/// Show effective values and built-in default markers.
	Show,
	/// Save a server-wide limit in the configuration.
	Set {
		/// The limit to configure.
		#[arg(value_enum)]
		key: Key,
		/// Non-negative integer, size (K/M/G/T), or duration (s/m/h/d/w).
		#[arg(allow_hyphen_values = true)]
		value: String,
	},
	/// Remove an override and use the built-in default.
	Unset {
		/// The limit to reset.
		#[arg(value_enum)]
		key: Key,
	},
}

pub(super) fn run(path: &Path, action: Action, out: &mut impl Write) -> ExitCode {
	run_with_restart(
		path,
		action,
		out,
		&mut super::style::stderr(),
		super::stack::run,
	)
}

fn run_with_restart(
	path: &Path,
	action: Action,
	out: &mut impl Write,
	status: &mut impl Write,
	restart: impl FnOnce(&Config, super::stack::StackAction) -> ExitCode,
) -> ExitCode {
	let result = match action {
		Action::Show => {
			let result = Config::load(path)
				.map_err(|error| error.to_string())
				.and_then(|config| show(&config, out).map_err(|error| error.to_string()));
			return match result {
				Ok(()) => ExitCode::SUCCESS,
				Err(error) => {
					let _ = writeln!(status, "cannot show limits: {error}");
					ExitCode::FAILURE
				}
			};
		}
		Action::Set { key, value } => change_config(path, key, Some(&value)),
		Action::Unset { key } => change_config(path, key, None),
	};
	let config = match result {
		Ok(Some(config)) => config,
		Ok(None) => {
			let _ = writeln!(status, "limits unchanged");
			return ExitCode::SUCCESS;
		}
		Err(error) => {
			let _ = writeln!(status, "cannot update limits: {error}");
			return ExitCode::FAILURE;
		}
	};
	let compose = super::init::compose_file_path(&config.data_dir);
	match std::fs::metadata(&compose) {
		Ok(_) => {
			let _ = writeln!(status, "limits saved; restarting mail");
			restart(
				&config,
				super::stack::StackAction::Restart {
					service: Some("mail".into()),
				},
			)
		}
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
			let _ = writeln!(status, "limits saved; server must be restarted");
			ExitCode::SUCCESS
		}
		Err(error) => {
			let _ = writeln!(
				status,
				"limits saved; cannot stat {}: {error}; server must be restarted",
				compose.display()
			);
			ExitCode::FAILURE
		}
	}
}

#[cfg(test)]
#[path = "limits_tests_cli.rs"]
mod tests_cli;
