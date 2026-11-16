//! The password and hashing settings of `[auth]`: what the loader enforces,
//! and what it puts in force once a configuration is accepted.
//!
//! Every value has a bound on the weak side, written next to the value in
//! `docs/configuration.md`: the password length floors in
//! [`crate::password::limits`], the OWASP argon2id minimum in
//! [`crate::smtp::auth::cost`] and the OWASP PBKDF2 minimum in
//! [`crate::smtp::scram::iterations`]. A value below one of them is a load
//! error naming the key, never a silent clamp.

use super::{Auth, Config, ConfigError};
use crate::password::limits::Limits;
use crate::smtp::auth::cost::Argon2Cost;

impl Auth {
	/// The password length limits: the configured ones, or 12 and 64.
	pub fn password_limits(&self) -> Limits {
		let default = Limits::default();
		Limits {
			min: self.min_password_length.unwrap_or(default.min),
			max: self.max_password_length.unwrap_or(default.max),
		}
	}

	/// The argon2id cost of a new password hash.
	pub fn argon2_cost(&self) -> Argon2Cost {
		let default = Argon2Cost::default();
		Argon2Cost {
			memory_kib: self.argon2_memory_kib.unwrap_or(default.memory_kib),
			iterations: self.argon2_iterations.unwrap_or(default.iterations),
			parallelism: self.argon2_parallelism.unwrap_or(default.parallelism),
		}
	}

	/// The PBKDF2 iteration count of a new SCRAM verifier.
	pub fn scram_iteration_count(&self) -> u32 {
		self.scram_iterations
			.unwrap_or(crate::smtp::scram::SCRAM_ITERATIONS)
	}

	/// Refuse a setting below its floor or above its ceiling, and a
	/// forbidden-passwords file that cannot be read.
	pub fn validate(&self) -> Result<(), String> {
		self.password_limits().validate()?;
		self.argon2_cost().validate()?;
		crate::smtp::scram::iterations::validate(self.scram_iteration_count())?;
		if let Some(path) = &self.forbidden_passwords_file {
			crate::password::forbidden::load(path).map_err(|error| {
				format!(
					"[auth] forbidden_passwords_file {}: cannot read it: {error}",
					path.display()
				)
			})?;
		}
		Ok(())
	}
}

impl Config {
	pub(super) fn validate_auth(&self) -> Result<(), ConfigError> {
		self.auth.validate().map_err(ConfigError::Invalid)
	}

	/// Put the process-wide settings of an accepted configuration in force:
	/// password length limits, the operator's forbidden list, the argon2id
	/// cost and the SCRAM iteration count. They are process-wide because the
	/// password policy and the hashes are used by every command and listener,
	/// none of which carries the configuration down to them.
	pub(crate) fn install_process_settings(&self) {
		crate::password::limits::install(self.auth.password_limits());
		let list = self
			.auth
			.forbidden_passwords_file
			.as_deref()
			.and_then(|path| crate::password::forbidden::load(path).ok());
		crate::password::forbidden::install(list);
		crate::smtp::auth::cost::install(self.auth.argon2_cost());
		crate::smtp::scram::iterations::install(self.auth.scram_iteration_count());
	}
}

#[cfg(test)]
mod tests;
