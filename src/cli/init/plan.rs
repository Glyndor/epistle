//! The plan the assistant prints before touching anything, and the
//! report the apply phase prints afterwards.
//!
//! The plan is a list of steps the operator can read top-to-bottom and
//! know exactly what is about to happen on their machine. The DNS step
//! is present even though this part of `init` does not implement
//! publishing: the seam lets the next part drop in without changing the
//! shape of what the operator sees.

use std::fmt;
use std::path::PathBuf;

/// One step the operator sees in the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanStep {
	/// A DKIM Ed25519 key file will be created at the given path, or
	/// reused if it already exists.
	DkimEd25519 {
		/// Path the key file will live at.
		path: PathBuf,
		/// `true` when the file already exists and will not be touched.
		reused: bool,
	},
	/// A DKIM RSA key file will be created at the given path, or reused
	/// if it already exists.
	DkimRsa {
		/// Path the key file will live at.
		path: PathBuf,
		/// `true` when the file already exists and will not be touched.
		reused: bool,
		/// `true` when `openssl` is on `PATH` and the key can be generated.
		/// `false` leaves the step out of the apply phase and reports
		/// the gap on stderr.
		openssl_available: bool,
	},
	/// The at-rest storage key file.
	Storage {
		/// Path the key file will live at.
		path: PathBuf,
		/// `true` when the file already exists and will not be touched.
		reused: bool,
	},
	/// The OAuth ES256 signing key file.
	OAuthPrivate {
		/// Path the key file will live at.
		path: PathBuf,
		/// `true` when the file already exists and will not be touched.
		reused: bool,
	},
	/// The OAuth ES256 public key file.
	OAuthPublic {
		/// Path the key file will live at.
		path: PathBuf,
		/// `true` when the file already exists and will not be touched.
		reused: bool,
	},
	/// The configuration file the operator chose.
	Config {
		/// Path the config will be written to.
		path: PathBuf,
		/// `true` when the existing config matches the desired one byte
		/// for byte and will not be touched.
		identical: bool,
		/// `true` when the config file already exists on disk and the
		/// merge will rewrite it (the operator sees `update` instead of
		/// `write`).
		file_exists: bool,
		/// Number of top-level keys `init` manages in the desired
		/// config. Surfaced in the plan so the operator can see how
		/// much the rewrite will touch.
		count: usize,
		/// Whether unknown top-level keys will be preserved by using
		/// `toml_edit`. When `false`, the merge uses plain
		/// `toml::Value` and may lose comments.
		preserves_comments: bool,
	},
	/// DNS publishing for automatic mode. This build leaves the step
	/// un-implemented; the seam is here so the next part of `init` can
	/// drop in.
	Dns {
		/// Provider id the operator chose.
		provider: String,
		/// Zone the operator chose.
		zone: String,
	},
	/// The parent directory of `config_path` will be created during the
	/// apply phase. Listed only when the directory is absent; existing
	/// directories are left untouched.
	ConfigDir {
		/// Parent directory that will be created with mode `0750`.
		path: PathBuf,
	},
	/// A self-signed certificate pair `cert.pem` + `key.pem` under
	/// `data_dir/keys/`. `init` generates the pair so the listener
	/// configuration validates out of the box; the operator replaces
	/// it with an ACME-issued or operator-supplied PEM later. The
	/// two halves are inspected independently, so a missing `cert.pem`
	/// with a surviving `key.pem` is rebuilt from the existing key
	/// without regenerating it; a missing `key.pem` with a surviving
	/// `cert.pem` is refused with a recoverable diagnostic (the plan
	/// surfaces the refusal).
	SelfSignedCert {
		/// Path the certificate PEM will live at.
		cert_path: PathBuf,
		/// Path the private key PEM will live at.
		key_path: PathBuf,
		/// `true` when both files already exist and will not be touched.
		reused: bool,
		/// `true` when `key.pem` already exists and will not be touched
		/// even when `cert.pem` is regenerated from it.
		key_reused: bool,
	},
	/// `data_dir` itself. Listed only when `init` will create it
	/// (mode `0700`); an existing directory is left untouched and
	/// does not appear in the plan because no step is taken.
	DataDir {
		/// Path the data directory will live at.
		path: PathBuf,
	},
}

impl fmt::Display for PlanStep {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			PlanStep::DkimEd25519 { path, reused } => {
				let verb = if *reused { "reuse" } else { "generate" };
				write!(f, "dkim ed25519 key: {verb} {}", path.display())
			}
			PlanStep::DkimRsa {
				path,
				reused,
				openssl_available,
			} => {
				if *reused {
					write!(f, "dkim rsa key: reuse {}", path.display())
				} else if *openssl_available {
					write!(f, "dkim rsa key: generate {}", path.display())
				} else {
					write!(
						f,
						"dkim rsa key: skip (openssl not on PATH); run \"epistle dkim-keygen --rsa\" to create {}",
						path.display()
					)
				}
			}
			PlanStep::Storage { path, reused } => {
				let verb = if *reused { "reuse" } else { "generate" };
				write!(f, "storage key: {verb} {}", path.display())
			}
			PlanStep::OAuthPrivate { path, reused } => {
				let verb = if *reused { "reuse" } else { "generate" };
				write!(f, "oauth private key: {verb} {}", path.display())
			}
			PlanStep::OAuthPublic { path, reused } => {
				let verb = if *reused { "reuse" } else { "generate" };
				write!(f, "oauth public key: {verb} {}", path.display())
			}
			PlanStep::Config {
				path,
				identical,
				file_exists,
				count,
				preserves_comments,
			} => {
				if *identical {
					write!(f, "config: identical, not touched ({})", path.display())
				} else {
					let verb = if *file_exists { "update" } else { "write" };
					let merge = if *preserves_comments {
						"preserving comments"
					} else {
						"merging without comments"
					};
					write!(
						f,
						"config: {verb} {} ({count} keys, {merge})",
						path.display()
					)
				}
			}
			PlanStep::Dns { provider, zone } => write!(
				f,
				"dns: publish records through {provider} for zone {zone} (not implemented in this build)"
			),
			PlanStep::ConfigDir { path } => {
				write!(f, "config dir: create {} (mode 0750)", path.display())
			}
			PlanStep::SelfSignedCert {
				cert_path,
				key_path,
				reused,
				key_reused,
			} => {
				if *reused {
					write!(
						f,
						"self-signed cert: reuse {} (and {})",
						cert_path.display(),
						key_path.display()
					)
				} else if *key_reused {
					write!(
						f,
						"self-signed cert: reuse {} and generate {} from it",
						key_path.display(),
						cert_path.display()
					)
				} else {
					write!(
						f,
						"self-signed cert: generate {} (and {})",
						cert_path.display(),
						key_path.display()
					)
				}
			}
			PlanStep::DataDir { path } => {
				write!(f, "data dir: create {} (mode 0700)", path.display())
			}
		}
	}
}

/// The full plan: every step, in the order the apply phase will run them.
#[derive(Debug, Clone)]
pub struct Plan {
	/// Steps in execution order.
	pub steps: Vec<PlanStep>,
}

impl Plan {
	/// Print the plan to `out` as a numbered list, one step per line.
	/// Empty plans print nothing.
	pub fn write_to(&self, out: &mut impl fmt::Write) -> fmt::Result {
		for (i, step) in self.steps.iter().enumerate() {
			writeln!(out, "  {}. {step}", i + 1)?;
		}
		Ok(())
	}
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
