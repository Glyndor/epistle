//! Configuration for the public MTA-STS policy.

use std::path::PathBuf;

use serde::Deserialize;

/// Public policy settings shared by the writer and DNS record generator.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MtaSts {
	/// Directory for `mta-sts.txt`. Unset disables writing at startup.
	pub policy_dir: Option<PathBuf>,
	/// Policy enforcement mode, defaulting to `testing`.
	pub mode: MtaStsMode,
	/// Policy cache lifetime in seconds, defaulting to one week.
	pub max_age: u64,
}

impl Default for MtaSts {
	fn default() -> Self {
		Self {
			policy_dir: None,
			mode: MtaStsMode::Testing,
			max_age: 604800,
		}
	}
}

/// Allowed modes for the published policy.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MtaStsMode {
	/// Collect reports without requiring compliant delivery.
	#[default]
	Testing,
	/// Require compliant delivery.
	Enforce,
	/// Disable MTA-STS enforcement.
	None,
}

impl MtaStsMode {
	pub(crate) fn as_str(self) -> &'static str {
		match self {
			Self::Testing => "testing",
			Self::Enforce => "enforce",
			Self::None => "none",
		}
	}
}
