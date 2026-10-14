//! Per-tenant submission limits editable through `epistle limits
//! --tenant ...`. Mirrors the shape of [`super::limits_keys`] so the
//! CLI subcommand and dispatch read the same way.

use clap::ValueEnum;

/// Numeric per-tenant settings accepted by `epistle limits --tenant`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TenantKey {
	/// Aggregate submission rate ceiling for the tenant (per minute,
	/// summed across every authenticated sender in every owned
	/// domain).
	SubmissionRate,
}

impl TenantKey {
	pub(super) const ALL: [Self; 1] = [Self::SubmissionRate];

	pub(super) fn name(self) -> &'static str {
		match self {
			Self::SubmissionRate => "submission-rate",
		}
	}

	pub(super) fn field(self) -> &'static str {
		match self {
			Self::SubmissionRate => "submission_rate_limit_per_min",
		}
	}
}