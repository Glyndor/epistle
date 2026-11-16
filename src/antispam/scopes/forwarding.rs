//! The forwarding settings a scope can override: where forwarded copies may
//! go and how many one account may send in a minute. The most specific
//! scope in reach wins, as for the numbers: every scope is written by the
//! operator, so a narrower one may relax what a wider one set.

use super::{Scopes, Target};
use crate::config::ForwardPolicy;

/// What one scope overrides.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct ForwardOverrides {
	pub(super) policy: Option<ForwardPolicy>,
	pub(super) per_min: Option<u32>,
}

impl ForwardOverrides {
	pub(super) fn is_empty(&self) -> bool {
		*self == Self::default()
	}
}

/// The forwarding settings in force for one target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardSettings {
	/// Where a forwarded copy may go.
	pub policy: ForwardPolicy,
	/// Copies per minute one account may forward, from a scope; `None`
	/// leaves it to the server-wide limit.
	pub per_min: Option<u32>,
}

impl Scopes {
	/// The forwarding settings for mail delivered to `target`, starting from
	/// the server's `policy` and applying the tenant, the domain and the
	/// account in turn.
	pub fn forward_settings(&self, target: &Target, policy: ForwardPolicy) -> ForwardSettings {
		self.layers(target).fold(
			ForwardSettings {
				policy,
				per_min: None,
			},
			|settings, layer| ForwardSettings {
				policy: layer.forward.policy.unwrap_or(settings.policy),
				per_min: layer.forward.per_min.or(settings.per_min),
			},
		)
	}
}
