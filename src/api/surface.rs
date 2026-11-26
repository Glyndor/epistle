//! The HTTP surfaces of the API listener: which routes belong to which
//! function, and which of them a listener serves.
//!
//! One listener of kind `api` serves every surface that has no listener of its
//! own, which is what 0.14.0 did, so a configuration from 0.14.0 means what it
//! meant. A listener of kind `jmap`, `scim` or `oauth` serves that surface and
//! nothing else, and `[api] surfaces` narrows what the `api` listener adds to
//! management.

use std::collections::BTreeSet;

use crate::config::{Config, ListenerKind};

/// One function of the HTTP API, served together or on a listener of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Surface {
	/// `/api/v1` and `/healthz`.
	Manage,
	/// JMAP: `/jmap/*` and `/.well-known/jmap`.
	Jmap,
	/// The OAuth grants: `/oauth/*`.
	Oauth,
	/// SCIM 2.0: `/scim/v2`.
	Scim,
}

/// Every surface, in the order they are listed.
const EVERY: [Surface; 4] = [
	Surface::Manage,
	Surface::Jmap,
	Surface::Oauth,
	Surface::Scim,
];

impl Surface {
	/// The name `[api] surfaces` and the commands use.
	pub fn name(self) -> &'static str {
		match self {
			Surface::Manage => "manage",
			Surface::Jmap => "jmap",
			Surface::Oauth => "oauth",
			Surface::Scim => "scim",
		}
	}

	/// The surface a name of `[api] surfaces` stands for. `manage` is not one:
	/// management is always on the `api` listener.
	pub fn optional(name: &str) -> Option<Surface> {
		match name {
			"jmap" => Some(Surface::Jmap),
			"oauth" => Some(Surface::Oauth),
			"scim" => Some(Surface::Scim),
			_ => None,
		}
	}

	/// The surface a path belongs to, or `None` for a path no route has.
	pub fn of_path(path: &str) -> Option<Surface> {
		let under = |prefix: &str| {
			path == prefix
				|| path
					.strip_prefix(prefix)
					.is_some_and(|rest| rest.starts_with('/'))
		};
		if under("/api/v1") || path == "/healthz" {
			Some(Surface::Manage)
		} else if under("/jmap") || path == "/.well-known/jmap" {
			Some(Surface::Jmap)
		} else if under("/oauth") {
			Some(Surface::Oauth)
		} else if under("/scim/v2") {
			Some(Surface::Scim)
		} else {
			None
		}
	}

	/// The surface a listener kind serves on its own, if it is one.
	pub fn of_listener(kind: ListenerKind) -> Option<Surface> {
		match kind {
			ListenerKind::Jmap => Some(Surface::Jmap),
			ListenerKind::Oauth => Some(Surface::Oauth),
			ListenerKind::Scim => Some(Surface::Scim),
			_ => None,
		}
	}
}

/// The surfaces one listener serves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Surfaces(BTreeSet<Surface>);

impl Surfaces {
	/// Every surface: what a listener of kind `api` served in 0.14.0.
	pub fn all() -> Self {
		Surfaces(EVERY.into_iter().collect())
	}

	/// Exactly the surfaces given.
	pub fn only(surfaces: &[Surface]) -> Self {
		Surfaces(surfaces.iter().copied().collect())
	}

	/// Whether `surface` is served.
	pub fn contains(&self, surface: Surface) -> bool {
		self.0.contains(&surface)
	}

	/// The surfaces served, in a fixed order.
	pub fn iter(&self) -> impl Iterator<Item = Surface> + '_ {
		self.0.iter().copied()
	}

	/// What a listener of `kind` serves in `config`:
	///
	/// 1. a surface with a listener of its own is served there and only there;
	/// 2. with `[api] surfaces` absent, the `api` listener also serves every
	///    surface that has no listener of its own;
	/// 3. with `surfaces` present, the `api` listener serves management and
	///    what is listed;
	/// 4. a surface both listed and listened on is refused when the
	///    configuration loads, so it never reaches here;
	/// 5. `oauth` is served where it is routed, and only mounted when an
	///    OAuth signing key is configured, which the router decides.
	pub fn for_listener(config: &Config, kind: ListenerKind) -> Self {
		if let Some(surface) = Surface::of_listener(kind) {
			return Surfaces([surface].into_iter().collect());
		}
		if kind != ListenerKind::Api {
			return Surfaces(BTreeSet::new());
		}
		let own = |surface: Surface| {
			config
				.listeners
				.iter()
				.any(|listener| Surface::of_listener(listener.kind) == Some(surface))
		};
		let mut served: BTreeSet<Surface> = [Surface::Manage].into_iter().collect();
		match config.api.as_ref().and_then(|api| api.surfaces.as_ref()) {
			None => {
				served.extend(
					EVERY
						.into_iter()
						.filter(|surface| *surface != Surface::Manage && !own(*surface)),
				);
			}
			Some(listed) => {
				served.extend(listed.iter().filter_map(|name| Surface::optional(name)));
			}
		}
		Surfaces(served)
	}
}
