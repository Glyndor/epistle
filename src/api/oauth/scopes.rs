//! OAuth scopes are explicit and independent; they never include administration.

use crate::api::api_keys::Scope;

#[derive(Clone)]
pub(super) struct Scopes(Vec<Scope>);

impl Scopes {
	/// An omitted scope grants read only. Explicit empty/unknown scopes fail closed.
	pub(super) fn requested(value: Option<&str>) -> Option<Self> {
		Self::parse(value.unwrap_or("read"))
	}

	pub(super) fn parse(value: &str) -> Option<Self> {
		if value.is_empty() || value.len() > 64 {
			return None;
		}
		let mut scopes = Vec::new();
		for name in value.split(' ') {
			let scope = match name {
				"read" => Scope::Read,
				"write" => Scope::Write,
				"send" => Scope::Send,
				_ => return None,
			};
			if !scopes.contains(&scope) {
				scopes.push(scope);
			}
		}
		Some(Self(scopes))
	}

	pub(super) fn as_string(&self) -> String {
		self.0
			.iter()
			.map(|scope| scope.as_str())
			.collect::<Vec<_>>()
			.join(" ")
	}

	/// Whether `self` and `other` name the same scopes, in any order.
	pub(super) fn same_set(&self, other: &Self) -> bool {
		self.0.len() == other.0.len() && self.0.iter().all(|scope| other.0.contains(scope))
	}

	/// Whether every scope of `self` is also in `other`.
	pub(super) fn is_subset_of(&self, other: &Self) -> bool {
		self.0.iter().all(|scope| other.0.contains(scope))
	}

	/// Whether the only scope is `read`, the default of an omitted scope.
	pub(super) fn is_default(&self) -> bool {
		self.0 == [Scope::Read]
	}

	pub(super) fn into_vec(self) -> Vec<Scope> {
		self.0
	}
}
