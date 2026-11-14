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

	pub(super) fn into_vec(self) -> Vec<Scope> {
		self.0
	}
}
