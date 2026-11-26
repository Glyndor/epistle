//! The four scopes that split `read` and `write` into management and mail,
//! and how a key keeps them in a file 0.14.0 can still load.
//!
//! 0.14.0 refuses a whole `api_keys.toml` on a scope name it does not know and
//! reads an empty `scopes` as every scope. So a key stores two fields: `scopes`,
//! in the names 0.14.0 reads, never empty, and `grants`, in the names 0.15.0
//! reads, which 0.14.0 ignores. [`ApiKey::reach`] is the one reading of both.

use super::{ApiKey, ApiKeyFile, ApiKeyStore, Scope, UnknownScopeError};

/// Every scope, in the order a set is written.
pub(crate) const ALL: [Scope; 9] = [
	Scope::ManageRead,
	Scope::ManageWrite,
	Scope::MailRead,
	Scope::MailWrite,
	Scope::Send,
	Scope::Scim,
	Scope::Alias,
	Scope::Ban,
	Scope::Health,
];

/// What a name of 0.14.0 reaches in 0.15.0: `read` and `write` keep both
/// halves, the other three are themselves. No key loses a route on upgrade.
pub(crate) fn expand_legacy(name: &str) -> Result<&'static [Scope], UnknownScopeError> {
	match name {
		"read" => Ok(&[Scope::ManageRead, Scope::MailRead]),
		"write" => Ok(&[Scope::ManageWrite, Scope::MailWrite]),
		"send" => Ok(&[Scope::Send]),
		"scim" => Ok(&[Scope::Scim]),
		"alias" => Ok(&[Scope::Alias]),
		other => Err(UnknownScopeError(other.to_string())),
	}
}

/// What a name in the `scopes` of a file means when it is read: the names of
/// 0.14.0, and `ban`, which a build of 0.15.0 before this one wrote there. A
/// writer never puts `ban` in `scopes` now, since 0.14.0 refuses the file that
/// names it; a file that has it still loads.
fn expand_loaded(name: &str) -> Result<&'static [Scope], UnknownScopeError> {
	match name {
		"ban" => Ok(&[Scope::Ban]),
		"health" => Ok(&[Scope::Health]),
		other => expand_legacy(other),
	}
}

impl Scope {
	/// The name 0.14.0 gave what this scope opens, or `None` when it had no
	/// scope for it. The `match` has no wildcard: a scope added later has to say
	/// here what 0.14.0 makes of it, and `None` is the only answer that does not
	/// widen anything (see [`ApiKey::unusable_in_v014`]).
	pub const fn v014_name(self) -> Option<&'static str> {
		match self {
			Scope::ManageRead | Scope::MailRead => Some("read"),
			Scope::ManageWrite | Scope::MailWrite => Some("write"),
			Scope::Send => Some("send"),
			Scope::Scim => Some("scim"),
			Scope::Alias => Some("alias"),
			Scope::Ban | Scope::Health => None,
		}
	}
}

/// The narrowest names of 0.14.0 that cover `grants`: `manage:read` or
/// `mail:read` gives `read`, `manage:write` or `mail:write` gives `write`, the
/// rest themselves. A scope 0.14.0 had no name for gives none, so the result is
/// empty for a key that holds only such scopes.
pub fn legacy_cover(grants: &[Scope]) -> Vec<&'static str> {
	["read", "write", "send", "scim", "alias"]
		.into_iter()
		.filter(|name| grants.iter().any(|scope| scope.v014_name() == Some(*name)))
		.collect()
}

impl ApiKey {
	/// The scopes the key holds. `None` is every scope: no `grants` and no
	/// `scopes`, the legacy key. `grants` win when present; otherwise `scopes`
	/// are expanded. A name this build cannot read is a scope the key does not
	/// hold, so the whole key holds nothing: the only fail-closed reading.
	pub fn reach(&self) -> Option<Vec<Scope>> {
		if self.grants.is_empty() && self.scopes.is_empty() {
			return None;
		}
		let mut held: Vec<Scope> = Vec::new();
		let mut add = |scope: Scope| {
			if !held.contains(&scope) {
				held.push(scope);
			}
		};
		if self.grants.is_empty() {
			for name in &self.scopes {
				match expand_loaded(name) {
					Ok(scopes) => scopes.iter().copied().for_each(&mut add),
					Err(_) => return Some(Vec::new()),
				}
			}
		} else {
			for name in &self.grants {
				match name.parse::<Scope>() {
					Ok(scope) => add(scope),
					Err(_) => return Some(Vec::new()),
				}
			}
		}
		Some(held)
	}

	/// Whether 0.14.0, reading the same file after a rollback, would have no
	/// scope for anything this key holds. Its `scopes` then carry a placeholder
	/// that 0.14.0 reads as `read`, so the key is written so that 0.14.0 loads it
	/// and refuses it (see `held::HELD`), and 0.15.0 restores it.
	pub fn unusable_in_v014(&self) -> bool {
		!self.grants.is_empty()
			&& self
				.reach()
				.is_some_and(|held| !held.is_empty() && legacy_cover(&held).is_empty())
	}

	/// Whether the key opens both a management route and a mail route of the
	/// same kind, which is what `read` and `write` do. A key bound to one
	/// account reaches no management route, and a legacy key has its own
	/// warning, so neither counts.
	pub fn spans_manage_and_mail(&self) -> bool {
		if self.account.is_some() {
			return false;
		}
		self.reach().is_some_and(|held| {
			(held.contains(&Scope::ManageRead) && held.contains(&Scope::MailRead))
				|| (held.contains(&Scope::ManageWrite) && held.contains(&Scope::MailWrite))
		})
	}
}

/// Check the scope entries of a key loaded from disk. `scopes` must be names of
/// 0.14.0 (so the file stays one 0.14.0 can load), `grants` names of 0.15.0, and
/// a key with `grants` must have `scopes` too, since 0.14.0 reads an empty
/// `scopes` as every scope. A typo in the file is the kind of thing that should
/// keep the server from starting: it is small and operator-edited.
pub(crate) fn validate_loaded(key: &ApiKey) -> std::io::Result<()> {
	let invalid = |message: String| {
		Err(std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			message,
		))
	};
	for scope in &key.scopes {
		if expand_loaded(scope).is_err() {
			return invalid(format!(
				"unknown API key scope \"{scope}\" in api_keys.toml (expected read, write, send, scim or alias)"
			));
		}
	}
	for grant in &key.grants {
		if grant.parse::<Scope>().is_err() {
			return invalid(format!(
				"unknown API key grant \"{grant}\" in api_keys.toml (expected manage:read, manage:write, mail:read, mail:write, send, scim or alias)"
			));
		}
	}
	if !key.grants.is_empty() && key.scopes.is_empty() {
		return invalid(format!(
			"API key \"{}\" has grants and no scopes; 0.14.0 would read that as every scope",
			key.label
		));
	}
	Ok(())
}

/// Why a list of scope names was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeInputError {
	/// No scope at all: a key must hold one.
	Empty,
	/// A name that is none of the seven new ones or the five of 0.14.0.
	Unknown(String),
}

impl std::fmt::Display for ScopeInputError {
	fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Empty => formatter.write_str(
				"API key must declare at least one scope (manage:read, manage:write, mail:read, mail:write, send, scim or alias)",
			),
			Self::Unknown(name) => write!(
				formatter,
				"unknown API key scope \"{name}\" (expected manage:read, manage:write, mail:read, mail:write, send, scim or alias)"
			),
		}
	}
}

impl std::error::Error for ScopeInputError {}

impl From<ScopeInputError> for std::io::Error {
	fn from(error: ScopeInputError) -> Self {
		std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
	}
}

/// The two fields a key stores for a set of scopes the operator named.
pub fn stored_form(
	names: &[String],
	account_bound: bool,
) -> Result<(Vec<String>, Vec<String>), ScopeInputError> {
	let mut set: Vec<Scope> = Vec::new();
	let mut as_given: Vec<String> = Vec::new();
	for name in names {
		if !as_given.contains(name) {
			as_given.push(name.clone());
		}
		let members: &[Scope] = match name.parse::<Scope>() {
			Ok(scope) => &[scope][..],
			Err(_) => match expand_legacy(name) {
				// A key bound to one account reaches mail routes only, so
				// `read` and `write` mean their mail half there.
				Ok([Scope::ManageRead, Scope::MailRead]) if account_bound => &[Scope::MailRead],
				Ok([Scope::ManageWrite, Scope::MailWrite]) if account_bound => &[Scope::MailWrite],
				Ok(members) => members,
				Err(_) => return Err(ScopeInputError::Unknown(name.clone())),
			},
		};
		for scope in members {
			if !set.contains(scope) {
				set.push(*scope);
			}
		}
	}
	if set.is_empty() {
		return Err(ScopeInputError::Empty);
	}
	set.sort_by_key(|scope| ALL.iter().position(|other| other == scope));
	// Names of 0.14.0 only: keep them as the operator wrote them, which is the
	// same set `legacy_cover` gives. Otherwise the narrowest covering names.
	let scopes = if as_given.iter().all(|name| expand_legacy(name).is_ok()) {
		as_given
	} else {
		let cover: Vec<String> = legacy_cover(&set).into_iter().map(String::from).collect();
		// 0.14.0 reads an empty list as every scope, so a key that holds only
		// scopes it had no name for gets a placeholder here and is made
		// unusable there instead ([`ApiKey::unusable_in_v014`]).
		if cover.is_empty() {
			vec!["read".to_string()]
		} else {
			cover
		}
	};
	let grants = set.iter().map(|scope| scope.as_str().to_string()).collect();
	Ok((scopes, grants))
}

/// The names to show an operator for a key: the ones it was made with when they
/// say what its `grants` say (a key made with `read` shows `read`), the
/// `grants` otherwise (a key narrowed to `mail:read`, or bound to an account).
pub fn display_names<'a>(scopes: &'a [String], grants: &'a [String]) -> &'a [String] {
	if grants.is_empty() {
		return scopes;
	}
	let mut expanded: Vec<Scope> = Vec::new();
	for name in scopes {
		match expand_loaded(name) {
			Ok(members) => members.iter().for_each(|member| {
				if !expanded.contains(member) {
					expanded.push(*member);
				}
			}),
			Err(_) => return grants,
		}
	}
	let same = expanded.len() == grants.len()
		&& grants.iter().all(|name| {
			name.parse::<Scope>()
				.is_ok_and(|scope| expanded.contains(&scope))
		});
	if same { scopes } else { grants }
}

/// `key` with `scopes` and `grants` written the way every writer stores them:
/// the set the key names, in both vocabularies, `scopes` never empty. The one
/// place a key enters the file, so no writer can leave 0.14.0 reading it as
/// every scope.
pub(super) fn normalized(mut key: ApiKey) -> std::io::Result<ApiKey> {
	let named: Vec<String> = key.scopes.iter().chain(&key.grants).cloned().collect();
	let (scopes, grants) = stored_form(&named, key.account.is_some())?;
	key.scopes = scopes;
	key.grants = grants;
	Ok(key)
}

impl ApiKeyStore {
	/// Replace the scopes of `label` with `names`, in both fields, in one
	/// locked rewrite. `NotFound` if the label is absent. The key keeps its
	/// secret, domains, expiry, address allowlist and account.
	pub fn set_scopes(&mut self, label: &str, names: &[String]) -> std::io::Result<()> {
		let label_owned = label.to_string();
		let new_state = crate::storage::locked::edit(
			&self.path,
			|text| {
				toml::from_str::<ApiKeyFile>(text)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
			},
			|state| {
				toml::to_string_pretty(state)
					.map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
			},
			ApiKeyFile::default,
			|state: &mut ApiKeyFile| -> std::io::Result<()> {
				let key = state
					.keys
					.iter_mut()
					.find(|existing| existing.label == label_owned)
					.ok_or_else(|| {
						std::io::Error::new(
							std::io::ErrorKind::NotFound,
							format!("no such API key \"{label}\""),
						)
					})?;
				let (scopes, grants) = stored_form(names, key.account.is_some())?;
				key.scopes = scopes;
				key.grants = grants;
				Ok(())
			},
		)
		.map_err(|error| match error {
			crate::storage::locked::EditError::Io(error)
			| crate::storage::locked::EditError::Mutate(error) => error,
		})?;
		self.keys = new_state.keys;
		Ok(())
	}
}
