//! The class of mail the API submits (see [`crate::evidence::submission`]).

use std::sync::Arc;

use super::{ApiState, MatchedAuth};
use crate::evidence::bindings::{BindingSet, api_key_key_of_token};
use crate::evidence::{ClassSources, MailClass};

impl ApiState {
	/// Attach the class bindings. Must be set before the state is shared.
	pub fn with_class_bindings(mut self, bindings: Arc<BindingSet>) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.class_bindings = Some(bindings);
		}
		self
	}

	/// Attach the identification header policy. Must be set before the
	/// state is shared, like every other builder here.
	pub fn with_identification(mut self, policy: crate::smtp::identification::Policy) -> Self {
		if let Some(inner) = Arc::get_mut(&mut self.inner) {
			inner.identification = policy;
		}
		self
	}

	/// The identification header policy submissions get.
	pub fn identification(&self) -> &crate::smtp::identification::Policy {
		&self.inner.identification
	}

	/// Where the class of a submission by `account` comes from: `explicit`
	/// (the request), then the class bound to the API key that authenticated
	/// `auth`, then the account default.
	pub fn class_sources(
		&self,
		auth: Option<&MatchedAuth>,
		account: &str,
		explicit: Option<MailClass>,
	) -> ClassSources {
		let key = auth
			.filter(|auth| !auth.configured)
			.and_then(|auth| auth.token.as_deref());
		self.class_sources_for_key(key, account, explicit)
	}

	/// [`class_sources`](Self::class_sources) for the bearer of an API key,
	/// when the request came from one: the REST handlers hold the matched
	/// auth, the JMAP ones the principal built from it, and both must find
	/// the same class for the same key.
	pub fn class_sources_for_key(
		&self,
		key: Option<&str>,
		account: &str,
		explicit: Option<MailClass>,
	) -> ClassSources {
		let Some(bindings) = &self.inner.class_bindings else {
			return ClassSources {
				explicit,
				..ClassSources::default()
			};
		};
		ClassSources {
			explicit,
			credential: key.and_then(|token| bindings.credential(&api_key_key_of_token(token))),
			account: bindings.account(account),
		}
	}
}
