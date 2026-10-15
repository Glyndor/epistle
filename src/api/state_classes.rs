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

	/// Where the class of a submission by `account` comes from: `explicit`
	/// (the request), then the class bound to the API key that authenticated
	/// `auth` (the REST API; JMAP sessions carry none), then the account
	/// default.
	pub fn class_sources(
		&self,
		auth: Option<&MatchedAuth>,
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
			credential: auth
				.filter(|auth| !auth.configured)
				.and_then(|auth| auth.token.as_deref())
				.and_then(|token| bindings.credential(&api_key_key_of_token(token))),
			account: bindings.account(account),
		}
	}
}
