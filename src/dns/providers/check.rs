//! Advisory credential findings shared by DNS providers.

use std::pin::Pin;

use serde::Serialize;

use crate::dns::provider::ProviderError;

/// An inspection that never creates, updates or deletes a record.
pub type CheckOp<'a> = Pin<Box<dyn Future<Output = AccessReport> + Send + 'a>>;

/// Whether a provider supplied evidence for a finding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
	/// The stated fact was established by a read operation.
	Verified,
	/// The API could not establish this fact with this credential.
	NotVerifiable,
	/// A request failed or an observed capability does not meet the need.
	Failure,
}

/// A fact with its evidence or the cause of an incomplete check.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
	/// One of the three inspection outcomes.
	pub status: Outcome,
	/// Evidence or cause, without credentials or remote error bodies.
	pub detail: String,
}

impl Finding {
	/// Record a fact established by the API.
	pub fn verified(detail: impl Into<String>) -> Self {
		Self {
			status: Outcome::Verified,
			detail: detail.into(),
		}
	}
	/// Leave unavailable metadata explicitly unknown.
	pub fn unknown(detail: impl Into<String>) -> Self {
		Self {
			status: Outcome::NotVerifiable,
			detail: detail.into(),
		}
	}
	/// Report an observed failure without enforcing any action.
	pub fn failure(detail: impl Into<String>) -> Self {
		Self {
			status: Outcome::Failure,
			detail: detail.into(),
		}
	}
}

/// Independent results so missing metadata cannot be mistaken for success.
#[derive(Clone, Debug, Serialize)]
pub struct AccessReport {
	/// Credential activity, where introspection exists.
	pub token_status: Finding,
	/// Effective record reading, scoped to the zones named in the detail.
	pub record_read: Finding,
	/// Record writing established from policy, never a trial write.
	pub record_write: Finding,
	/// Visible zones, including extra zones and missing own names.
	pub zones: Finding,
	/// Expiration time, if exposed, with a seven-day warning window.
	pub expiry: Finding,
	/// Zone restrictions versus account-wide access.
	pub scope: Finding,
}

impl AccessReport {
	/// An honest starting point for providers without introspection.
	pub fn unknown() -> Self {
		let unknown = Finding::unknown("not verifiable with this provider");
		Self {
			token_status: unknown.clone(),
			record_read: unknown.clone(),
			record_write: unknown.clone(),
			zones: unknown.clone(),
			expiry: unknown.clone(),
			scope: unknown,
		}
	}
	/// Report a failure that prevented the inspection from completing.
	pub fn failed(cause: &str) -> Self {
		let failure = Finding::failure(cause);
		Self {
			token_status: failure.clone(),
			record_read: failure.clone(),
			record_write: failure.clone(),
			zones: failure.clone(),
			expiry: failure.clone(),
			scope: failure,
		}
	}
}

/// Keep provider responses and transport diagnostics out of credential reports.
pub(crate) fn failure_cause(error: &ProviderError) -> &'static str {
	match error {
		ProviderError::Auth => "provider refused authentication or authorization",
		ProviderError::Unsupported => "provider does not expose this operation",
		ProviderError::ZoneNotFound(_) => "provider holds no zone with that name",
		ProviderError::Remote(_) => {
			"provider request failed, timed out or returned an invalid response"
		}
	}
}
