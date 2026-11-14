//! Status-to-error mapping, including GoDaddy account eligibility.

use crate::dns::provider::ProviderError;

/// Map a 401/403 to a typed auth error. 401 is a bad key; 403 is the
/// GoDaddy-specific "your account is not eligible for production API
/// access" verdict, so the message names the eligibility check instead
/// of the generic "authentication failed" the other providers use.
pub(super) fn auth_error(status: reqwest::StatusCode) -> ProviderError {
	if status == reqwest::StatusCode::FORBIDDEN {
		ProviderError::Remote(
			"GoDaddy account is not eligible for production API access; \
			 see https://developer.godaddy.com/getstarted for eligibility"
				.into(),
		)
	} else {
		ProviderError::Auth
	}
}

/// Map a write response to success or a typed error. 401 maps to
/// `ProviderError::Auth`; 403 maps to the eligibility-flavoured error.
pub(super) fn check(response: reqwest::Response) -> Result<(), ProviderError> {
	let status = response.status();
	if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
		return Err(auth_error(status));
	}
	if status.is_success() {
		Ok(())
	} else {
		Err(ProviderError::Remote(format!("HTTP {status}")))
	}
}
