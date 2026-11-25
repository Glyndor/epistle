//! The names an OAuth client asks for, and the claim of its token, stay
//! `read`, `write` and `send`: tokens issued before 0.15.0 keep working, and
//! 0.14.0 reads the ones issued after it. Inside, they are the mail scopes.

use super::super::scopes::Scopes;
use crate::api::api_keys::Scope;

#[test]
fn oauth_claim_keeps_old_names() {
	let scopes = Scopes::parse("read write send").expect("parse");
	assert_eq!(scopes.as_string(), "read write send");
	assert_eq!(
		scopes.into_vec(),
		[Scope::MailRead, Scope::MailWrite, Scope::Send]
	);
}

#[test]
fn a_claim_issued_by_0_14_0_is_read_as_before() {
	let scopes = Scopes::parse("read").expect("parse");
	assert!(scopes.is_default());
	assert_eq!(scopes.as_string(), "read");
}

#[test]
fn no_oauth_scope_reaches_management() {
	for name in [
		"manage:read",
		"manage:write",
		"mail:read",
		"mail:write",
		"scim",
		"alias",
	] {
		assert!(Scopes::parse(name).is_none(), "{name}");
	}
	let all = Scopes::parse("read write send").expect("parse").into_vec();
	assert!(!all.contains(&Scope::ManageRead) && !all.contains(&Scope::ManageWrite));
}
