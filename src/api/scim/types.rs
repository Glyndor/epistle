//! SCIM 2.0 wire types: the shape of a User resource, the filter expression
//! the IdP sends, the patch operations, and the list/search responses.
//!
//! The fields here are deliberately the minimum the three IdPs we integrate
//! against (Entra ID, Okta, Keycloak) actually populate: `userName`, `name`,
//! `emails`, `active`, and `password`. Anything else the IdP sends is
//! accepted on the wire (serde's default is permissive on unknown fields)
//! but not modelled — SCIM servers are required by RFC 7643 §3 to ignore
//! unknown attributes, and we do.
//!
//! `id` equals the account login name. SCIM treats it as an opaque
//! identifier; we set it to the same string the IdP sees in `userName`, so
//! a round trip stays unambiguous.

use serde::{Deserialize, Serialize};

/// The schema URN of a SCIM User. Every User resource carries it
/// (RFC 7643 §4.1).
pub const USER_SCHEMA: &str = "urn:ietf:params:scim:schemas:core:2.0:User";

/// The schema URN a SCIM `ListResponse` advertises when returning a
/// collection (RFC 7644 §3.4.2).
pub const LIST_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// One email address the IdP sends for the user (RFC 7643 §4.1.2 / §5.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Email {
	/// The email address itself (lowercased on input so equality is
	/// deterministic).
	pub value: String,
	/// `"work"`, `"home"`, … Ignored on read: we round-trip it so the IdP
	/// does not see its own field rewritten.
	#[serde(default, skip_serializing_if = "Option::is_none", rename = "type")]
	pub r#type: Option<String>,
	/// Whether this is the user's primary email. RFC 7643 says at most one
	/// email carries `primary: true`; we mirror whatever the IdP sent.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub primary: Option<bool>,
}

/// The `name` sub-object (RFC 7643 §4.1.1). We surface `givenName` and
/// `familyName` because the IdPs all populate them, and ignore the rest.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Name {
	/// Given name (RFC 7643 calls it the "honorific" plus "given" pieces; we
	/// collapse to one field that the IdPs populate under `givenName`).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub given_name: Option<String>,
	/// Family name.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub family_name: Option<String>,
}

/// SCIM User resource (RFC 7643 §4.1). The struct uses `camelCase` because
/// SCIM is a camelCase protocol — every IdP serialises `userName` /
/// `displayName` / `externalId` / `givenName` / `familyName` that way.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
	/// Server-assigned identifier (the account login name). RFC 7644 §3.3
	/// requires it be unique and stable.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub id: Option<String>,
	/// SCIM schema URN — always `USER_SCHEMA`. Multiple schemas are
	/// permitted by the spec; we advertise one.
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub schemas: Vec<String>,
	/// External Id, preserved verbatim so an IdP round trip is lossless.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub external_id: Option<String>,
	/// The account login name. Also used as `id`.
	pub user_name: String,
	/// Display name (optional; we surface it on reads when present).
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub display_name: Option<String>,
	/// Whether the account is enabled. `false` maps to the directory's
	/// `disabled` flag.
	pub active: bool,
	/// Email addresses (RFC 7643 §4.1.2). Empty list is allowed (an IdP
	/// can create an account without mail first).
	#[serde(default)]
	pub emails: Vec<Email>,
	/// The `name` sub-object.
	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub name: Option<Name>,
	/// Write-only plaintext password (RFC 7643 §8.2). Accepted on
	/// `POST`/`PUT`, never rendered back. SCIM puts it outside the core
	/// `User` schema, but every IdP we integrate against serialises it
	/// inline; we follow the convention.
	#[serde(default, skip_serializing)]
	pub password: Option<String>,
}

/// A SCIM list response (RFC 7644 §3.4.2).
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
	/// Schema URN (always [`LIST_RESPONSE_SCHEMA`]).
	pub schemas: Vec<String>,
	/// Total number of resources matching the query, ignoring pagination.
	#[serde(rename = "totalResults")]
	pub total_results: u64,
	/// The `Resources` array — SCIM capitalises the field name.
	#[serde(rename = "Resources")]
	pub resources: Vec<User>,
	/// 1-based index of the first item on this page.
	#[serde(rename = "startIndex")]
	pub start_index: u64,
	/// Number of items on this page.
	#[serde(rename = "itemsPerPage")]
	pub items_per_page: u64,
}

/// The body of a SCIM `PATCH` request (RFC 7644 §3.5.2).
#[derive(Debug, Serialize, Deserialize)]
pub struct PatchRequest {
	/// Schema URN (always [`PATCH_OP_SCHEMA`]).
	#[serde(default, skip_serializing_if = "Vec::is_empty")]
	pub schemas: Vec<String>,
	/// The operations to apply, in order. SCIM capitalises the field
	/// name on the wire (RFC 7644 §3.5.2); we rename explicitly.
	#[serde(rename = "Operations")]
	pub operations: Vec<PatchOperation>,
}

/// One SCIM patch operation (RFC 7644 §3.5.2). We implement a narrow
/// subset: `replace` (and `add` of a single-value attribute) of `active`
/// and `password`. Anything else — `remove`, multi-value ops, `path`
/// outside `active`/`password` — is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchOperation {
	/// `"add"`, `"replace"`, or `"remove"`. Only `replace` and `add` of
	/// the two accepted attributes are honoured; see `users::patch_user`.
	#[serde(rename = "op")]
	pub op: String,
	/// The dotted path of the attribute. Only `active` and `password`
	/// are accepted.
	#[serde(default, rename = "path")]
	pub path: Option<String>,
	/// The new value. RFC 7644 says the value shape depends on the path;
	/// we only accept a bool (`active`) or string (`password`).
	#[serde(default, rename = "value")]
	pub value: serde_json::Value,
}

impl ListResponse {
	/// Build a single-page response from `users`. The `start_index` and
	/// `items_per_page` are derived from the request; total is the full
	/// match count.
	pub fn single_page(start_index: u64, items_per_page: u64, users: Vec<User>) -> Self {
		ListResponse {
			schemas: vec![LIST_RESPONSE_SCHEMA.to_string()],
			total_results: users.len() as u64,
			resources: users,
			start_index,
			items_per_page,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn user_round_trips_through_json() {
		let original = User {
			id: Some("alice".to_string()),
			schemas: vec![USER_SCHEMA.to_string()],
			external_id: None,
			user_name: "alice".to_string(),
			display_name: Some("Alice".to_string()),
			active: true,
			emails: vec![Email {
				value: "alice@example.org".to_string(),
				r#type: Some("work".to_string()),
				primary: Some(true),
			}],
			name: Some(Name {
				given_name: Some("Alice".to_string()),
				family_name: Some("Liddell".to_string()),
			}),
			password: None,
		};
		let encoded = serde_json::to_string(&original).expect("encode");
		assert!(encoded.contains("\"userName\""), "{encoded}");
		assert!(encoded.contains("\"active\":true"), "{encoded}");
		let decoded: User = serde_json::from_str(&encoded).expect("decode");
		assert_eq!(decoded.user_name, "alice");
		assert!(decoded.active);
		assert_eq!(decoded.emails.len(), 1);
		assert_eq!(decoded.emails[0].value, "alice@example.org");
	}

	#[test]
	fn list_response_carries_scim_resource_field_name() {
		let list = ListResponse::single_page(1, 1, Vec::new());
		let encoded = serde_json::to_string(&list).expect("encode");
		assert!(encoded.contains("\"Resources\""), "{encoded}");
		assert!(encoded.contains(LIST_RESPONSE_SCHEMA), "{encoded}");
	}
}
