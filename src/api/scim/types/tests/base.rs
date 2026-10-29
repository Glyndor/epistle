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
	let list = ListResponse::single_page(1, 0, Vec::new());
	let encoded = serde_json::to_string(&list).expect("encode");
	assert!(encoded.contains("\"Resources\""), "{encoded}");
	assert!(encoded.contains(LIST_RESPONSE_SCHEMA), "{encoded}");
}
