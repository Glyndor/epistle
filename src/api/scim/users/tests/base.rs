use super::*;

#[test]
fn filter_parser_accepts_user_name_eq() {
	assert_eq!(
		parse_user_name_eq(r#"userName eq "alice""#).unwrap(),
		"alice"
	);
}

#[test]
fn filter_parser_honours_string_escapes() {
	assert_eq!(parse_user_name_eq(r#"userName eq "a\"b""#).unwrap(), "a\"b");
	assert_eq!(parse_user_name_eq(r#"userName eq "a\\b""#).unwrap(), "a\\b");
}

#[test]
fn filter_parser_rejects_other_expressions() {
	assert!(parse_user_name_eq("displayName eq \"Alice\"").is_err());
	assert!(parse_user_name_eq("userName co \"al\"").is_err());
	assert!(parse_user_name_eq("userName eq alice").is_err());
}
