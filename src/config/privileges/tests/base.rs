use super::*;

#[test]
fn parses_user_only() {
	let privileges: Privileges = toml::from_str(r#"user = "glyndor-epistle""#).expect("parse");
	assert_eq!(privileges.user, "glyndor-epistle");
	assert!(privileges.group.is_none());
}

#[test]
fn parses_user_and_group() {
	let privileges: Privileges =
		toml::from_str("user = \"mail\"\ngroup = \"mail\"").expect("parse");
	assert_eq!(privileges.group.as_deref(), Some("mail"));
}

#[test]
fn rejects_unknown_keys() {
	assert!(toml::from_str::<Privileges>("user = \"mail\"\nuid = 1000").is_err());
}

#[test]
fn requires_user() {
	assert!(toml::from_str::<Privileges>(r#"group = "mail""#).is_err());
}
