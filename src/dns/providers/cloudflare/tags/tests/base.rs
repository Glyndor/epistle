use super::*;

#[test]
fn host_tag_is_name_colon_hostname() {
	assert_eq!(
		host_tag("mail.example.org").as_deref(),
		Some("epistle:mail.example.org")
	);
}

#[test]
fn host_tag_drops_whitespace_and_cuts_to_the_value_limit() {
	assert_eq!(host_tag("a b\nc").as_deref(), Some("epistle:abc"));
	let long = "h".repeat(150);
	let tag = host_tag(&long).unwrap();
	assert_eq!(tag.len(), "epistle:".len() + 100);
	assert_eq!(host_tag(" \n"), None);
}

#[test]
fn merge_replaces_only_the_epistle_tag() {
	let existing = vec![
		"team:mail".to_string(),
		"Epistle:old.example.org".to_string(),
		"env:prod".to_string(),
	];
	assert_eq!(
		merge(&existing, Some("epistle:new.example.org")),
		vec!["team:mail", "env:prod", "epistle:new.example.org"]
	);
	assert_eq!(merge(&existing, None), vec!["team:mail", "env:prod"]);
}
