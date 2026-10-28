use super::*;

#[test]
fn parses_arc_section() {
	let arc: Arc = toml::from_str(
		r#"
selector = "arc"
key_file = "/etc/mail/arc.pem"
"#,
	)
	.expect("parse arc");
	assert_eq!(arc.selector, "arc");
}

#[test]
fn rejects_missing_fields_and_unknown_keys() {
	assert!(toml::from_str::<Arc>(r#"selector = "arc""#).is_err());
	assert!(
		toml::from_str::<Arc>(
			r#"
selector = "arc"
key_file = "/k.pem"
domain = "x"
"#
		)
		.is_err()
	);
}
