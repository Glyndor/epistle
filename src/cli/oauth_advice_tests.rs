use super::*;

fn config(extra: &str) -> Config {
	toml::from_str(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"/tmp/x\"\n{extra}"
	))
	.expect("config")
}

const EXTERNAL: &str =
	"[oauth]\nissuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n";

#[test]
fn no_section_and_the_built_in_server_say_nothing() {
	assert!(advice_for(&config(""), 2).is_empty());
	assert_eq!(notice(&config("")), None);
	let own = format!("{EXTERNAL}signing_key = \"S\"\n");
	assert!(advice_for(&config(&own), 2).is_empty());
	assert_eq!(notice(&config(&own)), None);
}

#[test]
fn the_verified_email_is_a_notice_not_a_warning() {
	let text = notice(&config(EXTERNAL)).expect("notice");
	assert!(text.contains("email_verified"));
	assert!(advice_for(&config(EXTERNAL), 0).is_empty());
	let allowed = format!("{EXTERNAL}allow_unverified_email = true\n");
	assert_eq!(notice(&config(&allowed)), None);
}

#[test]
fn accounts_with_a_second_factor_are_counted() {
	assert!(advice_for(&config(EXTERNAL), 0).is_empty());
	let lines = advice_for(&config(EXTERNAL), 2);
	assert_eq!(lines.len(), 1, "{lines:?}");
	assert!(lines[0].contains("2 account(s)"));
	let declared = format!("{EXTERNAL}idp_enforces_second_factor = true\n");
	assert!(advice_for(&config(&declared), 2).is_empty());
}
