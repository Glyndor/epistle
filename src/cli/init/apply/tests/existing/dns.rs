//! A re-run of `init` writes one `[dns]` table. It must not replace a list of
//! `[[dns]]` tables, one credential per zone, which `init` cannot express and
//! would otherwise reduce to a single zone without a word.

use super::apply_config;

fn parse(text: &str) -> toml::Value {
	toml::from_str(text).expect("parse")
}

const MANY: &str = "hostname = \"mail.example.org\"\n\
	[[dns]]\nprovider = \"cloudflare\"\nzone = \"example.org\"\n\
	[[dns]]\nprovider = \"desec\"\nzone = \"client.example\"\n";

#[test]
fn a_list_of_dns_tables_survives_a_rerun_that_has_its_own_dns() {
	let desired = parse(
		"hostname = \"mail.example.org\"\n[dns]\nprovider = \"manual\"\nzone = \"example.org\"\n",
	);
	let merged = apply_config::reconcile(parse(MANY), desired, false);
	let dns = merged.get("dns").and_then(toml::Value::as_array).unwrap();
	assert_eq!(dns.len(), 2, "the second zone was dropped: {merged}");
}

#[test]
fn a_list_of_dns_tables_survives_a_rerun_without_dns() {
	let merged = apply_config::reconcile(
		parse(MANY),
		parse("hostname = \"mail.example.org\"\n"),
		false,
	);
	assert_eq!(
		merged
			.get("dns")
			.and_then(toml::Value::as_array)
			.map(Vec::len),
		Some(2)
	);
}

#[test]
fn a_single_dns_table_is_still_replaced_by_the_answers() {
	let existing = parse(
		"hostname = \"mail.example.org\"\n[dns]\nprovider = \"cloudflare\"\nzone = \"old.example\"\n",
	);
	let desired = parse(
		"hostname = \"mail.example.org\"\n[dns]\nprovider = \"manual\"\nzone = \"example.org\"\n",
	);
	let merged = apply_config::reconcile(existing, desired, false);
	assert_eq!(merged["dns"]["zone"].as_str(), Some("example.org"));
}
