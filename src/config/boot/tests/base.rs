use crate::config::Config;
use std::path::Path;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

fn parse(extra: &str) -> Result<Config, crate::config::ConfigError> {
	Config::parse_text(&format!("{BASE}{extra}"), Path::new("mail.toml"))
}

#[test]
fn both_drop_ins_are_on_without_a_table() {
	let config = parse("").expect("parse");
	assert!(config.boot.restart_on_failure);
	assert!(config.boot.order_after_network);
}

#[test]
fn each_drop_in_turns_off_on_its_own() {
	let config = parse("[boot]\nrestart_on_failure = false\n").expect("parse");
	assert!(!config.boot.restart_on_failure);
	assert!(config.boot.order_after_network);
	let config = parse("[boot]\norder_after_network = false\n").expect("parse");
	assert!(config.boot.restart_on_failure);
	assert!(!config.boot.order_after_network);
}

#[test]
fn an_unknown_key_in_the_table_is_refused() {
	assert!(parse("[boot]\nrestart = false\n").is_err());
}
