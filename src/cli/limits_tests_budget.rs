//! `limits show` reports the message memory budget the server derives when
//! `message_memory_budget` is unset, not a fixed default.

use super::tests_config::config_file;
use super::*;

/// The `message-memory-budget` line of `limits show`, and its JSON entry.
fn shown(config: &Config) -> (String, serde_json::Value) {
	let mut out = Vec::new();
	show(config, &mut out).unwrap();
	let line = String::from_utf8(out)
		.unwrap()
		.lines()
		.find(|line| line.starts_with("message-memory-budget\t"))
		.expect("a message-memory-budget line")
		.to_string();
	(line, show_json(config)["message-memory-budget"].clone())
}

fn write_compose(config: &Config, mail_memory: &str) {
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(
		compose,
		format!(r#"{{"services":{{"mail":{{"mem_limit":"{mail_memory}"}}}}}}"#),
	)
	.unwrap();
}

#[test]
fn an_unset_budget_shows_what_the_mail_limit_gives() {
	let (_dir, file) = config_file();
	let config = Config::load(file.path()).unwrap();
	write_compose(&config, "2g");
	assert_eq!(
		shown(&config),
		(
			"message-memory-budget\tauto (409 MiB from the mail container limit)\tderived\tadjustable\tno standard mandate"
				.to_string(),
			serde_json::json!({"value": 409_u64 * 1024 * 1024, "unit": "bytes", "source": "derived", "kind": "adjustable", "bounds": null, "reference": "no standard mandate"})
		)
	);
}

#[test]
fn an_unset_budget_without_a_compose_file_shows_the_assumed_limit() {
	let (_dir, file) = config_file();
	let config = Config::load(file.path()).unwrap();
	assert_eq!(
		shown(&config),
		(
			"message-memory-budget\tauto (204 MiB, no mail container limit found, 1g \
			 assumed)\tderived\tadjustable\tno standard mandate"
				.to_string(),
			serde_json::json!({"value": 204_u64 * 1024 * 1024, "unit": "bytes", "source": "derived", "kind": "adjustable", "bounds": null, "reference": "no standard mandate"})
		)
	);
}

#[test]
fn a_set_budget_is_configured_whatever_its_value() {
	let (_dir, file) = config_file();
	change_config(file.path(), Key::MessageMemoryBudget, Some("256M")).unwrap();
	let config = Config::load(file.path()).unwrap();
	write_compose(&config, "2g");
	assert_eq!(
		shown(&config),
		(
			"message-memory-budget\t268435456 bytes\tconfigured\tadjustable\tno standard mandate"
				.to_string(),
			serde_json::json!({"value": 268_435_456_u64, "unit": "bytes", "source": "configured", "kind": "adjustable", "bounds": null, "reference": "no standard mandate"})
		)
	);
}
