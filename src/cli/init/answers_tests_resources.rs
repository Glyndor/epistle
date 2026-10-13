//! The `[resources.<service>]` answers.

use super::*;
use crate::cli::init::compose::stack_answers;
use crate::cli::init::resources::ServiceResources;

fn with(service: &str, memory: Option<&str>, pids: Option<u32>) -> Answers {
	let mut answers = stack_answers();
	answers.data_dir = std::path::PathBuf::from("/var/lib/glyndor/epistle/data");
	answers.resources.insert(
		service.to_string(),
		ServiceResources {
			memory: memory.map(str::to_string),
			pids,
		},
	);
	answers
}

fn errors(answers: &Answers) -> Vec<String> {
	match answers.validate() {
		Ok(_) => Vec::new(),
		Err(errors) => errors.iter().map(ToString::to_string).collect(),
	}
}

#[test]
fn the_answers_file_reads_a_resources_table() {
	let text = format!(
		"{}\n[resources.clamav]\nmemory = \"4g\"\npids = 256\n",
		Answers::template()
	);
	let answers: Answers = toml::from_str(&text).expect("parse");
	assert_eq!(
		answers.resources.get("clamav"),
		Some(&ServiceResources {
			memory: Some("4g".to_string()),
			pids: Some(256),
		})
	);
}

#[test]
fn an_unknown_key_in_a_resources_table_is_refused() {
	let text = format!("{}\n[resources.clamav]\ncpus = 2\n", Answers::template());
	assert!(toml::from_str::<Answers>(&text).is_err());
}

#[test]
fn well_formed_values_pass() {
	for memory in ["512m", "2g", "65536k", "3G"] {
		assert_eq!(
			errors(&with("mail", Some(memory), Some(64))),
			Vec::<String>::new(),
			"{memory}"
		);
	}
}

#[test]
fn an_unknown_service_is_named() {
	let found = errors(&with("redis", Some("1g"), None));
	assert_eq!(found.len(), 1, "{found:?}");
	assert!(found[0].contains("resources.redis"), "{found:?}");
	assert!(
		found[0].contains("mail, db, clamav, freshclam"),
		"{found:?}"
	);
}

#[test]
fn a_memory_without_a_unit_or_with_zero_is_refused() {
	for memory in ["1024", "0g", "1.5g", "g", "-1g", "1 g", "1t"] {
		let found = errors(&with("db", Some(memory), None));
		assert_eq!(found.len(), 1, "{memory}: {found:?}");
		assert!(found[0].contains("resources.db.memory"), "{found:?}");
	}
}

#[test]
fn a_process_limit_of_zero_is_refused() {
	let found = errors(&with("db", None, Some(0)));
	assert_eq!(found.len(), 1, "{found:?}");
	assert!(found[0].contains("resources.db.pids"), "{found:?}");
}
