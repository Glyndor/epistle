//! The LLM endpoint, model and API-key env name are stored verbatim, but the
//! show path renders them as `set`/`unset` and never prints the values.

use std::io::Write;
use std::path::Path;

use super::*;
use crate::config::Config;

fn fixture(extra: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().unwrap();
	let canonical = std::env::current_dir().unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		canonical.to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	file
}

fn load(path: &Path) -> Config {
	Config::load(path).expect("config must load")
}

#[test]
fn llm_summary_marks_every_field_set_when_present() {
	let file = fixture(
		"[antispam_llm]\nendpoint = \"https://api.example/v1/chat/completions\"\napi_key_env = \"EPISTLE_LLM_API_KEY\"\nmodel = \"gpt-4o-mini\"\n",
	);
	let config = load(file.path());
	assert!(llm_is_set(&config));
	let summary = llm_summary(&config);
	assert_eq!(summary.get("endpoint"), Some(&"set"));
	assert_eq!(summary.get("model"), Some(&"set"));
	assert_eq!(summary.get("api_key_env"), Some(&"set"));
}

#[test]
fn llm_summary_marks_every_field_unset_when_absent() {
	let file = fixture("");
	let config = load(file.path());
	assert!(!llm_is_set(&config));
	let summary = llm_summary(&config);
	assert_eq!(summary.get("endpoint"), Some(&"unset"));
	assert_eq!(summary.get("model"), Some(&"unset"));
	assert_eq!(summary.get("api_key_env"), Some(&"unset"));
}

#[test]
fn show_does_not_leak_the_endpoint_url_or_env_var_name() {
	let file = fixture(
		"[antispam_llm]\nendpoint = \"https://api.example/v1/chat/completions\"\napi_key_env = \"EPISTLE_LLM_API_KEY\"\nmodel = \"gpt-4o-mini\"\n",
	);
	let config = load(file.path());
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	let output = String::from_utf8(out).unwrap();
	assert!(
		!output.contains("EPISTLE_LLM_API_KEY"),
		"show must not echo the api_key_env value: {output}"
	);
	assert!(
		!output.contains("https://api.example"),
		"show must not echo the endpoint value: {output}"
	);
	assert!(
		!output.contains("gpt-4o-mini"),
		"show must not echo the model value: {output}"
	);
}
