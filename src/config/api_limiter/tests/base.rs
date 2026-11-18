use super::*;

fn parse(text: &str) -> ApiLimiter {
	toml::from_str(text).expect("parse")
}

#[test]
fn an_empty_section_keeps_every_default() {
	let limiter = parse("");
	limiter.validate().expect("valid");
	assert_eq!(limiter.max_failures(), 20);
	assert_eq!(limiter.window_secs(), 60);
	assert_eq!(limiter.network_factor(), 8);
	assert_eq!(limiter.global_max_failures(), 2000);
	assert_eq!(limiter.max_concurrent_hashes(), 2);
	assert_eq!(limiter.hash_queue(), 64);
}

#[test]
fn values_inside_the_bounds_are_accepted_and_read_back() {
	let limiter = parse(
		"max_failures = 10\nwindow_secs = 120\nnetwork_factor = 4\n\
		 global_max_failures = 500\nmax_concurrent_hashes = 4\nhash_queue = 128\n",
	);
	limiter.validate().expect("valid");
	assert_eq!(limiter.max_failures(), 10);
	assert_eq!(limiter.window_secs(), 120);
	assert_eq!(limiter.network_factor(), 4);
	assert_eq!(limiter.global_max_failures(), 500);
	assert_eq!(limiter.max_concurrent_hashes(), 4);
	assert_eq!(limiter.hash_queue(), 128);
}

#[test]
fn each_bound_is_enforced_on_both_sides() {
	let cases = [
		("max_failures", 0, 101),
		("window_secs", 29, 3601),
		("network_factor", 0, 33),
		("global_max_failures", 99, 20_001),
		("max_concurrent_hashes", 0, 65),
		("hash_queue", 0, 4097),
	];
	for (key, below, above) in cases {
		for value in [below, above] {
			let error = parse(&format!("{key} = {value}\n"))
				.validate()
				.expect_err(key);
			assert!(
				error.contains(&format!("[api.limiter] {key} ({value}) must be between")),
				"{error}"
			);
		}
	}
}

#[test]
fn the_bounds_themselves_are_accepted() {
	for (key, low, high) in [
		("max_failures", 1u64, 100u64),
		("window_secs", 30, 3600),
		("network_factor", 1, 32),
		("global_max_failures", 100, 20_000),
		("max_concurrent_hashes", 1, 64),
		("hash_queue", 1, 4096),
	] {
		for value in [low, high] {
			parse(&format!("{key} = {value}\n"))
				.validate()
				.unwrap_or_else(|error| panic!("{key} = {value}: {error}"));
		}
	}
}

#[test]
fn it_loads_under_api_in_a_config_file() {
	let api: crate::config::Api = toml::from_str("[limiter]\nmax_failures = 10\n").expect("parse");
	assert_eq!(api.limiter.max_failures(), 10);
}
