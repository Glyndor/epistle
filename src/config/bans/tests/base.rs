use super::*;

fn parse(text: &str) -> Bans {
	toml::from_str(text).expect("parse")
}

#[test]
fn an_empty_section_keeps_every_default() {
	let bans = parse("");
	bans.validate().expect("valid");
	assert_eq!(bans.policy(BanPolicy::default()), BanPolicy::default());
}

#[test]
fn the_defaults_are_what_the_server_always_did() {
	let policy = BanPolicy::default();
	assert_eq!(policy.threshold, 5);
	assert_eq!(policy.window_secs, 900);
	assert_eq!(policy.base_secs, 900);
	assert_eq!(policy.max_secs, 86_400);
	assert_eq!(policy.account_threshold_factor, 4);
	assert_eq!(policy.known_network_max_per_account, 32);
}

#[test]
fn every_value_inside_its_bounds_is_accepted_and_applied() {
	let bans = parse(
		"threshold = 3\nwindow_secs = 600\nbase_secs = 1800\nmax_secs = 172800\n\
		 account_threshold_factor = 6\nknown_network_max_per_account = 64\n",
	);
	bans.validate().expect("valid");
	let policy = bans.policy(BanPolicy::default());
	assert_eq!(policy.threshold, 3);
	assert_eq!(policy.window_secs, 600);
	assert_eq!(policy.base_secs, 1800);
	assert_eq!(policy.max_secs, 172_800);
	assert_eq!(policy.threshold_for("account:alice"), 18);
	assert_eq!(policy.threshold_for("client:203.0.113.5"), 3);
	assert_eq!(policy.known_network_max_per_account, 64);
}

#[test]
fn each_bound_is_enforced_on_both_sides() {
	let cases = [
		("threshold", 1, 21),
		("window_secs", 299, 86_401),
		("base_secs", 299, 86_401),
		("max_secs", 3599, 2_592_001),
		("account_threshold_factor", 1, 9),
		("known_network_max_per_account", 0, 257),
	];
	for (key, below, above) in cases {
		for value in [below, above] {
			let error = parse(&format!("{key} = {value}\n"))
				.validate()
				.expect_err(key);
			assert!(
				error.contains(&format!("[bans] {key} ({value}) must be between")),
				"{error}"
			);
		}
	}
}

#[test]
fn the_bounds_themselves_are_accepted() {
	for (key, low, high) in [
		("threshold", 2u64, 20u64),
		("window_secs", 300, 86_400),
		("base_secs", 300, 3600),
		("max_secs", 3600, 2_592_000),
		("account_threshold_factor", 2, 8),
		("known_network_max_per_account", 1, 256),
	] {
		for value in [low, high] {
			parse(&format!("{key} = {value}\n"))
				.validate()
				.unwrap_or_else(|error| panic!("{key} = {value}: {error}"));
		}
	}
}

#[test]
fn a_longest_ban_shorter_than_the_first_is_refused() {
	let error = parse("base_secs = 7200\nmax_secs = 3600\n")
		.validate()
		.expect_err("inverted");
	assert!(error.contains("max_secs (3600) must not be shorter than base_secs (7200)"));
	let error = parse("base_secs = 86400\n").validate();
	assert!(error.is_ok(), "the default maximum is a day");
	let error = parse("base_secs = 86400\nmax_secs = 3600\n")
		.validate()
		.expect_err("inverted");
	assert!(error.contains("must not be shorter"));
}

#[test]
fn an_unknown_key_is_refused() {
	assert!(toml::from_str::<Bans>("thresold = 3\n").is_err());
}
