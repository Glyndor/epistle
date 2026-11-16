use super::*;

fn parse(text: &str) -> Auth {
	toml::from_str(text).expect("parse")
}

fn refused(text: &str) -> String {
	parse(text).validate().expect_err(text)
}

#[test]
fn an_empty_section_keeps_every_default() {
	let auth = parse("");
	auth.validate().expect("valid");
	assert_eq!(auth.password_limits(), Limits { min: 12, max: 64 });
	assert_eq!(
		auth.argon2_cost(),
		Argon2Cost {
			memory_kib: 19_456,
			iterations: 2,
			parallelism: 1
		}
	);
	assert_eq!(auth.scram_iteration_count(), 600_000);
	assert!(auth.forbidden_passwords_file.is_none());
}

#[test]
fn password_lengths_inside_the_bounds_are_accepted() {
	for text in [
		"min_password_length = 8\n",
		"max_password_length = 64\n",
		"max_password_length = 1024\n",
		"min_password_length = 15\nmax_password_length = 128\n",
	] {
		parse(text)
			.validate()
			.unwrap_or_else(|e| panic!("{text}: {e}"));
	}
	let auth = parse("min_password_length = 10\nmax_password_length = 200\n");
	assert_eq!(auth.password_limits(), Limits { min: 10, max: 200 });
}

#[test]
fn a_minimum_length_below_eight_is_refused() {
	let error = refused("min_password_length = 7\n");
	assert!(
		error.contains("min_password_length (7) must be at least 8"),
		"{error}"
	);
}

#[test]
fn a_maximum_length_below_sixty_four_is_refused() {
	let error = refused("max_password_length = 63\n");
	assert!(
		error.contains("max_password_length (63) must be at least 64"),
		"{error}"
	);
	assert!(error.contains("NIST"));
}

#[test]
fn a_maximum_length_above_the_ceiling_is_refused() {
	let error = refused("max_password_length = 1025\n");
	assert!(error.contains("must be at most 1024"), "{error}");
}

#[test]
fn a_minimum_above_the_maximum_is_refused() {
	let error = refused("min_password_length = 100\nmax_password_length = 80\n");
	assert!(
		error.contains("must not be above max_password_length"),
		"{error}"
	);
}

#[test]
fn the_argon2_cost_cannot_go_below_the_owasp_minimum() {
	for (text, key) in [
		(
			"argon2_memory_kib = 19455\n",
			"argon2_memory_kib (19455) must be at least 19456",
		),
		(
			"argon2_iterations = 1\n",
			"argon2_iterations (1) must be at least 2",
		),
		(
			"argon2_parallelism = 0\n",
			"argon2_parallelism (0) must be at least 1",
		),
	] {
		let error = refused(text);
		assert!(error.contains(key), "{error}");
		assert!(error.contains("OWASP"), "{error}");
	}
}

#[test]
fn the_argon2_cost_has_a_ceiling_and_accepts_what_is_stronger() {
	for text in [
		"argon2_memory_kib = 1048577\n",
		"argon2_iterations = 21\n",
		"argon2_parallelism = 17\n",
	] {
		assert!(refused(text).contains("must be at most"), "{text}");
	}
	let auth = parse("argon2_memory_kib = 65536\nargon2_iterations = 3\nargon2_parallelism = 4\n");
	auth.validate().expect("stronger is accepted");
	assert_eq!(auth.argon2_cost().memory_kib, 65_536);
	auth.argon2_cost().hasher().expect("usable parameters");
}

#[test]
fn the_scram_iterations_cannot_go_below_the_owasp_minimum() {
	let error = refused("scram_iterations = 599999\n");
	assert!(
		error.contains("scram_iterations (599999) must be at least 600000"),
		"{error}"
	);
	assert!(refused("scram_iterations = 10000001\n").contains("must be at most 10000000"));
	parse("scram_iterations = 600000\n")
		.validate()
		.expect("the floor");
	parse("scram_iterations = 1000000\n")
		.validate()
		.expect("stronger");
	assert_eq!(
		parse("scram_iterations = 800000\n").scram_iteration_count(),
		800_000
	);
}

#[test]
fn a_forbidden_passwords_file_that_cannot_be_read_is_refused() {
	let dir = tempfile::tempdir().expect("tempdir");
	let missing = dir.path().join("forbidden.txt");
	let error = refused(&format!(
		"forbidden_passwords_file = {:?}\n",
		missing.display().to_string()
	));
	assert!(error.contains("forbidden_passwords_file"), "{error}");
	assert!(error.contains("cannot read it"), "{error}");
	// A directory is not a list either.
	let error = refused(&format!(
		"forbidden_passwords_file = {:?}\n",
		dir.path().display().to_string()
	));
	assert!(error.contains("cannot read it"), "{error}");
}

#[test]
fn a_readable_forbidden_passwords_file_is_accepted() {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("forbidden.txt");
	std::fs::write(&path, "# example list\nexample company 2026\n").expect("write");
	parse(&format!(
		"forbidden_passwords_file = {:?}\n",
		path.display().to_string()
	))
	.validate()
	.expect("valid");
}

#[test]
fn unknown_keys_are_still_refused() {
	assert!(toml::from_str::<Auth>("argon2_memory = 20000\n").is_err());
}
