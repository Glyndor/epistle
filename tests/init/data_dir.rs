use epistle::cli::Answers;

fn minimal() -> Answers {
	toml::from_str(&Answers::template()).unwrap()
}
use std::path::PathBuf;

#[test]
fn default_data_dir_is_below_the_service_home() {
	let answers: Answers = toml::from_str(&Answers::template()).unwrap();
	assert_eq!(
		answers.data_dir,
		PathBuf::from("/var/lib/glyndor/epistle/data"),
		"the default data_dir must isolate mail from the service home"
	);
}

#[test]
fn data_dir_rejects_the_running_users_home_and_ancestors() {
	let home = PathBuf::from(std::env::var_os("HOME").unwrap());
	for path in [&home, home.parent().unwrap()] {
		let mut answers = minimal();
		answers.data_dir = path.into();
		let errors: Vec<String> = answers
			.validate()
			.err()
			.unwrap_or_default()
			.iter()
			.map(ToString::to_string)
			.collect();
		let expected = format!(
			"data_dir: must exclude the user home, Podman storage and systemd units; a writable container mount would expose host services and backups would include container storage; use {}",
			home.join("data").display()
		);
		assert!(
			errors.contains(&expected),
			"init must reject a home or ancestor with the host-service explanation and home/data suggestion"
		);
	}
}

#[test]
fn data_dir_rejects_top_level_host_runtime_directories() {
	let home = PathBuf::from(std::env::var_os("HOME").unwrap());
	for marker in [".local/share/containers", ".config/systemd"] {
		let dir = tempfile::tempdir().unwrap();
		std::fs::create_dir_all(dir.path().join(marker)).unwrap();
		let mut answers = minimal();
		answers.data_dir = dir.path().into();
		let errors: Vec<String> = answers
			.validate()
			.err()
			.unwrap_or_default()
			.iter()
			.map(ToString::to_string)
			.collect();
		let expected = format!(
			"data_dir: must exclude the user home, Podman storage and systemd units; a writable container mount would expose host services and backups would include container storage; use {}",
			home.join("data").display()
		);
		assert!(
			errors.contains(&expected),
			"init must reject top-level host runtime directories with the home/data suggestion"
		);
	}
}

#[test]
fn data_dir_accepts_a_child_of_home() {
	let mut answers = minimal();
	answers.data_dir = PathBuf::from(std::env::var_os("HOME").unwrap()).join("data");
	assert!(
		answers.validate().is_ok(),
		"home/data must remain a valid data directory"
	);
}

#[test]
fn data_dir_rejects_home_aliases_and_parent_components() {
	use std::os::unix::fs::symlink;
	let home = PathBuf::from(std::env::var_os("HOME").unwrap());
	let dir = tempfile::tempdir().unwrap();
	let alias = dir.path().join("home");
	symlink(&home, &alias).unwrap();
	let ancestor_alias = dir.path().join("ancestor");
	symlink(home.parent().unwrap(), &ancestor_alias).unwrap();
	for path in [
		ancestor_alias.join("missing/.."),
		alias.clone(),
		alias.join("missing/.."),
		alias.join("missing/spare/../.."),
		home.join("data/.."),
		home.join("../"),
	] {
		let mut answers = minimal();
		answers.data_dir = path;
		let errors: Vec<String> = answers
			.validate()
			.err()
			.unwrap_or_default()
			.iter()
			.map(ToString::to_string)
			.collect();
		let expected = format!(
			"data_dir: must exclude the user home, Podman storage and systemd units; a writable container mount would expose host services and backups would include container storage; use {}",
			home.join("data").display()
		);
		assert!(
			errors.contains(&expected),
			"home aliases and parent components must not bypass data isolation"
		);
	}
}
