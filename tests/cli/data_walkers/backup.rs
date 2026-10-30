use super::*;

fn check_backup_skips(kind: &str) {
	let root = tempfile::tempdir().unwrap();
	let data = root.path().join("data");
	std::fs::create_dir(&data).unwrap();
	std::fs::write(data.join("mail"), "Subject: x\r\n\r\nbody").unwrap();
	let outside = root.path().join("outside");
	if kind == "directory-link" {
		std::fs::create_dir(&outside).unwrap();
		std::fs::write(outside.join("host-file"), "outside").unwrap();
	} else if kind != "broken-link" {
		std::fs::write(&outside, "outside").unwrap();
	}
	let skipped = data.join("skip");
	special(&skipped, kind, &outside);
	let config = config(root.path(), &data);
	let output = run(&["backup", "--config", config.to_str().unwrap()]);
	assert_eq!(
		output.as_ref().map(|out| out.status.code()),
		Some(Some(0)),
		"backup must finish successfully while skipping non-regular paths"
	);
	let output = output.unwrap();
	assert_eq!(
		archive_names(&output.stdout),
		vec!["data/mail"],
		"backup must archive only the regular mail file"
	);
	assert_warning_once(&output, &skipped);
}

#[test]
fn backup_skips_non_regular_paths_socket() {
	check_backup_skips("socket");
}

#[test]
fn backup_skips_non_regular_paths_fifo() {
	check_backup_skips("fifo");
}

#[test]
fn backup_skips_non_regular_paths_symlink() {
	check_backup_skips("symlink");
}

#[test]
fn backup_skips_non_regular_paths_directory_link() {
	check_backup_skips("directory-link");
}

#[test]
fn backup_skips_non_regular_paths_broken_link() {
	check_backup_skips("broken-link");
}

#[test]
fn backup_skips_a_symlink_cycle() {
	let root = tempfile::tempdir().unwrap();
	std::fs::write(root.path().join("mail"), "mail").unwrap();
	symlink(root.path(), root.path().join("cycle")).unwrap();
	let config_root = tempfile::tempdir().unwrap();
	let config = config(config_root.path(), root.path());
	let output = run(&["backup", "--config", config.to_str().unwrap()]);
	assert_eq!(
		output.as_ref().map(|out| out.status.code()),
		Some(Some(0)),
		"backup must terminate successfully without following a symlink cycle"
	);
	let output = output.unwrap();
	assert_eq!(
		archive_names(&output.stdout),
		vec!["data/mail"],
		"a symlink cycle must add no archive entries"
	);
	assert_warning_once(&output, &root.path().join("cycle"));
}
