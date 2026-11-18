use std::os::unix::fs::symlink;

use super::*;

#[test]
fn a_secrets_link_to_another_disk_is_followed() {
	let l = layout();
	let elsewhere = l._root.path().join("elsewhere");
	std::fs::create_dir(&elsewhere).expect("mkdir");
	symlink(&elsewhere, l.data.parent().expect("parent").join("secrets")).expect("link");
	run(&l, NOW);
	assert!(
		std::fs::read_dir(&elsewhere)
			.expect("read")
			.next()
			.is_some()
	);
}

#[test]
fn a_secrets_link_into_the_data_dir_is_refused_and_left_alone() {
	let l = layout();
	let inside = l.data.join("inside");
	std::fs::create_dir(&inside).expect("mkdir");
	symlink(&inside, l.data.parent().expect("parent").join("secrets")).expect("link");
	let mut report = Report::default();
	let error = ensure(&l.data, NOW, &mut report).expect_err("must refuse");
	assert!(matches!(error, ApplyError::KeyWrite(..)));
	assert!(std::fs::read_dir(&inside).expect("read").next().is_none());
}
