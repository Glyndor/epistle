//! What an export does when something it was asked for is not there.

use super::tests::kept_stamped_at;
use super::*;
use crate::evidence::audit::tests::DAY;
use crate::evidence::day::Day;
use crate::evidence::test_support::at;

fn export_kept(
	kept: &super::tests::Kept,
) -> Result<(Exported, std::path::PathBuf, tempfile::TempDir), BundleError> {
	let out = tempfile::tempdir().expect("tempdir");
	let bundle = out.path().join("bundle");
	let selector = Selector::MessageId("<kept@example.org>".into());
	let done = export(kept.dir.path(), &kept.crypto, &selector, &bundle)?;
	Ok((done, bundle, out))
}

fn stored(kept: &super::tests::Kept) -> std::path::PathBuf {
	kept.dir
		.path()
		.join("messages")
		.join(Day(DAY).name())
		.join("30")
		.join(format!("{}.eml", kept.id))
}

#[test]
fn a_message_kept_under_the_next_day_by_a_clock_across_midnight_is_found() {
	let kept = kept_stamped_at(false, at(DAY + 1, 1));
	let next = kept
		.dir
		.path()
		.join("messages")
		.join(Day(DAY + 1).name())
		.join("30");
	std::fs::create_dir_all(&next).expect("dir");
	std::fs::rename(stored(&kept), next.join(format!("{}.eml", kept.id))).expect("move");
	let (_done, bundle, _out) = export_kept(&kept).expect("export");
	assert!(
		bundle
			.join("messages")
			.join(format!("{}.eml", kept.id))
			.exists()
	);
}

#[test]
fn a_kept_message_that_is_gone_stops_the_export_instead_of_leaving_it_out() {
	let kept = kept_stamped_at(false, at(DAY + 1, 1));
	std::fs::remove_file(stored(&kept)).expect("remove");
	let error = export_kept(&kept).expect_err("a bundle without the message it says it keeps");
	assert_eq!(
		error.to_string(),
		format!(
			"the message {} is recorded as kept and is not in the evidence directory",
			kept.id
		)
	);
}

#[test]
fn nothing_is_said_of_a_message_whose_day_is_not_sealed() {
	let kept = kept_stamped_at(false, at(DAY + 1, 1));
	let paths = crate::evidence::checkpoint::files(kept.dir.path(), Day(DAY));
	for path in [&paths.json, &paths.sig, &paths.tsr] {
		std::fs::remove_file(path).expect("remove");
	}
	let (done, bundle, _out) = export_kept(&kept).expect("export");
	assert_eq!(done.unsealed, vec![Day(DAY)]);
	assert!(done.messages.is_empty(), "{:?}", done.messages);
	assert!(
		!bundle
			.join("messages")
			.join(format!("{}.eml", kept.id))
			.exists(),
		"a message of a day nothing in the bundle covers"
	);
	let readme = std::fs::read_to_string(bundle.join("README.md")).expect("readme");
	assert!(
		!readme.contains(&kept.id.to_string()),
		"the README names it"
	);
}
