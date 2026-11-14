//! The step itself, with something else at the file's path by the time it
//! runs: nothing is written over it, and the key keeps its old secret.

use super::super::super::journal::{Kind, Step};
use super::super::super::secrets::Secrets;
use super::super::super::steps::{self, Context};
use super::*;

/// Swap the key file for a link to where it was moved.
fn link_in_its_place(install: &Install) -> PathBuf {
	let path = key_file(install);
	let elsewhere = path.with_file_name("elsewhere");
	std::fs::rename(&path, &elsewhere).unwrap();
	std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
	elsewhere
}

#[test]
fn a_file_that_cannot_be_written_leaves_the_stored_key_as_it_was() {
	let install = install_with_panel();
	let config = Config::load(&install.config).unwrap();
	let context = Context {
		path: &install.config,
		config: &config,
		now: NOW,
	};
	let dir = install.data.join("rotate");
	std::fs::create_dir_all(&dir).unwrap();
	let mut secrets = Secrets::open(&dir).unwrap();
	let step = Step::pending(Kind::PanelApiKey, "panel", None);
	let intent = steps::prepare(&context, &step, &mut secrets).unwrap();
	let before = stored(&install, "panel");
	let elsewhere = link_in_its_place(&install);
	let kept = std::fs::read(&elsewhere).unwrap();
	let refusal = steps::apply(&context, &step, &intent, &secrets).expect_err("it was written");
	assert!(refusal.contains("symlink"), "{refusal}");
	// The file comes first: a key rotated here would have a secret that is
	// in no file the panel reads.
	assert_eq!(stored(&install, "panel"), before, "the key was rotated");
	assert_eq!(std::fs::read(&elsewhere).unwrap(), kept);
	assert!(
		std::fs::symlink_metadata(key_file(&install))
			.unwrap()
			.file_type()
			.is_symlink(),
		"the link was replaced"
	);
}

#[test]
fn the_same_step_with_the_file_in_place_writes_it_and_rotates_the_key() {
	let install = install_with_panel();
	let config = Config::load(&install.config).unwrap();
	let context = Context {
		path: &install.config,
		config: &config,
		now: NOW,
	};
	let dir = install.data.join("rotate");
	std::fs::create_dir_all(&dir).unwrap();
	let mut secrets = Secrets::open(&dir).unwrap();
	let step = Step::pending(Kind::PanelApiKey, "panel", None);
	let intent = steps::prepare(&context, &step, &mut secrets).unwrap();
	let before = stored(&install, "panel");
	steps::apply(&context, &step, &intent, &secrets).unwrap();
	assert!(stored(&install, "panel") != before);
	assert!(file_is_the_stored_key(&install));
	assert!(steps::landed(&context, &step, &intent).unwrap());
}
