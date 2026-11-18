//! The panel answer is a key operators set, so the template and the CLI guide
//! have to name it, and the guide has to name the file the choice is kept in.

use crate::cli::init::Answers;

const CLI_GUIDE: &str = include_str!("../../../../../../docs/cli.md");

#[test]
fn the_answers_template_names_the_panel_key() {
	assert!(
		Answers::template().contains("# panel = false"),
		"the template must show how to decline the panel"
	);
}

#[test]
fn the_cli_guide_names_the_key_the_file_and_the_compose_marker() {
	for needle in [
		"`services.panel`",
		"/usr/share/glyndor/epistle-panel/image",
		"`x-epistle-panel`",
		super::REPOSITORY,
	] {
		assert!(
			CLI_GUIDE.contains(needle),
			"docs/cli.md does not name {needle}"
		);
	}
}
