use super::read;

#[test]
fn operator_docs_show_the_packaged_service_sequence() {
	let readme = read("README.md");
	let cli = read("docs/cli.md");
	for text in [&readme, &cli] {
		for command in [
			"sudo apt install epistle",
			"sudo epistle init",
			"sudo epistle stack up",
			"sudo epistle stack ps",
		] {
			assert!(
				text.contains(command),
				"operator docs must show the packaged service sequence"
			);
		}
	}
	for topic in [
		"loginctl enable-linger glyndor-epistle",
		"compose.override.yaml",
		"sudo epistle stack update",
		"autostart",
	] {
		assert!(
			cli.contains(topic),
			"CLI docs must explain persistent operation and upgrades"
		);
	}
}
