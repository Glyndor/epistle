use super::*;

fn parse(extra: &str) -> Result<Config, ConfigError> {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("config file");
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n{extra}"
	)
	.expect("write config");
	Config::load(file.path())
}

#[test]
fn an_absent_section_flags_so_an_upgrade_changes_nothing_silently() {
	let config = parse("").expect("loads");
	assert_eq!(config.attachments.mode, AttachmentMode::Flag);
	assert_eq!(config.attachments.macros, ContentAction::Flag);
	assert_eq!(config.attachments.encrypted_archives, ContentAction::Flag);
	assert!(config.attachments.block_extensions.is_empty());
}

#[test]
fn every_key_is_read() {
	let config = parse(
		"[attachments]\nmode = \"reject\"\nblock_extensions = [\".DOCM\"]\n\
		 allow_extensions = [\"iso\"]\nmacros = \"allow\"\nencrypted_archives = \"quarantine\"",
	)
	.expect("loads");
	let section = &config.attachments;
	assert_eq!(section.mode, AttachmentMode::Reject);
	assert_eq!(section.block_extensions, vec![".DOCM"]);
	assert_eq!(section.allow_extensions, vec!["iso"]);
	assert_eq!(section.macros, ContentAction::Allow);
	assert_eq!(section.encrypted_archives, ContentAction::Quarantine);
	assert_eq!(normalise_extension(" .DOCM"), "docm");
}

#[test]
fn bad_extensions_and_contradictions_are_refused() {
	for (extra, expected) in [
		("block_extensions = [\"a/b\"]", "is not an extension"),
		("block_extensions = [\"\"]", "is not an extension"),
		(
			"allow_extensions = [\"x\\u001b[2J\"]",
			"is not an extension",
		),
		(
			"block_extensions = [\"js\"]\nallow_extensions = [\".JS\"]",
			"js is in both",
		),
	] {
		let error = parse(&format!("[attachments]\n{extra}"))
			.err()
			.map(|error| error.to_string())
			.expect("must be refused");
		assert!(error.contains(expected), "{extra}: {error}");
		assert!(
			!error.contains('\u{1b}'),
			"an escape character reached the message"
		);
	}
	let many: Vec<String> = (0..300).map(|i| format!("\"e{i}\"")).collect();
	let error = parse(&format!(
		"[attachments]\nblock_extensions = [{}]",
		many.join(",")
	))
	.err()
	.map(|error| error.to_string())
	.expect("too many");
	assert!(error.contains("more than 256"), "{error}");
}

#[test]
fn unknown_keys_and_values_are_refused() {
	assert!(parse("[attachments]\nmode = \"delete\"").is_err());
	assert!(parse("[attachments]\nmacro = \"allow\"").is_err());
}
