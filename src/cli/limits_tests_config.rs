use std::io::{Seek, Write};

use super::*;

pub(super) fn config_file() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir_in(".").unwrap();
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\nlog_format = \"json\"\nsrs_secret = \"${{USER}}\"\n[antispam]\nclamd_timeout_secs = 45",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	(dir, file)
}

#[test]
fn limits_set_unset_round_trip_preserves_every_other_key() {
	let (_dir, file) = config_file();
	let original: toml::Value =
		toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
	for (key, input, expected) in [
		(Key::Quota, "7G", 7 * 1024 * 1024 * 1024),
		(Key::SubmissionRate, "120", 120),
		(Key::NewRecipientsPerDay, "400", 400),
		(Key::QueueGiveUp, "12h", 43200),
		(Key::InboundRatePerIp, "25", 25),
		(Key::InboundRatePerSender, "80", 80),
		(Key::MaxConnectionsPerListener, "200", 200),
		(Key::MaskedAddressesMax, "30", 30),
		(Key::FirstTimeSenderDelay, "10s", 10),
		(Key::GreylistDelay, "3m", 180),
	] {
		let result = change_config(file.path(), key, Some(input));
		assert!(
			result.is_ok(),
			"limits set must save the numeric value in the existing config"
		);
		let mut edited: toml::Value =
			toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
		assert_eq!(
			edited[key.field()].as_integer(),
			Some(expected),
			"limits set must write the mapped config field"
		);
		edited.as_table_mut().unwrap().remove(key.field());
		assert!(
			edited == original,
			"limits set must preserve unrelated keys and environment placeholders"
		);
		assert!(
			change_config(file.path(), key, None).is_ok(),
			"limits unset must remove the configured override"
		);
		let restored: toml::Value =
			toml::from_str(&std::fs::read_to_string(file.path()).unwrap()).unwrap();
		assert!(
			restored == original,
			"limits unset must restore the original config values"
		);
	}
}

#[test]
fn limits_invalid_values_leave_config_bytes_untouched() {
	let (_dir, file) = config_file();
	let original = std::fs::read(file.path()).unwrap();
	for (key, input) in [
		(Key::Quota, "1.5G"),
		(Key::SubmissionRate, "4294967296"),
		(Key::QueueGiveUp, "-5d"),
		(Key::MaskedAddressesMax, "9223372036854775808"),
	] {
		assert_eq!(
			change_config(file.path(), key, Some(input)).err(),
			Some(format!(
				"{}: expected a non-negative integer with a supported suffix within the field range",
				key.name()
			)),
			"limits must report the rejected key and the allowed numeric shape"
		);
		assert!(
			std::fs::read(file.path()).unwrap() == original,
			"invalid limits must leave the file byte-for-byte untouched"
		);
	}
}

#[test]
fn limits_candidate_validation_preserves_invalid_config() {
	let (_dir, mut file) = config_file();
	let text = std::fs::read_to_string(file.path())
		.unwrap()
		.replace("mail.example.org", "bad hostname");
	file.as_file_mut().set_len(0).unwrap();
	file.as_file_mut().rewind().unwrap();
	file.write_all(text.as_bytes()).unwrap();
	let result = change_config(file.path(), Key::Quota, Some("7G"));
	assert!(
		result
			.err()
			.is_some_and(|message| message.contains("hostname")),
		"limits must validate the complete candidate before replacing the config"
	);
	assert!(
		std::fs::read_to_string(file.path()).unwrap() == text,
		"failed candidate validation must preserve the original file bytes"
	);
	assert_eq!(
		std::fs::read_dir(file.path().parent().unwrap())
			.unwrap()
			.count(),
		1,
		"failed validation must remove its staging file"
	);
}

#[test]
fn limits_show_marks_effective_defaults_and_configured_values() {
	let (_dir, file) = config_file();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	assert_eq!(
		String::from_utf8(out).unwrap(),
		"quota\t5368709120 bytes\tdefault\nsubmission-rate\tdisabled\tdefault\nnew-recipients-per-day\tdisabled\tdefault\nqueue-give-up\t432000 seconds\tdefault\ninbound-rate-per-ip\tdisabled\tdefault\ninbound-rate-per-sender\tdisabled\tdefault\nmax-connections-per-listener\tprotocol defaults\tdefault\nmasked-addresses-max\t100\tdefault\nfirst-time-sender-delay\t0 seconds\tdefault\ngreylist-delay\t0 seconds\tdefault\n",
		"limits show must print each effective value and mark built-in defaults"
	);
	change_config(file.path(), Key::SubmissionRate, Some("120")).unwrap();
	let config = Config::load(file.path()).unwrap();
	let mut out = Vec::new();
	show(&config, &mut out).unwrap();
	assert!(
		String::from_utf8(out)
			.unwrap()
			.lines()
			.any(|line| line == "submission-rate\t120\tconfigured"),
		"limits show must mark a changed value as configured"
	);
}
