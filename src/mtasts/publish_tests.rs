use super::*;
use crate::config::MtaStsMode;
use crate::mtasts::{Mode, policy};

fn config() -> Config {
	toml::from_str(
		"hostname = 'mail.example.org'\ndata_dir = '/unused'\ndomains = ['example.org']\n",
	)
	.expect("config")
}

#[test]
fn writer_produces_parseable_public_policy_atomically() {
	use std::io::Write;
	let dir = tempfile::tempdir().expect("tempdir");
	let policy_dir = dir.path().join("policy");
	let mut file = tempfile::NamedTempFile::new_in(dir.path()).expect("config file");
	writeln!(file, "hostname = 'mail.example.org'\ndata_dir = '{}'\n[mta_sts]\npolicy_dir = '{}'\nmode = 'enforce'\nmax_age = 12345", dir.path().display(), policy_dir.display()).expect("config contents");
	let configured = Config::load(file.path()).expect("validated configuration");
	write_policy(&configured).expect("publish configured policy");
	let path = policy_dir.join("mta-sts.txt");
	let mut previous = fs::File::open(&path).expect("published file");
	let content = fs::read_to_string(&path).expect("policy");
	let parsed = policy::parse(&content).expect("valid generated policy");
	assert_eq!(parsed.mode, Mode::Enforce);
	assert_eq!(parsed.mx, ["mail.example.org"]);
	assert_eq!(parsed.max_age, 12345);
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		assert_eq!(
			fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
			0o644
		);
	}
	let mut replacement = config();
	replacement.mta_sts.policy_dir = Some(policy_dir.clone());
	write_policy(&replacement).expect("replace policy");
	let mut old_bytes = String::new();
	std::io::Read::read_to_string(&mut previous, &mut old_bytes).expect("old inode");
	assert_eq!(
		old_bytes, content,
		"replacement must preserve the previous inode"
	);
	assert_eq!(
		fs::read_to_string(path).expect("new policy"),
		publication(&replacement).content
	);
	assert_eq!(fs::read_dir(policy_dir).expect("directory").count(), 1);
}

#[test]
fn policy_defaults_and_dns_identifier_track_content() {
	let config = config();
	let first = publication(&config);
	let parsed = policy::parse(&first.content).expect("default policy parses");
	assert_eq!(parsed.mode, Mode::Testing);
	assert_eq!(parsed.max_age, 604800);
	assert!(config.mta_sts.policy_dir.is_none());
	assert_eq!(first.id.len(), 32);
	assert!(first.id.bytes().all(|byte| byte.is_ascii_hexdigit()));
	assert_eq!(first.id, publication(&config).id);
	assert_eq!(first.id, crate::dns::records::mta_sts_id(&config));
	let mut changed = config.clone();
	changed.mta_sts.mode = MtaStsMode::Enforce;
	assert_ne!(first.id, publication(&changed).id);
	assert_ne!(first.id, crate::dns::records::mta_sts_id(&changed));
	let mode_id = publication(&changed).id;
	changed.mta_sts.max_age += 1;
	assert_ne!(mode_id, publication(&changed).id);
	let age_id = publication(&changed).id;
	changed.hostname = "mx.example.org".into();
	assert_ne!(age_id, publication(&changed).id);
}
