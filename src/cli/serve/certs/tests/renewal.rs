//! What the certificates role renews with, and where it keeps it.

use super::*;

fn job(dir: &std::path::Path) -> RenewalJob {
	let config = config(dir, Some("dns-01"), true);
	let acme = requirements(&config).expect("requirements").clone();
	let provider = config
		.dns
		.build_for_host(&config.hostname)
		.expect("provider from the token file");
	renewal(
		&config,
		&acme,
		Arc::new(crate::acme::http01::ChallengeStore::new()),
		(provider, config.hostname.clone()),
	)
}

/// `mail` mounts data_dir read-write: a key kept there would be readable by
/// the process that takes SMTP from the internet.
#[test]
fn the_account_key_is_read_outside_data_dir() {
	let dir = tempfile::tempdir().expect("directory");
	let job = job(dir.path());
	let data_dir = dir.path().join("data");
	assert!(
		!job.account_key.starts_with(&data_dir),
		"{} is under {}",
		job.account_key.display(),
		data_dir.display()
	);
	assert_eq!(
		job.account_key,
		crate::cli::init::host_secrets::acme_account_key(&data_dir)
	);
	assert_ne!(
		job.account_key,
		crate::acme::renew::account_key_path(&data_dir)
	);
}

/// Nothing is served from this process, so a new pair only lands on disk,
/// where `mail` picks it up.
#[test]
fn the_pair_is_written_to_data_dir_and_no_acceptor_is_reloaded() {
	let dir = tempfile::tempdir().expect("directory");
	let job = job(dir.path());
	assert!(job.reloadable.is_none());
	assert_eq!(job.data_dir, dir.path().join("data"));
	assert_eq!(job.renew_before_days, 30);
	assert_eq!(job.domains, ["mail.example.org"]);
}

#[test]
fn the_tlsa_record_follows_the_certificate_from_this_role() {
	let dir = tempfile::tempdir().expect("directory");
	let job = job(dir.path());
	let (_, hostname) = job.tlsa.as_ref().expect("TLSA publisher");
	assert_eq!(hostname, "mail.example.org");
}
