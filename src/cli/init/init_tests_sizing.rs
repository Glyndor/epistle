//! `epistle init` sizes the containers from the host's memory before it
//! plans anything.

use super::detect::tests::Scripted;
use super::tests_detect::dry_run_args;
use super::*;

#[test]
fn init_reports_the_limits_it_picked_for_the_host() {
	let dir = tempfile::tempdir().expect("tempdir");
	let meminfo = dir.path().join("meminfo");
	std::fs::write(&meminfo, "MemTotal:       16777216 kB\n").expect("meminfo");
	let probes = Probes {
		detector: &Scripted::found(None, None),
		resolver: &|| None,
		meminfo: &meminfo,
		clock: &|| crate::clock::sync::HostClock::Synced,
	};
	let mut out = Vec::new();
	let code = run_with(
		dry_run_args(
			dir.path(),
			"public_ipv4 = \"none\"\npublic_ipv6 = \"none\"\n",
		),
		&probes,
		&mut out,
	);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let text = String::from_utf8(out).expect("utf8");
	assert!(
		text.lines().any(|line| line
			== "container memory for a host with 16.0 GiB: mail 2g, clamav 2g, freshclam 1g"),
		"{text}"
	);
}
