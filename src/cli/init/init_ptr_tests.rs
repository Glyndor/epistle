//! The reverse-DNS block wired into `init`: printed after a dry-run, built
//! from the addresses that ended up in the answers, never changing the
//! exit code.

use std::cell::Cell;

use super::detect::tests::{Scripted, v4};
use super::tests_detect::dry_run_args;
use super::*;
use crate::cli::status::dns_fake::FakeDns;

fn fake() -> Option<Box<dyn crate::spf::DnsLookup>> {
	Some(Box::new(FakeDns::default()))
}

#[test]
fn dry_run_prints_the_block_and_still_exits_0_with_a_missing_ptr() {
	let dir = tempfile::tempdir().expect("tempdir");
	let probes = Probes {
		detector: &Scripted::found(None, None),
		resolver: &fake,
	};
	let mut out = Vec::new();
	let args = dry_run_args(dir.path(), "public_ipv4 = \"8.8.8.8\"\n");
	let code = run_with(args, &probes, &mut out);
	assert_eq!(
		code,
		ExitCode::from(EXIT_OK),
		"a missing PTR is not a failure"
	);
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		text.ends_with(
			"dry-run: nothing was written\n\
			 reverse DNS (PTR), expected to name mail.example.org:\n  \
			 8.8.8.8: missing; ask your hosting provider to set the PTR of 8.8.8.8 to mail.example.org\n"
		),
		"the block must close the dry-run output: {text}"
	);
	assert!(!dir.path().join("data").exists(), "dry-run wrote data_dir");
}

#[test]
fn a_detected_address_gets_its_ptr_checked_too() {
	let dir = tempfile::tempdir().expect("tempdir");
	let probes = Probes {
		detector: &Scripted::found(Some(v4()), None),
		resolver: &fake,
	};
	let mut out = Vec::new();
	let code = run_with(dry_run_args(dir.path(), ""), &probes, &mut out);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		text.contains("  8.8.8.8: missing; ask your hosting provider"),
		"the detected address must be in the block: {text}"
	);
}

#[test]
fn no_address_prints_no_block_and_builds_no_resolver() {
	let dir = tempfile::tempdir().expect("tempdir");
	let built = Cell::new(false);
	let resolver = || {
		built.set(true);
		fake()
	};
	let probes = Probes {
		detector: &Scripted::found(None, None),
		resolver: &resolver,
	};
	let mut out = Vec::new();
	let code = run_with(dry_run_args(dir.path(), ""), &probes, &mut out);
	assert_eq!(code, ExitCode::from(EXIT_OK));
	let text = String::from_utf8(out).expect("utf-8");
	assert!(
		!text.contains("reverse DNS"),
		"no address, no block: {text}"
	);
	assert!(!built.get(), "the resolver must not be built for nothing");
}
