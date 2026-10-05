//! Plan unit tests.

use std::path::PathBuf;

use super::*;

#[test]
fn plan_step_dkim_ed25519_renders() {
	let step = PlanStep::DkimEd25519 {
		path: PathBuf::from("/var/lib/epistle/keys/s1.pem"),
		reused: false,
	};
	assert_eq!(
		step.to_string(),
		"dkim ed25519 key: generate /var/lib/epistle/keys/s1.pem"
	);
}

#[test]
fn plan_step_dkim_rsa_skipped_text_mentions_dkim_keygen() {
	let step = PlanStep::DkimRsa {
		path: PathBuf::from("/var/lib/epistle/keys/s2.pem"),
		reused: false,
		openssl_available: false,
	};
	let rendered = step.to_string();
	assert!(rendered.contains("dkim-keygen --rsa"), "got {rendered}");
}

#[test]
fn plan_step_config_identical_renders() {
	let step = PlanStep::Config {
		path: PathBuf::from("/etc/mail.toml"),
		identical: true,
		file_exists: true,
		count: 6,
		preserves_comments: false,
	};
	let rendered = step.to_string();
	assert!(rendered.contains("identical"));
}

#[test]
fn plan_step_dns_says_not_implemented() {
	let step = PlanStep::Dns {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
	};
	let rendered = step.to_string();
	assert!(
		rendered.contains("not implemented in this build"),
		"got {rendered}"
	);
}

#[test]
fn plan_write_to_numbered_lines() {
	let plan = Plan {
		steps: vec![
			PlanStep::DkimEd25519 {
				path: PathBuf::from("/s1.pem"),
				reused: true,
			},
			PlanStep::Storage {
				path: PathBuf::from("/storage.key"),
				reused: false,
			},
		],
	};
	let mut out = String::new();
	plan.write_to(&mut out).expect("write");
	assert!(out.contains("1."));
	assert!(out.contains("2."));
	assert!(out.contains("dkim ed25519"));
	assert!(out.contains("storage key"));
}
