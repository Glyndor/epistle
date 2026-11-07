//! The rotation with the certificates container on: it keeps running and
//! publishes through the hand-off the other container serves.

use tracing::Level;

use super::super::DnsWrite;
use super::dkim_rotation::DkimRotationPlan;

/// The rotation's plan where the rotation runs.
const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

/// With the certificates container on the rotation still runs: it
/// publishes through the hand-off the other container serves, and says so.
#[test]
fn with_the_split_the_rotation_publishes_through_the_hand_off() {
	let config = super::base::parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let events = super::super::super::super::trace::capture::run_with_capture(|| {
		super::super::spawn_dkim_rotation(
			&config,
			&None,
			None,
			&DnsWrite::Handoff(std::path::PathBuf::from("/var/lib/mail/dns-handoff")),
		);
	});
	let notice = events
		.iter()
		.find(|e| e.level == Level::INFO)
		.expect("the rotation says where it publishes");
	let msg = notice
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("certificates container"),
		"the notice names the other container: {msg}"
	);
}

/// The plan of the rotation is the same with and without the split: the
/// domains it signs for do not change because of who writes the records.
#[test]
fn the_plan_does_not_depend_on_who_writes_the_records() {
	let config = super::base::parse(&format!(
		"{BASE}
domains = [\"example.org\"]
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let direct = super::super::dkim_rotation::decide_dkim_rotation(&config, &DnsWrite::Direct);
	let handoff = super::super::dkim_rotation::decide_dkim_rotation(
		&config,
		&DnsWrite::Handoff(std::path::PathBuf::from("/var/lib/mail/dns-handoff")),
	);
	assert_eq!(direct, handoff);
	let DkimRotationPlan::Run {
		signing_domains, ..
	} = handoff
	else {
		panic!("rotation should run");
	};
	assert_eq!(signing_domains, vec!["example.org"]);
}
