//! The DKIM rotation's plan and the task that runs it: when it runs, with
//! what timing, and what it logs.

use tracing::Level;

use super::super::super::super::trace::capture::run_with_capture;
use super::super::DnsWrite;
use super::base::{BASE, parse};
use super::dkim_rotation::{DkimRotationPlan, decide_dkim_rotation};
use crate::config::Config;

/// The plan of a configuration whose rotation writes the records itself.
fn rotation_plan(config: &Config) -> DkimRotationPlan {
	decide_dkim_rotation(config, &DnsWrite::Direct)
}

#[test]
fn rotation_runs_when_dns_is_present_without_rotate_days() {
	// [dkim] + [dns], no rotate_days: rotation runs with the constant
	// interval/overlap and no deprecation flag. The expected values are
	// spelled out in days and converted here so a constant change shows
	// up as a failing test.
	let config = parse(&format!(
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
	assert_eq!(
		rotation_plan(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: false,
			signing_domains: Vec::new(),
			out_of_zone: Vec::new(),
		}
	);
}

#[test]
fn rotation_runs_with_constants_when_legacy_fields_are_set() {
	// The legacy `rotate_days` / `rotate_overlap_days` values are captured
	// for backward compatibility but ignored: the effective timing comes
	// from the constants (not from the file), and the deprecation flag is
	// set. The file deliberately carries different values so a test that
	// leaked the file's values would fail loudly.
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 7
rotate_overlap_days = 3

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert_eq!(
		rotation_plan(&config),
		DkimRotationPlan::Run {
			interval: 90 * 86_400,
			overlap: 14 * 86_400,
			deprecated_fields_present: true,
			signing_domains: Vec::new(),
			out_of_zone: Vec::new(),
		}
	);
}

#[test]
fn rotation_is_off_without_dns_and_logs_inactive_notice() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
"
	));
	assert_eq!(rotation_plan(&config), DkimRotationPlan::Off);

	// The caller (`spawn_dkim_rotation`) must leave a record at startup.
	// We exercise it directly so the log emission is captured.
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	let notice = events
		.iter()
		.find(|e| e.level == Level::INFO)
		.expect("expected an inactivity notice when [dkim] is set but [dns] is not");
	let msg = notice
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("rotation is inactive"),
		"inactive notice must explain why: {msg}"
	);
	assert!(
		msg.contains("[dns]"),
		"inactive notice must point at the missing [dns] section: {msg}"
	);
}

#[test]
fn spawn_dkim_rotation_warns_when_legacy_rotation_fields_are_set() {
	let config = parse(&format!(
		"{BASE}
[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"
rotate_days = 30

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	assert!(!config.dns.is_empty(), "test fixture must include [dns]");

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN)
		.expect("expected a deprecation warning for rotate_days");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("deprecated"),
		"warning must say the field is deprecated: {msg}"
	);
	// The effective values are spelled out so operators can confirm what
	// actually happens without reading the source.
	assert!(
		msg.contains(&format!("every {} days", crate::dkim::ROTATE_INTERVAL_DAYS)),
		"warning must state the effective interval: {msg}"
	);
	assert!(
		msg.contains(&format!("{} day overlap", crate::dkim::ROTATE_OVERLAP_DAYS)),
		"warning must state the effective overlap: {msg}"
	);
	// Structured fields are present too: useful for log search.
	assert_eq!(
		warning.fields.get("interval_days").map(String::as_str),
		Some("90")
	);
	assert_eq!(
		warning.fields.get("overlap_days").map(String::as_str),
		Some("14")
	);
}

#[test]
fn spawn_dkim_rotation_silent_when_legacy_fields_absent_and_dns_present() {
	// No legacy fields, [dns] is present: nothing deprecation-related is
	// logged (the rotation itself does spawn, but its first tick is on the
	// next hour and we don't wait for it here).
	let config = parse(&format!(
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
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	assert!(
		!events.iter().any(|e| e.level == Level::WARN),
		"clean config must not log a deprecation warning: {events:?}"
	);
	assert!(
		!events.iter().any(|e| e.level == Level::INFO),
		"clean config must not log the inactive notice: {events:?}"
	);
}

#[test]
fn rotation_is_off_when_dkim_section_is_absent() {
	// No [dkim]: there is nothing to rotate. This is intentionally silent
	// — the absence of [dkim] is visible from the surrounding config.
	let config = parse(BASE);
	assert_eq!(rotation_plan(&config), DkimRotationPlan::Off);

	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	assert!(
		events.is_empty(),
		"absent [dkim] must not log anything (the operator chose it): {events:?}"
	);
}

#[test]
fn rotation_partitions_domains_into_in_zone_and_out_of_zone() {
	// The decision must compute the set the rotator will publish for and
	// the set the operator has to fix. Both lists are sorted and deduped
	// (the helper builds a BTreeSet under the hood) so the assert can
	// compare exact contents without worrying about iteration order.
	let config = parse(&format!(
		"{BASE}
domains = [\"example.org\", \"mail.example.org\", \"other.example.net\"]
[domain_aliases]
\"alias.example.org\" = \"example.org\"

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let plan = rotation_plan(&config);
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = plan
	else {
		panic!("expected Run, got {plan:?}");
	};
	assert_eq!(
		signing_domains,
		vec![
			"alias.example.org".to_string(),
			"example.org".to_string(),
			"mail.example.org".to_string(),
		],
		"every domain inside the zone must be marked for publication"
	);
	assert_eq!(
		out_of_zone,
		vec!["other.example.net".to_string()],
		"domains outside the zone must be reported separately"
	);
}

#[test]
fn spawn_dkim_rotation_warns_and_skips_when_a_signing_domain_is_out_of_zone() {
	let config = parse(&format!(
		"{BASE}
domains = [\"example.org\", \"other.example.net\"]

[dkim]
selector = \"mail\"
key_file = \"/etc/mail/dkim.pem\"

[dns]
provider = \"cloudflare\"
zone = \"example.org\"
token = \"abc\"
"
	));
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	let warning = events
		.iter()
		.find(|e| e.level == Level::WARN)
		.expect("expected an out-of-zone warning");
	let msg = warning
		.fields
		.get("message")
		.expect("message field")
		.as_str();
	assert!(
		msg.contains("rotation is disabled"),
		"warning must say rotation is disabled: {msg}"
	);
	assert!(
		msg.contains("[dns] zone"),
		"warning must point the operator at the [dns] zone field: {msg}"
	);
	let out_of_zone = warning
		.fields
		.get("out_of_zone")
		.expect("structured out_of_zone field")
		.as_str();
	assert!(
		out_of_zone.contains("other.example.net"),
		"structured field must name the offending domain: {out_of_zone}"
	);
	assert_eq!(
		warning.fields.get("zone").map(String::as_str),
		Some("example.org"),
		"structured field must echo the [dns] zone for context"
	);
}

#[test]
fn spawn_dkim_rotation_skips_silently_when_no_domains_are_configured() {
	// Empty [domains] and no aliases: there is nothing to publish, so the
	// out-of-zone path does not fire either. The startup log stays empty
	// (rotation runs on an empty set without ceremony).
	let config = parse(&format!(
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
	let plan = rotation_plan(&config);
	let DkimRotationPlan::Run {
		signing_domains,
		out_of_zone,
		..
	} = plan
	else {
		panic!("expected Run, got {plan:?}");
	};
	assert!(signing_domains.is_empty());
	assert!(out_of_zone.is_empty());
	let events = run_with_capture(|| {
		super::spawn_dkim_rotation(&config, &None, None, &DnsWrite::Direct);
	});
	assert!(
		!events.iter().any(|e| e.level == Level::WARN),
		"empty domain list must not log an out-of-zone warning: {events:?}"
	);
}
