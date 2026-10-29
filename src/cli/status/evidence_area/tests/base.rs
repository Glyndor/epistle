use super::*;

fn write(root: &Path, status: &Status) {
	std::fs::create_dir_all(root).expect("dir");
	std::fs::write(
		root.join("status.json"),
		serde_json::to_vec(status).expect("json"),
	)
	.expect("write");
}

#[test]
fn a_held_gate_fails_the_area_and_says_why_and_what_to_do() {
	let dir = tempfile::tempdir().expect("tempdir");
	write(
		dir.path(),
		&Status {
			time: 100,
			held: Some("2026-10-14 line 2: record does not chain\u{1b}[31m".into()),
			..Status::default()
		},
	);
	let report = evaluate(dir.path(), 200);
	assert_eq!(report.status, Level::Fail);
	assert_eq!(
		report.detail,
		"the evidence does not verify: transactional mail is held"
	);
	assert!(
		report.items[0]
			.detail
			.contains("epistle evidence acknowledge")
	);
	assert!(
		!report.items[0].detail.contains('\u{1b}'),
		"terminal escapes reached the output"
	);
}

#[test]
fn a_healthy_status_is_ok_and_a_stale_one_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	write(
		dir.path(),
		&Status {
			time: 1000,
			days: 3,
			records: 40,
			stamped: 3,
			..Status::default()
		},
	);
	let report = evaluate(dir.path(), 1100);
	assert_eq!(report.status, Level::Ok);
	assert_eq!(
		report.detail,
		"3 days, 40 records verified in 0 s; 3 days timestamped"
	);
	assert_eq!(evaluate(dir.path(), 1000 + 7200).status, Level::Warn);
}

#[test]
fn no_status_yet_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	assert_eq!(evaluate(dir.path(), 1).status, Level::Warn);
}

#[test]
fn disabled_timestamps_warn() {
	let dir = tempfile::tempdir().expect("tempdir");
	write(
		dir.path(),
		&Status {
			time: 1000,
			..Status::default()
		},
	);
	assert_eq!(evaluate(dir.path(), 1000).status, Level::Ok);
	let settings = crate::evidence::tsa::settings::Settings {
		enabled: false,
		authorities: Vec::new(),
	};
	crate::evidence::tsa::settings::save(dir.path(), &settings).expect("save");
	let report = evaluate(dir.path(), 1000);
	assert_eq!(report.status, Level::Warn);
	assert!(
		report
			.items
			.iter()
			.any(|item| item.detail.contains("disabled"))
	);
}

#[test]
fn a_verification_past_half_the_time_it_is_given_warns_before_the_gate_closes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let limit = u64::try_from(crate::evidence::tasks::AUDIT_TIMEOUT.as_millis()).expect("ms");
	let at = |millis: u64| {
		write(
			dir.path(),
			&Status {
				time: 1000,
				days: 3,
				records: 40,
				audit_millis: millis,
				..Status::default()
			},
		);
		evaluate(dir.path(), 1100)
	};
	assert_eq!(at(limit / 2 - 1).status, Level::Ok);
	let slow = at(limit / 2);
	assert_eq!(slow.status, Level::Warn);
	let item = slow
		.items
		.iter()
		.find(|item| item.name == "verification time")
		.expect("the slow verification is named");
	assert!(
		item.detail.contains("300 s of the 600 s"),
		"{}",
		item.detail
	);
	assert!(slow.detail.contains("in 300 s"), "{}", slow.detail);
}
