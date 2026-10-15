use super::*;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const LARGEST: u64 = 25 * MIB;

/// A fake `/proc/self/cgroup` naming `cgroup`, and a fake cgroup mount.
fn fake_cgroup(cgroup: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let proc = dir.path().join("cgroup");
	std::fs::write(&proc, format!("0::{cgroup}\n")).expect("proc");
	let root = dir.path().join("sys-fs-cgroup");
	std::fs::create_dir_all(&root).expect("root");
	(dir, proc, root)
}

fn set_max(root: &Path, cgroup: &str, value: &str) {
	let level = root.join(cgroup.trim_start_matches('/'));
	std::fs::create_dir_all(&level).expect("level");
	std::fs::write(level.join("memory.max"), format!("{value}\n")).expect("memory.max");
}

fn limit(bytes: u64, source: LimitSource) -> ContainerLimit {
	ContainerLimit { bytes, source }
}

#[test]
fn memory_sizes_read_as_compose_writes_them() {
	assert_eq!(parse_memory("2g"), Some(2 * GIB));
	assert_eq!(parse_memory("2G"), Some(2 * GIB));
	assert_eq!(parse_memory("512m"), Some(512 * MIB));
	assert_eq!(parse_memory("1024k"), Some(MIB));
	for refused in [
		"",
		"g",
		"0g",
		"1.5g",
		"2",
		"2gb",
		"-1g",
		"99999999999999999999g",
	] {
		assert_eq!(parse_memory(refused), None, "{refused:?}");
	}
}

#[test]
fn a_cgroup_number_is_the_limit() {
	let (_dir, proc, root) = fake_cgroup("/");
	set_max(&root, "/", "2147483648");
	assert_eq!(read_cgroup_limit(&proc, &root), Some(2 * GIB));
}

#[test]
fn a_cgroup_set_to_max_or_missing_has_no_limit() {
	let (_dir, proc, root) = fake_cgroup("/system.slice/epistle.service");
	assert_eq!(read_cgroup_limit(&proc, &root), None, "no memory.max");
	set_max(&root, "/system.slice/epistle.service", "max");
	set_max(&root, "/system.slice", "max");
	assert_eq!(read_cgroup_limit(&proc, &root), None, "max at every level");
	assert_eq!(
		read_cgroup_limit(&root.join("absent"), &root),
		None,
		"no /proc/self/cgroup"
	);
}

#[test]
fn the_lowest_limit_on_the_way_to_the_root_wins() {
	let (_dir, proc, root) = fake_cgroup("/system.slice/epistle.service");
	set_max(&root, "/system.slice/epistle.service", "max");
	set_max(&root, "/system.slice", "1073741824");
	assert_eq!(read_cgroup_limit(&proc, &root), Some(GIB));
	set_max(&root, "/system.slice/epistle.service", "2147483648");
	assert_eq!(
		read_cgroup_limit(&proc, &root),
		Some(GIB),
		"a parent below the process's own limit"
	);
	set_max(&root, "/system.slice/epistle.service", "536870912");
	assert_eq!(read_cgroup_limit(&proc, &root), Some(512 * MIB));
}

#[test]
fn a_cgroup_v1_line_or_a_path_that_climbs_is_not_followed() {
	let (dir, proc, root) = fake_cgroup("/../outside");
	std::fs::create_dir_all(dir.path().join("outside")).expect("outside");
	std::fs::write(dir.path().join("outside/memory.max"), "1024\n").expect("outside");
	assert_eq!(read_cgroup_limit(&proc, &root), None, "`..` is not walked");
	std::fs::write(&proc, "4:memory:/docker/abc\n").expect("v1");
	set_max(&root, "/docker/abc", "1024");
	assert_eq!(
		read_cgroup_limit(&proc, &root),
		None,
		"only the 0:: line counts"
	);
}

#[test]
fn a_deep_cgroup_path_is_walked_a_bounded_number_of_levels() {
	let (_dir, proc, root) = fake_cgroup("/");
	set_max(&root, "/", "1073741824");
	std::fs::write(&proc, format!("0::{}\n", "/a".repeat(1000))).expect("proc");
	assert_eq!(
		read_cgroup_limit(&proc, &root),
		None,
		"a path deeper than the walk is not followed to the root's limit"
	);
	std::fs::write(&proc, format!("0::{}\n", "/a".repeat(100_000))).expect("proc");
	let started = std::time::Instant::now();
	assert_eq!(read_cgroup_limit(&proc, &root), None);
	assert!(started.elapsed() < std::time::Duration::from_secs(5));
}

#[test]
fn the_compose_file_gives_the_mail_limit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let compose = dir.path().join("compose.yaml");
	assert_eq!(read_compose_limit(&compose), None, "missing");
	std::fs::write(&compose, r#"{"services":{"mail":{"mem_limit":"2g"}}}"#).expect("write");
	assert_eq!(read_compose_limit(&compose), Some(2 * GIB));
	std::fs::write(&compose, r#"{"services":{"mail":{}}}"#).expect("write");
	assert_eq!(read_compose_limit(&compose), None, "no mem_limit");
	std::fs::write(&compose, "services: [").expect("write");
	assert_eq!(read_compose_limit(&compose), None, "not JSON");
}

#[test]
fn the_cgroup_wins_then_the_compose_file_then_the_fallback() {
	let (dir, proc, root) = fake_cgroup("/");
	let compose = dir.path().join("compose.yaml");
	let paths = LimitPaths {
		proc_self_cgroup: proc,
		cgroup_root: root.clone(),
		compose: compose.clone(),
	};
	assert_eq!(container_limit(&paths), ContainerLimit::fallback());
	std::fs::write(&compose, r#"{"services":{"mail":{"mem_limit":"2g"}}}"#).expect("write");
	assert_eq!(
		container_limit(&paths),
		limit(2 * GIB, LimitSource::Compose)
	);
	set_max(&root, "/", "3221225472");
	assert_eq!(container_limit(&paths), limit(3 * GIB, LimitSource::Cgroup));
}

#[test]
fn the_derived_budget_is_a_fifth_of_the_limit_within_its_clamps() {
	assert_eq!(derive(GIB, LARGEST), 204 * MIB, "rounded down to whole MiB");
	assert_eq!(derive(2 * GIB, LARGEST), 409 * MIB);
	assert_eq!(derive(5 * GIB, LARGEST), GIB);
	assert_eq!(derive(8 * GIB, LARGEST), GIB, "at most 1 GiB");
	assert_eq!(derive(64 * MIB, LARGEST), LARGEST, "at least one message");
	assert_eq!(derive(0, LARGEST), LARGEST);
}

#[test]
fn a_configured_budget_is_kept_and_an_unset_one_is_derived() {
	let two = limit(2 * GIB, LimitSource::Cgroup);
	assert_eq!(
		effective(Some(100 * MIB), LARGEST, two),
		Budget {
			bytes: 100 * MIB,
			derived: false,
			limit: two
		}
	);
	assert_eq!(
		effective(None, LARGEST, two),
		Budget {
			bytes: 409 * MIB,
			derived: true,
			limit: two
		}
	);
	assert_eq!(effective(Some(0), LARGEST, two).bytes, 0, "0 is no cap");
}

#[test]
fn a_configured_budget_over_seventy_percent_of_the_limit_warns() {
	let two = limit(2 * GIB, LimitSource::Cgroup);
	assert_eq!(
		warning(&effective(Some(512 * MIB), LARGEST, two)).as_deref(),
		Some(
			"message_memory_budget is 512 MiB: a full budget takes about 3 times that \
			 (1536 MiB) while the messages arrive, more than 70% of the 2048 MiB the mail \
			 container may use (cgroup memory.max); lower message_memory_budget or give the \
			 mail container more memory"
		)
	);
	assert_eq!(warning(&effective(Some(256 * MIB), LARGEST, two)), None);
	assert_eq!(warning(&effective(Some(0), LARGEST, two)), None, "no cap");
}

#[test]
fn exactly_seventy_percent_does_not_warn() {
	// 3 x 70 MiB = 210 MiB is exactly 70% of 300 MiB.
	let limit = limit(300 * MIB, LimitSource::Compose);
	assert_eq!(warning(&effective(Some(70 * MIB), MIB, limit)), None);
	assert!(warning(&effective(Some(70 * MIB + 1), MIB, limit)).is_some());
}

#[test]
fn a_derived_budget_warns_only_when_the_largest_message_raised_it() {
	assert_eq!(
		warning(&effective(
			None,
			LARGEST,
			limit(2 * GIB, LimitSource::Cgroup)
		)),
		None
	);
	assert_eq!(
		warning(&effective(
			None,
			LARGEST,
			limit(64 * MIB, LimitSource::Compose)
		))
		.as_deref(),
		Some(
			"max_message_size raised the message memory budget to 25 MiB: a full budget takes \
			 about 3 times that (75 MiB) while the messages arrive, more than 70% of the 64 MiB \
			 the mail container may use (mem_limit in compose.yaml); lower max_message_size or \
			 give the mail container more memory"
		)
	);
}
