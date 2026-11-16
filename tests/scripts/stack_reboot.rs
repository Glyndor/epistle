//! `scripts/stack-reboot/stack-reboot.sh` with fakes: no machine is rebooted
//! here. The reboot itself, and the real `podman` and `epistle`, are not
//! exercised; everything the script decides from their output is.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(
	env!("CARGO_MANIFEST_DIR"),
	"/scripts/stack-reboot/stack-reboot.sh"
);

/// Example data only.
const PS_BEFORE: &str = "mail\taaa111\timg1\t2026-01-01 10:00:00\trunning\n\
db\tbbb222\timg2\t2026-01-01 10:00:01\trunning\n";
const IMAGES: &str = "img1\nimg2\n";

fn boot_json(unit: &str, services: &str) -> String {
	format!(
		r#"{{"boot":{{"status":"{}","detail":"x","items":[
		{{"name":"linger","status":"ok","detail":"on"}},
		{{"name":"boot unit","status":"{unit}","detail":"unit state"}},
		{{"name":"services","status":"{services}","detail":"mail is exited with status 1"}}]}}}}"#,
		if unit == "ok" && services == "ok" {
			"ok"
		} else {
			"fail"
		}
	)
}

struct Fx {
	dir: tempfile::TempDir,
}

impl Fx {
	fn new() -> Self {
		let fx = Fx {
			dir: tempfile::tempdir().unwrap(),
		};
		fx.script(
			"epistle",
			r#"#!/bin/sh
n=$(cat "$FX/calls" 2>/dev/null || echo 0); echo $((n+1)) > "$FX/calls"
if [ "$1" = status ]; then cat "$FX/status.json"; exit 0; fi
if [ -f "$FX/ok_after" ] && [ "$n" -lt "$(cat "$FX/ok_after")" ]; then cat "$FX/bad.json"; exit 1; fi
cat "$FX/check.json"
"#,
		);
		fx.script(
			"podman",
			r#"#!/bin/sh
case "$1" in ps) cat "$FX/ps.tsv" ;; images) cat "$FX/images.txt" ;; esac
"#,
		);
		fx.script("reboot", "#!/bin/sh\ntouch \"$FX/rebooted\"\n");
		fx.set("check.json", &boot_json("ok", "ok"));
		fx.set("status.json", &boot_json("ok", "ok"));
		fx.set("bad.json", &boot_json("fail", "fail"));
		fx.set("ps.tsv", PS_BEFORE);
		fx.set("images.txt", IMAGES);
		fx.set("boot_id", "boot-one\n");
		fx.set("marker", "");
		fx
	}

	fn p(&self, name: &str) -> PathBuf {
		self.dir.path().join(name)
	}

	fn set(&self, name: &str, text: &str) {
		fs::write(self.p(name), text).unwrap();
	}

	fn script(&self, name: &str, text: &str) {
		self.set(name, text);
		fs::set_permissions(self.p(name), fs::Permissions::from_mode(0o755)).unwrap();
	}

	fn state(&self) -> PathBuf {
		self.p("state")
	}

	fn run(&self, args: &[&str]) -> Output {
		let path: &Path = self.dir.path();
		Command::new("bash")
			.arg(SCRIPT)
			.args(args)
			.env("FX", path)
			.env("EPISTLE_BIN", self.p("epistle"))
			.env("STACK_REBOOT_PODMAN", self.p("podman"))
			.env("STACK_REBOOT_CMD", self.p("reboot"))
			.env("STACK_REBOOT_STATE", self.state())
			.env("STACK_REBOOT_MARKER", self.p("marker"))
			.env("STACK_REBOOT_BOOT_ID", self.p("boot_id"))
			.env("STACK_REBOOT_INTERVAL", "0")
			.output()
			.unwrap()
	}

	/// Record the state the way a real `before` does, as a started reboot.
	fn recorded(&self) {
		let out = self.run(&["before", "--yes-reboot"]);
		assert!(out.status.success(), "{}", text(&out));
		self.set("boot_id", "boot-two\n");
	}
}

fn text(out: &Output) -> String {
	format!(
		"{}{}",
		String::from_utf8_lossy(&out.stdout),
		String::from_utf8_lossy(&out.stderr)
	)
}

fn code(out: &Output) -> i32 {
	out.status.code().unwrap()
}

#[test]
fn before_refuses_without_the_flag() {
	let fx = Fx::new();
	let out = fx.run(&["before"]);
	assert_eq!(code(&out), 2, "{}", text(&out));
	assert!(text(&out).contains("without --yes-reboot"));
	assert!(!fx.p("rebooted").exists());
	assert!(!fx.state().exists());
}

#[test]
fn before_prints_the_plan_before_it_refuses() {
	let fx = Fx::new();
	let out = fx.run(&["before"]);
	let all = text(&out);
	assert!(all.find("will, on this machine").unwrap() < all.find("refusing").unwrap());
}

#[test]
fn before_refuses_a_machine_not_marked_disposable() {
	let fx = Fx::new();
	fs::remove_file(fx.p("marker")).unwrap();
	let out = fx.run(&["before", "--yes-reboot"]);
	assert_eq!(code(&out), 2, "{}", text(&out));
	assert!(text(&out).contains("not marked disposable"));
	assert!(!fx.p("rebooted").exists());
}

#[test]
fn force_overrides_the_disposable_marker() {
	let fx = Fx::new();
	fs::remove_file(fx.p("marker")).unwrap();
	let out = fx.run(&["before", "--yes-reboot", "--force-not-disposable"]);
	assert_eq!(code(&out), 0, "{}", text(&out));
	assert!(fx.p("rebooted").exists());
}

#[test]
fn dry_run_changes_nothing_and_needs_no_flag() {
	let fx = Fx::new();
	let out = fx.run(&["before", "--dry-run"]);
	assert_eq!(code(&out), 0, "{}", text(&out));
	assert!(text(&out).contains("nothing was rebooted"));
	assert!(!fx.p("rebooted").exists());
	assert!(!fx.state().exists());
}

#[test]
fn before_records_and_reboots() {
	let fx = Fx::new();
	let out = fx.run(&["before", "--yes-reboot"]);
	assert_eq!(code(&out), 0, "{}", text(&out));
	assert!(fx.p("rebooted").exists());
	let mode = fs::metadata(fx.state()).unwrap().permissions().mode() & 0o777;
	assert_eq!(mode, 0o700);
	let tsv = fs::read_to_string(fx.state().join("before/containers.tsv")).unwrap();
	assert!(tsv.lines().all(|line| line.split('\t').count() == 5));
	assert_eq!(
		fs::read_to_string(fx.state().join("before/images.txt")).unwrap(),
		IMAGES
	);
}

#[test]
fn before_refuses_when_the_boot_area_is_not_ok() {
	let fx = Fx::new();
	fx.set("check.json", &boot_json("fail", "ok"));
	let out = fx.run(&["before", "--yes-reboot"]);
	assert_eq!(code(&out), 1, "{}", text(&out));
	assert!(text(&out).contains("boot unit: fail"));
	assert!(!fx.p("rebooted").exists());
}

fn judge(fx: &Fx, json: &str) -> Output {
	fx.set("doc.json", json);
	fx.run(&["judge", fx.p("doc.json").to_str().unwrap()])
}

#[test]
fn judge_passes_an_ok_boot_area() {
	let fx = Fx::new();
	assert_eq!(code(&judge(&fx, &boot_json("ok", "ok"))), 0);
}

#[test]
fn judge_names_the_service_that_is_down() {
	let fx = Fx::new();
	let out = judge(&fx, &boot_json("ok", "warn"));
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("services: warn: mail is exited with status 1"));
}

#[test]
fn judge_names_a_failed_boot_unit() {
	let fx = Fx::new();
	let out = judge(&fx, &boot_json("fail", "ok"));
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("boot unit: fail"));
}

#[test]
fn judge_rejects_a_boot_area_that_judged_nothing() {
	let fx = Fx::new();
	let out = judge(
		&fx,
		r#"{"boot":{"status":"ok","detail":"no stack here","items":[]}}"#,
	);
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("no boot unit item"));
}

#[test]
fn judge_rejects_an_area_that_is_not_ok_whatever_its_items_say() {
	let fx = Fx::new();
	let doc = boot_json("ok", "ok").replace(
		r#""status":"ok","detail":"x""#,
		r#""status":"warn","detail":"x""#,
	);
	let out = judge(&fx, &doc);
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("boot area is warn"));
}

#[test]
fn judge_rejects_a_document_without_the_area() {
	let fx = Fx::new();
	assert_eq!(
		code(&judge(
			&fx,
			r#"{"dns":{"status":"ok","detail":"","items":[]}}"#
		)),
		1
	);
	assert_eq!(code(&judge(&fx, "not json")), 1);
}

fn compare(fx: &Fx, ps_after: &str, images_after: &str) -> Output {
	for (side, ps, images) in [
		("before", PS_BEFORE, IMAGES),
		("after", ps_after, images_after),
	] {
		let dir = fx.p(side);
		fs::create_dir_all(&dir).unwrap();
		fs::write(dir.join("containers.tsv"), ps).unwrap();
		fs::write(dir.join("images.txt"), images).unwrap();
	}
	fx.run(&[
		"compare",
		fx.p("before").to_str().unwrap(),
		fx.p("after").to_str().unwrap(),
	])
}

#[test]
fn compare_passes_an_unchanged_stack() {
	let fx = Fx::new();
	assert_eq!(code(&compare(&fx, PS_BEFORE, IMAGES)), 0);
}

#[test]
fn compare_fails_a_recreated_container() {
	let fx = Fx::new();
	let ps = PS_BEFORE.replace("aaa111", "ccc333");
	let out = compare(&fx, &ps, IMAGES);
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("container mail was recreated"));
}

#[test]
fn compare_fails_a_new_creation_time_with_the_same_id() {
	let fx = Fx::new();
	let ps = PS_BEFORE.replace("2026-01-01 10:00:00", "2026-01-02 09:00:00");
	assert_eq!(code(&compare(&fx, &ps, IMAGES)), 1);
}

#[test]
fn compare_fails_another_image() {
	let fx = Fx::new();
	let ps = PS_BEFORE.replace("img2", "img9");
	let out = compare(&fx, &ps, IMAGES);
	assert!(text(&out).contains("container db runs another image"));
}

#[test]
fn compare_fails_an_image_that_appeared() {
	let fx = Fx::new();
	let out = compare(&fx, PS_BEFORE, "img1\nimg2\nimg3\n");
	assert_eq!(code(&out), 1);
	assert!(text(&out).contains("image img3 appeared"));
}

#[test]
fn compare_fails_a_gone_or_new_container() {
	let fx = Fx::new();
	let gone = compare(
		&fx,
		"mail\taaa111\timg1\t2026-01-01 10:00:00\trunning\n",
		IMAGES,
	);
	assert!(text(&gone).contains("container db is gone"));
	let extra = format!("{PS_BEFORE}x\tddd444\timg1\t2026-01-03 00:00:00\trunning\n");
	assert!(text(&compare(&fx, &extra, IMAGES)).contains("container x did not exist"));
}

#[test]
fn compare_fails_a_container_that_stopped() {
	let fx = Fx::new();
	let ps = PS_BEFORE.replace(
		"img1\t2026-01-01 10:00:00\trunning",
		"img1\t2026-01-01 10:00:00\texited",
	);
	assert!(text(&compare(&fx, &ps, IMAGES)).contains("was running and is exited"));
}

#[test]
fn after_passes_when_the_stack_came_back_untouched() {
	let fx = Fx::new();
	fx.recorded();
	let out = fx.run(&["after", "--wait", "5"]);
	assert_eq!(code(&out), 0, "{}", text(&out));
	assert!(text(&out).contains("RESULT: PASSED"));
	assert!(fx.state().join("report.txt").exists());
}

#[test]
fn after_fails_when_no_reboot_happened() {
	let fx = Fx::new();
	let out = fx.run(&["before", "--yes-reboot"]);
	assert!(out.status.success());
	let out = fx.run(&["after", "--wait", "5"]);
	assert_eq!(code(&out), 1, "{}", text(&out));
	assert!(text(&out).contains("did not reboot"));
}

#[test]
fn after_fails_when_a_container_was_recreated() {
	let fx = Fx::new();
	fx.recorded();
	fx.set("ps.tsv", &PS_BEFORE.replace("bbb222", "eee555"));
	let out = fx.run(&["after", "--wait", "5"]);
	assert_eq!(code(&out), 1, "{}", text(&out));
	assert!(text(&out).contains("container db was recreated"));
}

#[test]
fn after_fails_when_the_boot_area_stays_bad() {
	let fx = Fx::new();
	fx.recorded();
	fx.set("check.json", &boot_json("ok", "fail"));
	let out = fx.run(&["after", "--wait", "0"]);
	assert_eq!(code(&out), 1, "{}", text(&out));
	assert!(text(&out).contains("services: fail"));
}

#[test]
fn after_waits_for_a_service_that_comes_up_late() {
	let fx = Fx::new();
	fx.recorded();
	let seen = fs::read_to_string(fx.p("calls")).unwrap_or_default();
	let start: u32 = seen.trim().parse().unwrap_or(0);
	fx.set("ok_after", &(start + 3).to_string());
	let out = fx.run(&["after", "--wait", "30"]);
	assert_eq!(code(&out), 0, "{}", text(&out));
}

#[test]
fn after_fails_when_status_json_disagrees() {
	let fx = Fx::new();
	fx.recorded();
	fx.set("status.json", &boot_json("ok", "warn"));
	let out = fx.run(&["after", "--wait", "5"]);
	assert_eq!(code(&out), 1, "{}", text(&out));
	assert!(text(&out).contains("status --json"));
}

#[test]
fn after_needs_a_recorded_state() {
	let fx = Fx::new();
	assert_eq!(code(&fx.run(&["after"])), 2);
}

#[test]
fn clean_removes_the_state() {
	let fx = Fx::new();
	fx.recorded();
	assert_eq!(code(&fx.run(&["clean"])), 0);
	assert!(!fx.state().exists());
}
