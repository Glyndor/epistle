//! `epistle stack logs` against a stub `podup` that serves canned logs: the
//! default tail, the options, the time-ordered merge of two services and the
//! cut of a long line. The helpers are shared from `stack_podup_helpers.rs`.

#[cfg(unix)]
#[path = "stack_podup_helpers.rs"]
mod helpers;

#[cfg(unix)]
mod cases {
	use super::helpers::{
		data_dir_with_compose, install_podup_shim, read_argv_log, run_with_podup, write_config,
	};
	use std::path::{Path, PathBuf};

	/// A stub `podup`: `ps --all-services` names `mail` and `db`; `logs` prints
	/// the last `-n` lines of `<logs>/<service>.txt` the way podup does, with
	/// the container name first and the time only when `-t` is given. Every
	/// call is written to the argv log on one line.
	fn shim(argv_log: &Path, logs: &Path) -> String {
		format!(
			"#!/bin/sh\n\
			 echo \"$*\" >> {argv_log}\n\
			 if [ \"$1\" = \"--version\" ]; then\n\
			 \tprintf '\\npodup version v5.19.0\\n\\n'\n\
			 \texit 0\n\
			 fi\n\
			 while [ \"$1\" = \"-f\" ]; do shift 2; done\n\
			 if [ \"$1\" = \"ps\" ]; then printf 'mail\\ndb\\n'; exit 0; fi\n\
			 shift\n\
			 stamps=0; count=100; service=\n\
			 while [ $# -gt 0 ]; do\n\
			 \tcase \"$1\" in\n\
			 \t\t-t) stamps=1 ;;\n\
			 \t\t-n) count=$2; shift ;;\n\
			 \t\t--since|--until) shift ;;\n\
			 \t\t--follow) ;;\n\
			 \t\t*) service=$1 ;;\n\
			 \tesac\n\
			 \tshift\n\
			 done\n\
			 file={logs}/$service.txt\n\
			 [ -f \"$file\" ] || {{ echo \"no such service: $service\" >&2; exit 7; }}\n\
			 if [ \"$count\" = all ]; then cat \"$file\"; else tail -n \"$count\" \"$file\"; fi |\n\
			 \tif [ $stamps = 1 ]; then sed \"s/^/$service-1 | /\"; else sed \"s/^[^ ]* //; s/^/$service-1 | /\"; fi\n",
			argv_log = argv_log.display(),
			logs = logs.display()
		)
	}

	/// One log line `second` seconds after ten o'clock on a fixed day.
	fn at(second: u32, text: &str) -> String {
		format!(
			"2026-01-01T10:{:02}:{:02}Z {text}\n",
			second / 60,
			second % 60
		)
	}

	struct Fixture {
		_dir: tempfile::TempDir,
		shim_dir: PathBuf,
		argv_log: PathBuf,
		config: PathBuf,
	}

	/// A data dir, a stub `podup` and the canned logs of `mail` and `db`.
	fn fixture(mail: &str, db: &str) -> Fixture {
		let dir = tempfile::tempdir().expect("tempdir");
		let shim_dir = dir.path().join("bin");
		let argv_log = dir.path().join("argv.log");
		let logs = dir.path().join("canned");
		std::fs::create_dir_all(&logs).expect("canned dir");
		std::fs::write(logs.join("mail.txt"), mail).expect("mail log");
		std::fs::write(logs.join("db.txt"), db).expect("db log");
		install_podup_shim(&shim_dir, &shim(&argv_log, &logs));
		let data_dir = data_dir_with_compose(dir.path());
		let config = write_config(&data_dir);
		Fixture {
			_dir: dir,
			shim_dir,
			argv_log,
			config,
		}
	}

	impl Fixture {
		fn logs(&self, extra: &[&str]) -> (std::process::Output, Vec<String>) {
			let mut args = vec!["stack", "--config", self.config.to_str().unwrap(), "logs"];
			args.extend_from_slice(extra);
			let output = run_with_podup(&args, &self.shim_dir);
			let calls = read_argv_log(&self.argv_log)
				.into_iter()
				.filter(|call| !call.starts_with("--version"))
				// Drop `-f <compose>` so the cases read the verb and flags.
				.map(|call| match call.strip_prefix("-f ") {
					Some(rest) => rest
						.split_once(' ')
						.map_or(String::new(), |(_, words)| words.to_string()),
					None => call,
				})
				.collect();
			(output, calls)
		}
	}

	fn stdout(output: &std::process::Output) -> String {
		String::from_utf8_lossy(&output.stdout).into_owned()
	}

	fn lines(prefix: &str, count: u32, step: u32) -> String {
		(0..count)
			.map(|n| at(n * step, &format!("{prefix} {n}")))
			.collect()
	}

	#[test]
	fn the_default_is_the_last_two_hundred_lines_of_each_service() {
		let fixture = fixture(&lines("mail line", 250, 1), &lines("db line", 3, 1));
		let (output, calls) = fixture.logs(&[]);
		assert!(output.status.success(), "{:?}", output.stderr);
		assert_eq!(calls[0], "ps --all-services");
		assert_eq!(calls[1], "logs -t -n 200 mail");
		assert_eq!(calls[2], "logs -t -n 200 db");
		let text = stdout(&output);
		assert_eq!(text.lines().count(), 203, "200 from mail and 3 from db");
		assert!(text.contains("mail-1 | 2026-01-01T10:00:50Z mail line 50\n"));
		assert!(
			!text.contains("mail line 49\n"),
			"the first fifty are left out"
		);
	}

	#[test]
	fn tail_all_since_and_until_reach_podup() {
		let fixture = fixture(&lines("m", 5, 1), &lines("d", 5, 1));
		let (_, calls) = fixture.logs(&["--tail", "3", "mail"]);
		assert_eq!(calls, ["logs -n 3 mail"]);
		let (_, calls) = fixture.logs(&[
			"--all",
			"--since",
			"10m",
			"--until",
			"2026-01-01T11:00:00",
			"db",
		]);
		assert_eq!(
			calls[1],
			"logs -n all --since 10m --until 2026-01-01T11:00:00 db"
		);
	}

	#[test]
	fn two_services_are_interleaved_in_time_order() {
		let mail = [at(1, "m1"), at(4, "m2"), at(6, "m3")].concat();
		let db = [at(2, "d1"), at(3, "d2"), at(5, "d3")].concat();
		let fixture = fixture(&mail, &db);
		let (output, _) = fixture.logs(&[]);
		let order: Vec<String> = stdout(&output)
			.lines()
			.map(|line| line.rsplit(' ').next().unwrap().to_string())
			.collect();
		assert_eq!(order, ["m1", "d1", "d2", "m2", "d3", "m3"]);
	}

	#[test]
	fn no_merge_keeps_each_service_together_without_times() {
		let mail = [at(1, "m1"), at(4, "m2")].concat();
		let db = [at(2, "d1")].concat();
		let fixture = fixture(&mail, &db);
		let (output, calls) = fixture.logs(&["--no-merge"]);
		assert_eq!(calls[1], "logs -n 200 mail");
		assert_eq!(stdout(&output), "mail-1 | m1\nmail-1 | m2\ndb-1 | d1\n");
	}

	#[test]
	fn a_single_service_is_asked_for_by_name_and_shows_no_times() {
		let fixture = fixture(&at(1, "m1"), &at(2, "d1"));
		let (output, calls) = fixture.logs(&["db"]);
		assert_eq!(calls, ["logs -n 200 db"]);
		assert_eq!(stdout(&output), "db-1 | d1\n");
		let (output, calls) = fixture.logs(&["--merge", "db"]);
		assert_eq!(calls[1], "logs -t -n 200 db");
		assert!(stdout(&output).contains("2026-01-01T10:00:02Z d1"));
	}

	#[test]
	fn a_long_line_is_cut_and_raw_keeps_it_whole() {
		let long = format!("{}{}", "x".repeat(500), "TAIL".repeat(25));
		let fixture = fixture(&at(1, &long), &at(2, "short"));
		let (output, _) = fixture.logs(&[]);
		let text = stdout(&output);
		assert!(text.contains(&format!(
			"{} [100 more bytes cut; --raw shows them]",
			"x".repeat(500)
		)));
		assert!(!text.contains("TAIL"));
		assert!(text.contains("db-1 | 2026-01-01T10:00:02Z short"));
		let (output, _) = fixture.logs(&["--raw"]);
		assert!(stdout(&output).contains(&long));
	}

	#[test]
	fn follow_asks_podup_once_and_cuts_on_the_way() {
		let long = "y".repeat(520);
		let fixture = fixture(&at(1, &long), &at(2, "d1"));
		let (output, calls) = fixture.logs(&["--follow", "mail"]);
		assert_eq!(calls, ["logs --follow -n 200 mail"]);
		assert!(stdout(&output).contains("[20 more bytes cut; --raw shows them]"));
		let (_, calls) = fixture.logs(&["--follow", "--raw", "--tail", "5", "mail"]);
		assert_eq!(calls[1], "logs --follow -n 5 mail");
	}

	#[test]
	fn a_failing_podup_stops_with_its_exit_code_and_names_the_call() {
		let fixture = fixture(&at(1, "m1"), &at(2, "d1"));
		let (output, _) = fixture.logs(&["ghost"]);
		assert_eq!(output.status.code(), Some(7));
		let stderr = String::from_utf8_lossy(&output.stderr);
		assert!(stderr.contains("no such service: ghost"), "{stderr}");
		assert!(stderr.contains("logs -n 200 ghost"), "{stderr}");
	}
}
