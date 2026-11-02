use super::{render, stack_answers};

#[cfg(unix)]
#[test]
fn db_healthcheck_rejects_temporary_server_and_requires_query() {
	use crate::test_executable::write_executable;
	use std::fs;
	use std::process::Command;

	let value = render(&stack_answers(), true);
	let test = &value["services"]["db"]["healthcheck"]["test"];
	assert_eq!(test[0], "CMD-SHELL");
	let cmd = test[1].as_str().unwrap();
	let dir = tempfile::tempdir().unwrap();
	for (comm, query_status, expected_status, expected_queries) in [
		("sh", 0, 1, 0),
		("postgres", 0, 0, 1),
		("postgres", 1, 1, 1),
	] {
		let marker = dir.path().join("queried");
		let _ = fs::remove_file(&marker);
		write_executable(
			&dir.path().join("cat"),
			format!(
				"#!/bin/sh\nif [ \"$1\" = /proc/1/comm ]; then printf '%s\\n' '{comm}'; else printf 'fixture'; fi\n"
			),
		);
		write_executable(
			&dir.path().join("psql"),
			format!("#!/bin/sh\nprintf 'query' > \"$QUERY_MARKER\"\nexit {query_status}\n"),
		);
		let output = Command::new("/bin/sh")
			.args(["-c", cmd])
			.env("PATH", dir.path())
			.env("QUERY_MARKER", &marker)
			.output()
			.unwrap();
		assert_eq!(
			output.status.code(),
			Some(expected_status),
			"db healthcheck must reject the temporary server and query failures"
		);
		assert_eq!(
			usize::from(marker.exists()),
			expected_queries,
			"temporary server must not be queried"
		);
	}
}
