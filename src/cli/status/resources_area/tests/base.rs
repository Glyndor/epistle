//! Tests for the resources check, on fake compose files.

use super::{Level, evaluate};
use crate::cli::status::test_support::ctx;

/// A compose file whose `mail` service may use `memory`.
fn compose(dir: &std::path::Path, memory: &str) -> std::path::PathBuf {
	let path = dir.join("compose.yaml");
	std::fs::write(
		&path,
		format!(r#"{{"services":{{"mail":{{"mem_limit":"{memory}"}}}}}}"#),
	)
	.expect("compose");
	path
}

fn budget_line(extra: &str, memory: Option<&str>) -> (Level, String) {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), extra);
	let path = match memory {
		Some(memory) => compose(dir.path(), memory),
		None => dir.path().join("absent.yaml"),
	};
	let report = evaluate(ctx.config.as_ref().expect("config"), &path, &ctx.meminfo);
	let item = report
		.items
		.iter()
		.find(|item| item.name == "message budget")
		.expect("a message budget finding");
	(item.status, item.detail.clone())
}

#[test]
fn an_unset_budget_is_derived_from_the_mail_limit() {
	assert_eq!(
		budget_line("", Some("2g")),
		(
			Level::Ok,
			"409 MiB, derived from the 2048 MiB the mail container may use (mem_limit in \
			 compose.yaml)"
				.to_string()
		)
	);
	assert_eq!(
		budget_line("", None),
		(
			Level::Ok,
			"204 MiB, derived from the 1024 MiB the mail container may use (no limit found, \
			 the former 1g default)"
				.to_string()
		)
	);
}

#[test]
fn a_configured_budget_over_seventy_percent_warns_with_the_start_up_line() {
	assert_eq!(
		budget_line("message_memory_budget = 536870912", Some("2g")),
		(
			Level::Warn,
			"message_memory_budget is 512 MiB: a full budget takes about 3 times that (1536 \
			 MiB) while the messages arrive, more than 70% of the 2048 MiB the mail container \
			 may use (mem_limit in compose.yaml); lower message_memory_budget or give the mail \
			 container more memory"
				.to_string()
		)
	);
	assert_eq!(
		budget_line("message_memory_budget = 268435456", Some("2g")),
		(
			Level::Ok,
			"256 MiB, set by message_memory_budget".to_string()
		)
	);
	assert_eq!(
		budget_line("message_memory_budget = 0", Some("2g")),
		(Level::Ok, "off (message_memory_budget = 0)".to_string())
	);
}

#[test]
fn the_warning_rolls_up_to_the_area() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = ctx(dir.path(), "message_memory_budget = 536870912");
	let report = evaluate(
		ctx.config.as_ref().expect("config"),
		&compose(dir.path(), "2g"),
		&ctx.meminfo,
	);
	assert_eq!(report.status, Level::Warn, "{report:?}");
}
