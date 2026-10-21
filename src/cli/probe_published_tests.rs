//! Publication routing tests with deterministic protocol probe results.

use super::*;

fn api() -> Listener {
	toml::from_str("kind = 'api'\naddr = '0.0.0.0'\nport = 8025").unwrap()
}

fn publication(ip: &str, published: serde_json::Value) -> String {
	serde_json::json!([{
		"Service": "mail", "Publishers": [{
			"URL": ip, "TargetPort": 8025, "PublishedPort": published, "Protocol": "tcp"
		}]
	}])
	.to_string()
}

async fn run(json: Result<String, String>, answering: bool) -> (Vec<ProbeLine>, Vec<SocketAddr>) {
	let mut dialed = Vec::new();
	let lines = probe_with(&[api()], json, |listener| {
		let addr = listener.socket_addr();
		dialed.push(addr);
		let ok = answering && addr == "10.0.0.1:18025".parse::<SocketAddr>().unwrap();
		std::future::ready(ProbeLine {
			kind: listener.kind.as_str(),
			addr: addr.to_string(),
			ok,
			error: (!ok).then(|| "connect: connection refused".to_string()),
			warning: None,
		})
	})
	.await;
	(lines, dialed)
}

#[tokio::test]
async fn pinned_api_answers_at_its_published_address_and_port() {
	let (lines, dialed) = run(Ok(publication("10.0.0.1", 18025.into())), true).await;
	assert!(lines[0].ok, "{lines:?}");
	assert_eq!(
		dialed,
		vec!["10.0.0.1:18025".parse::<SocketAddr>().unwrap()]
	);
	assert_eq!(lines[0].addr, "10.0.0.1:18025");
	assert!(lines[0].warning.is_none());
	assert_eq!(
		super::super::result_code(&lines),
		std::process::ExitCode::SUCCESS
	);
}

#[tokio::test]
async fn published_api_that_is_down_still_fails() {
	let (lines, dialed) = run(Ok(publication("10.0.0.1", 18025.into())), false).await;
	assert!(!lines[0].ok);
	assert_eq!(
		dialed,
		vec!["10.0.0.1:18025".parse::<SocketAddr>().unwrap()]
	);
	assert_eq!(
		lines[0].error.as_deref(),
		Some("connect: connection refused")
	);
	assert!(lines[0].warning.is_none());
	assert_eq!(
		super::super::result_code(&lines),
		std::process::ExitCode::FAILURE
	);
}

#[tokio::test]
async fn unknown_publications_warn_without_dialing_or_failing() {
	for json in [
		Err("cannot run podup".to_string()),
		Ok("not JSON".to_string()),
		Ok("[]".to_string()),
		Ok(r#"[{"Service":"mail"}]"#.to_string()),
		Ok(r#"[{"Service":"mail","Publishers":[]}]"#.to_string()),
		Ok(publication("", 8025.into())),
		Ok(publication("hostname.invalid", 8025.into())),
		Ok(publication("10.0.0.1", serde_json::Value::Null)),
		Ok(publication("10.0.0.1", 0.into())),
	] {
		let (lines, dialed) = run(json, true).await;
		assert!(dialed.is_empty());
		assert_eq!(
			super::super::result_code(&lines),
			std::process::ExitCode::SUCCESS
		);
		assert!(!lines[0].ok, "unchecked must not claim to answer");
		assert!(lines[0].error.is_none(), "{lines:?}");
		assert!(
			lines[0]
				.warning
				.as_deref()
				.unwrap()
				.starts_with("not checkable from here:")
		);
		let mut out = Vec::new();
		super::super::render(&lines, false, &mut out);
		assert!(String::from_utf8(out).unwrap().contains("warn api"));
		let json = serde_json::to_value(&lines).unwrap();
		assert!(json[0].get("error").is_none());
		assert!(
			json[0]["warning"]
				.as_str()
				.unwrap()
				.contains("epistle stack ps")
		);
	}
}

#[test]
fn wildcard_publications_keep_loopback_targets_without_an_override() {
	for (ip, expected) in [
		("0.0.0.0", "127.0.0.1:8025"),
		("::", "[::1]:8025"),
		("127.0.0.1", "127.0.0.1:8025"),
	] {
		let ports = parse(&publication(ip, 8025.into())).unwrap();
		let targets = targets(&api(), &ports).unwrap();
		assert_eq!(targets[0].socket_addr().to_string(), expected);
	}
}

#[test]
fn standalone_and_container_healthchecks_stay_local() {
	let dir = tempfile::tempdir().unwrap();
	let compose = dir.path().join("compose.yaml");
	assert!(local(&compose, false));
	std::fs::write(&compose, "{}").unwrap();
	assert!(!local(&compose, false));
	assert!(local(&compose, true), "compose is mounted inside mail too");
	let blocked = compose.join("compose.yaml");
	assert!(
		!local(&blocked, false),
		"an unreadable stack path is not a standalone install"
	);
}

#[tokio::test]
async fn every_known_binding_is_checked_and_other_services_are_ignored() {
	let json = serde_json::json!([
		{"Service":"db", "Publishers":[{"URL":"192.0.2.1", "TargetPort":8025, "PublishedPort":8025, "Protocol":"tcp"}]},
		{"Service":"mail", "Publishers":[
			{"URL":"10.0.0.1", "TargetPort":8025, "PublishedPort":18025, "Protocol":"tcp"},
			{"URL":"10.0.0.2", "TargetPort":8025, "PublishedPort":8025, "Protocol":"tcp"},
			{"URL":"192.0.2.2", "TargetPort":8025, "PublishedPort":8025, "Protocol":"udp"}
		]}
	]).to_string();
	let (lines, dialed) = run(Ok(json), true).await;
	assert_eq!(dialed.len(), 2);
	assert_eq!(lines.len(), 1);
	assert!(
		!lines[0].ok,
		"one failed publication must still fail the listener"
	);
	assert!(lines[0].error.is_some());
}

#[tokio::test]
async fn host_discovery_passes_the_override_and_reports_unknown_metadata() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().unwrap();
	let config: Config = toml::from_str(&format!(
		"hostname = 'mail.example.org'\ndata_dir = {:?}\n[[listeners]]\nkind = 'api'\naddr = '0.0.0.0'\nport = 8025\n",
		dir.path().to_str().unwrap()
	)).unwrap();
	let compose = crate::cli::stack::compose_path(&config.data_dir);
	std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
	std::fs::write(&compose, "{}").unwrap();
	let override_path = compose.with_file_name("compose.override.yaml");
	std::fs::write(&override_path, "services: {}\n").unwrap();
	let stub = dir.path().join("podup");
	// Paths are passed as argv, never interpolated into the script.
	std::fs::write(&stub, "#!/bin/sh\n[ \"$1\" = -f ] && [ \"$3\" = -f ] && [ \"$5\" = ps ] && [ \"$6\" = --format ] && [ \"$7\" = json ] || exit 1\nprintf '[]'\n").unwrap();
	std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o700)).unwrap();
	let lines = probe_in(&config, None, stub.to_str().unwrap(), false)
		.await
		.unwrap();
	assert_eq!(lines.len(), 1);
	assert!(
		lines[0]
			.warning
			.as_deref()
			.unwrap()
			.contains("mail is not listed by podup ps"),
		"{lines:?}"
	);
	assert_eq!(
		super::super::result_code(&lines),
		std::process::ExitCode::SUCCESS
	);
}
