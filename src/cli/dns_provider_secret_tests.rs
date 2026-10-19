use super::*;
use clap::Parser;
use std::os::unix::fs::PermissionsExt;

const TOKEN: &str = "private-dns-token";

fn migrate(source: &str, dry_run: bool, stack: bool) {
	let dir = tempfile::tempdir().unwrap();
	let data = dir.path().join("data");
	std::fs::create_dir(&data).unwrap();
	let path = dir.path().join("mail.toml");
	let original = format!(
		"hostname = 'mail.example.org'\ndata_dir = {data:?}\n[dns]\nprovider = 'desec'\nzone = 'example.org'\n{source}\n"
	);
	std::fs::write(&path, &original).unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	let compose = crate::cli::init::compose_file_path(&data);
	if stack {
		std::fs::create_dir_all(compose.parent().unwrap()).unwrap();
		std::fs::write(&compose, r#"{"services":{"mail":{"environment":{"DNS_MIGRATION_TEST_TOKEN":"${DNS_MIGRATION_TEST_TOKEN}","TZ":"UTC"},"volumes":[]},"db":{"environment":{}}}}"#).unwrap();
	}
	let crate::cli::Command::Dns { action, .. } = crate::cli::Cli::try_parse_from([
		"epistle",
		"dns",
		"provider",
		"set",
		"desec",
		"--zone",
		"example.org",
		"--store-token",
	])
	.unwrap()
	.command
	else {
		unreachable!()
	};
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let result = execute_with(
		&path,
		action,
		dry_run,
		false,
		&mut out,
		&mut status,
		|_, action| {
			assert!(matches!(action, StackAction::Recreate { service } if service == "mail"));
			ExitCode::SUCCESS
		},
	);
	assert_eq!(result.unwrap(), ExitCode::SUCCESS);
	assert!(!String::from_utf8(out).unwrap().contains(TOKEN));
	assert!(!String::from_utf8(status).unwrap().contains(TOKEN));
	let secret = dir.path().join("secrets/dns_provider_token");
	if dry_run {
		assert!(!secret.exists());
		assert_eq!(std::fs::read_to_string(path).unwrap(), original);
		return;
	}
	assert!(std::fs::read_to_string(&secret).unwrap() == TOKEN);
	assert_eq!(
		std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
		0o600
	);
	let config = Config::load(&path).unwrap();
	let dns = config.dns.unwrap();
	assert_eq!(dns.token_file.as_ref(), Some(&secret));
	assert!(dns.token.is_none() && dns.token_env.is_none());
	assert!(dns.build().is_some());
	if stack {
		let rendered = std::fs::read_to_string(compose).unwrap();
		assert!(!rendered.contains(TOKEN));
		let compose: serde_json::Value = serde_json::from_str(&rendered).unwrap();
		assert!(
			compose["services"]["mail"]["environment"]
				.get("DNS_MIGRATION_TEST_TOKEN")
				.is_none()
		);
		assert!(
			compose["services"]["mail"]["volumes"]
				.as_array()
				.unwrap()
				.iter()
				.any(|mount| mount["source"] == secret.display().to_string()
					&& mount["read_only"] == true)
		);
		assert!(compose["services"]["db"].get("volumes").is_none());
	}
	std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o644)).unwrap();
	let error = crate::dns::provider::ScopedSecret::from_file("example.org", &secret).unwrap_err();
	assert!(error.to_string().contains("0600"));
	assert!(!error.to_string().contains(TOKEN));
	assert!(dns.build().is_none());
}

#[test]
fn store_inline_token_and_preview_without_disclosure() {
	migrate("token = 'private-dns-token'", true, false);
	migrate("token = 'private-dns-token'", false, false);
}

#[test]
fn store_environment_token_and_remove_container_environment() {
	unsafe { std::env::set_var("DNS_MIGRATION_TEST_TOKEN", TOKEN) };
	migrate("token_env = 'DNS_MIGRATION_TEST_TOKEN'", false, true);
}
