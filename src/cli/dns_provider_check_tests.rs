use super::*;
use crate::cli::dns_provider::tests::run;
use crate::dns::provider::{DnsProvider, ManualProvider, ProviderError};
use crate::dns::providers::check::{Finding, failure_cause};

#[test]
fn check_is_advisory_and_never_edits_or_restarts() {
	for extra in [
		"",
		"\n[dns]\nprovider = 'manual'\nzone = 'example.org'\n",
		"\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\n",
	] {
		for args in [vec!["check"], vec!["check", "--json"]] {
			let run = run(extra, &args, false);
			assert_eq!(run.result.unwrap(), std::process::ExitCode::SUCCESS);
			assert_eq!(run.before, run.after);
			assert!(run.status.is_empty());
			if args.len() == 2 {
				let value: serde_json::Value = serde_json::from_str(&run.out).unwrap();
				assert!(value.get("record_write").is_some());
			} else {
				assert!(run.out.contains("record_write"));
			}
		}
	}
}

#[tokio::test]
async fn manual_provider_never_claims_read_capability() {
	let report = ManualProvider.check_access("example.org", &[]).await;
	assert_eq!(report.record_read.status, Outcome::NotVerifiable);
	assert_eq!(report.record_write.status, Outcome::NotVerifiable);
}

#[test]
fn text_and_json_have_the_same_facts_without_remote_errors_or_secret_fragments() {
	let secret = crate::test_fixtures::fresh_secret();
	let error = ProviderError::Remote(format!("remote reflected {secret}"));
	let mut report = AccessReport::failed(failure_cause(&error));
	report.expiry = Finding::verified("expires at 2026-10-25T00:00:00Z; expires within seven days");
	report.record_read = Finding::unknown("remote\u{1b}[31m\n\u{200b}\u{202e}\tend");
	let (mut text, mut json) = (Vec::new(), Vec::new());
	print(&report, false, &mut text).unwrap();
	print(&report, true, &mut json).unwrap();
	let text = String::from_utf8(text).unwrap();
	let json = String::from_utf8(json).unwrap();
	let value: serde_json::Value = serde_json::from_str(&json).unwrap();
	for fragment in [secret.as_str(), &secret[..8], &secret[secret.len() - 8..]] {
		assert!(!text.contains(fragment));
		assert!(!json.contains(fragment));
	}
	assert_eq!(text.lines().count(), 6);
	assert_eq!(
		text.lines()
			.map(|line| line.split('\t').next().unwrap())
			.collect::<std::collections::BTreeSet<_>>(),
		value
			.as_object()
			.unwrap()
			.keys()
			.map(String::as_str)
			.collect::<std::collections::BTreeSet<_>>()
	);
	assert!(text.contains(r"remote\u{1b}[31m\n\u{200b}\u{202e}\tend"));
	assert!(!text.contains(['\u{1b}', '\u{200b}', '\u{202e}']));
	for line in text.lines() {
		let fields = line.split('\t').collect::<Vec<_>>();
		assert_eq!(fields.len(), 3);
		let finding = &value[fields[0]];
		let status = match finding["status"].as_str().unwrap() {
			"verified" => "verified",
			"not_verifiable" => "not verifiable with this provider",
			"failure" => "failure",
			_ => panic!("unexpected inspection status"),
		};
		assert_eq!(fields[1], status);
		let detail = finding["detail"].as_str().unwrap();
		if fields[0] == "record_read" {
			assert_eq!(detail, "remote\u{1b}[31m\n\u{200b}\u{202e}\tend");
			assert_eq!(fields[2], r"remote\u{1b}[31m\n\u{200b}\u{202e}\tend");
		} else {
			assert_eq!(fields[2], detail);
		}
	}
}

struct ReadOnly(Result<Vec<crate::dns::provider::DnsRecord>, ProviderError>);

impl DnsProvider for ReadOnly {
	fn upsert(
		&self,
		_: &str,
		_: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
		panic!("inspection must never write records")
	}
	fn delete(
		&self,
		_: &str,
		_: crate::dns::provider::DnsRecord,
	) -> std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + '_>> {
		panic!("inspection must never delete records")
	}
	fn list(
		&self,
		_: &str,
	) -> std::pin::Pin<
		Box<
			dyn Future<Output = Result<Vec<crate::dns::provider::DnsRecord>, ProviderError>>
				+ Send
				+ '_,
		>,
	> {
		let result = self.0.clone();
		Box::pin(async move { result })
	}
}

#[tokio::test]
async fn default_inspection_proves_only_reading_and_keeps_failures_secret() {
	let provider = ReadOnly(Ok(vec![]));
	let report = provider.check_access("example.org", &[]).await;
	assert_eq!(report.record_read.status, Outcome::Verified);
	for finding in [
		&report.record_write,
		&report.zones,
		&report.expiry,
		&report.scope,
	] {
		assert_eq!(finding.status, Outcome::NotVerifiable);
	}
	let secret = crate::test_fixtures::fresh_secret();
	for error in [
		ProviderError::Auth,
		ProviderError::Remote(secret.clone()),
		ProviderError::Unsupported,
	] {
		let unsupported = error == ProviderError::Unsupported;
		let report = ReadOnly(Err(error)).check_access("example.org", &[]).await;
		assert_eq!(
			report.record_read.status,
			if unsupported {
				Outcome::NotVerifiable
			} else {
				Outcome::Failure
			}
		);
		for json in [false, true] {
			let mut out = Vec::new();
			print(&report, json, &mut out).unwrap();
			let out = String::from_utf8(out).unwrap();
			assert!(!out.contains(&secret));
			assert!(!out.contains(&secret[..8]));
		}
	}
}

#[test]
fn malformed_config_never_discloses_credentials() {
	const ENV: &str = "EPISTLE_DNS_CHECK_PARSE_SECRET";
	if std::env::var_os(ENV).is_none() {
		let secret = crate::test_fixtures::fresh_secret();
		let result = std::process::Command::new(std::env::current_exe().unwrap())
			.args([
				"--exact",
				"cli::dns_provider::check::tests::malformed_config_never_discloses_credentials",
				"--nocapture",
			])
			.env(ENV, &secret)
			.output()
			.unwrap();
		assert!(
			result.status.success(),
			"credential-safe parse assertions failed in child process"
		);
		return;
	}
	let secret = std::env::var(ENV).unwrap();
	for token in [secret.clone(), format!("${{{ENV}}}")] {
		for field in [
			format!("token = '{token}' INVALID"),
			format!("token = ['{token}']"),
		] {
			for args in [vec!["check"], vec!["check", "--json"]] {
				let extra =
					format!("\n[dns]\nprovider = 'cloudflare'\nzone = 'example.org'\n{field}\n");
				let run = run(&extra, &args, false);
				let error = run.result.expect_err("malformed configuration must fail");
				for output in [run.out.as_str(), run.status.as_str(), error.as_ref()] {
					for fragment in [secret.as_str(), &secret[..8], &secret[secret.len() - 8..]] {
						assert!(
							!output.contains(fragment),
							"configuration error disclosed a credential fragment"
						);
					}
				}
				assert!(error.as_ref().contains("TOML"));
				assert!(run.out.is_empty());
			}
		}
	}
}

#[test]
fn check_passes_every_own_name_to_the_provider() {
	use std::sync::{Arc, Mutex};
	type WriteOp<'a> =
		std::pin::Pin<Box<dyn Future<Output = Result<(), ProviderError>> + Send + 'a>>;
	type ListOp<'a> = std::pin::Pin<
		Box<
			dyn Future<Output = Result<Vec<crate::dns::provider::DnsRecord>, ProviderError>>
				+ Send
				+ 'a,
		>,
	>;
	struct Capture(Arc<Mutex<Vec<String>>>);
	impl DnsProvider for Capture {
		fn upsert(&self, _: &str, _: crate::dns::provider::DnsRecord) -> WriteOp<'_> {
			panic!("inspection must never write records")
		}
		fn delete(&self, _: &str, _: crate::dns::provider::DnsRecord) -> WriteOp<'_> {
			panic!("inspection must never delete records")
		}
		fn list(&self, _: &str) -> ListOp<'_> {
			panic!("inspection must use the provider capability check")
		}
		fn check_access<'a>(
			&'a self,
			zone: &'a str,
			names: &'a [String],
		) -> crate::dns::providers::check::CheckOp<'a> {
			Box::pin(async move {
				assert_eq!(zone, "example.org");
				*self.0.lock().unwrap() = names.to_vec();
				AccessReport::unknown()
			})
		}
	}
	let (_dir, file) = crate::cli::resource::test_config("");
	let mut config = Config::load(file.path()).unwrap();
	config.domains = vec![
		"example.org".into(),
		"example.net".into(),
		"example.org".into(),
	];
	config.dns = Some(toml::from_str("provider = 'cloudflare'\nzone = 'example.org'").unwrap());
	let expected = vec![
		"autoconfig.example.net",
		"autoconfig.example.org",
		"autodiscover.example.net",
		"autodiscover.example.org",
		"example.net",
		"example.org",
		"mail.example.org",
		"mta-sts.example.net",
		"mta-sts.example.org",
	];
	for json in [false, true] {
		let captured = Arc::new(Mutex::new(Vec::new()));
		let mut out = Vec::new();
		run_with(&config, json, &mut out, |dns, hostname| {
			assert_eq!(dns.provider, "cloudflare");
			assert_eq!(hostname, "mail.example.org");
			Some(Arc::new(Capture(captured.clone())))
		})
		.unwrap();
		assert_eq!(*captured.lock().unwrap(), expected);
		assert!(!out.is_empty());
	}
}
