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
	for (key, finding) in value.as_object().unwrap() {
		assert!(text.contains(key));
		assert!(text.contains(finding["detail"].as_str().unwrap()));
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
