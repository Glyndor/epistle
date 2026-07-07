//! Tests for the DNS provider abstraction and scoped secrets.

use super::*;
use std::sync::Mutex;

/// An in-memory provider, proving the trait is test-injectable.
#[derive(Default)]
struct FakeProvider {
	records: Mutex<Vec<DnsRecord>>,
}

impl DnsProvider for FakeProvider {
	fn upsert(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			let mut records = self.records.lock().unwrap();
			records.retain(|r| !(r.name == record.name && r.kind == record.kind));
			records.push(record);
			Ok(())
		})
	}
	fn delete(&self, _zone: &str, record: DnsRecord) -> Op<'_> {
		Box::pin(async move {
			self.records
				.lock()
				.unwrap()
				.retain(|r| !(r.name == record.name && r.kind == record.kind));
			Ok(())
		})
	}
	fn list(&self, _zone: &str) -> ListOp<'_> {
		Box::pin(async move { Ok(self.records.lock().unwrap().clone()) })
	}
}

fn record() -> DnsRecord {
	DnsRecord {
		name: "_dmarc.example.org".to_string(),
		kind: RecordKind::Txt,
		value: "v=DMARC1; p=reject".to_string(),
		ttl: 3600,
	}
}

#[tokio::test]
async fn fake_provider_upsert_list_delete() {
	let provider = FakeProvider::default();
	provider
		.upsert("example.org", record())
		.await
		.expect("upsert");
	// Upsert is idempotent (replaces, not duplicates).
	provider
		.upsert("example.org", record())
		.await
		.expect("upsert");
	assert_eq!(provider.list("example.org").await.unwrap().len(), 1);
	provider
		.delete("example.org", record())
		.await
		.expect("delete");
	assert!(provider.list("example.org").await.unwrap().is_empty());
}

#[tokio::test]
async fn manual_provider_refuses_writes_but_lists_empty() {
	let provider = ManualProvider;
	assert_eq!(
		provider.upsert("example.org", record()).await,
		Err(ProviderError::Unsupported)
	);
	assert_eq!(
		provider.delete("example.org", record()).await,
		Err(ProviderError::Unsupported)
	);
	assert!(provider.list("example.org").await.unwrap().is_empty());
}

#[test]
fn record_kind_tokens() {
	assert_eq!(RecordKind::Aaaa.as_str(), "AAAA");
	assert_eq!(RecordKind::Tlsa.as_str(), "TLSA");
}

#[test]
fn scoped_secret_authorizes_only_its_zone() {
	let secret = ScopedSecret::new("example.org", "tok");
	assert!(secret.authorizes("example.org"));
	assert!(secret.authorizes("_dmarc.example.org"));
	assert!(secret.authorizes("MAIL.Example.ORG"));
	assert!(!secret.authorizes("other.example"));
	assert!(!secret.authorizes("notexample.org"));
}

#[test]
fn scoped_secret_debug_redacts_token() {
	let secret = ScopedSecret::new("example.org", "super-secret-token");
	let rendered = format!("{secret:?}");
	assert!(rendered.contains("example.org"), "{rendered}");
	assert!(!rendered.contains("super-secret-token"), "{rendered}");
	assert!(rendered.contains("***"), "{rendered}");
}

#[test]
fn scoped_secret_from_env_reads_and_rejects_empty() {
	// Vary the var name per case to avoid cross-test env races.
	unsafe { std::env::set_var("EPISTLE_TEST_DNS_TOKEN_A", "  abc  ") };
	let secret =
		ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_A").expect("present");
	assert_eq!(secret.token(), "abc");
	unsafe { std::env::set_var("EPISTLE_TEST_DNS_TOKEN_B", "   ") };
	assert!(ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_B").is_none());
	assert!(ScopedSecret::from_env("example.org", "EPISTLE_TEST_DNS_TOKEN_UNSET").is_none());
}

#[cfg(unix)]
#[test]
fn scoped_secret_from_file_enforces_permissions() {
	use std::io::Write;
	use std::os::unix::fs::PermissionsExt;

	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("token");
	let mut file = std::fs::File::create(&path).expect("create");
	writeln!(file, "secret-token").expect("write");

	// World/group-accessible: rejected.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
	assert!(ScopedSecret::from_file("example.org", &path).is_err());

	// Owner-only: accepted and trimmed.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	let secret = ScopedSecret::from_file("example.org", &path).expect("load");
	assert_eq!(secret.token(), "secret-token");
	assert_eq!(secret.zone(), "example.org");
}

#[cfg(unix)]
#[test]
fn scoped_secret_from_file_rejects_empty() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("empty");
	std::fs::write(&path, "   \n").expect("write");
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	assert!(ScopedSecret::from_file("example.org", &path).is_err());
}
