use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

fn app(dir: &std::path::Path) -> axum::Router {
	let password = crate::smtp::auth::tests::fixture_password();
	let directory = crate::smtp::directory::Directory::new(
		["example.org".into()],
		[("alice@example.org".into(), "alice".into())],
	)
	.with_password_hashes(std::collections::HashMap::from([(
		"alice".into(),
		crate::smtp::auth::tests::hash(password),
	)]));
	super::router(
		crate::directory_store::DirectoryHandle::new(directory),
		dir.into(),
	)
}

async fn send(app: &axum::Router, method: &str, uri: &str, body: String) -> Vec<u8> {
	let auth = base64::engine::general_purpose::STANDARD.encode(format!(
		"alice:{}",
		crate::smtp::auth::tests::fixture_password()
	));
	let response = app
		.clone()
		.oneshot(
			Request::builder()
				.method(method)
				.uri(uri)
				.header("Authorization", format!("Basic {auth}"))
				.header("Depth", "1")
				.body(Body::from(body))
				.expect("request"),
		)
		.await
		.expect("response");
	assert_eq!(response.status(), StatusCode::MULTI_STATUS);
	to_bytes(response.into_body(), usize::MAX)
		.await
		.expect("body")
		.to_vec()
}

fn check_href(bytes: &[u8], href: &str, stored: &str) {
	let xml = String::from_utf8_lossy(bytes);
	assert!(
		xml.contains(&format!("<D:href>{href}</D:href>")),
		"DAV wire href must percent-encode the stored path segments"
	);
	let decoded = percent_encoding::percent_decode_str(href)
		.decode_utf8()
		.expect("utf8");
	assert!(
		decoded == stored,
		"DAV href must decode to the exact stored name"
	);
}

#[tokio::test]
async fn propfind_href_preserves_percent_space_and_unicode_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav/dir %2e");
	std::fs::create_dir_all(&root).expect("mkdir");
	let app = app(dir.path());
	for (name, encoded) in [
		("a%2eb", "a%252eb"),
		("a space", "a%20space"),
		("café", "caf%C3%A9"),
		("a&b", "a%26b"),
		("a-._~", "a-._~"),
	] {
		std::fs::write(root.join(name), b"body").expect("write");
		let bytes = send(&app, "PROPFIND", "/dir%20%252e/", String::new()).await;
		let href = format!("/dir%20%252e/{encoded}");
		check_href(&bytes, &href, &format!("/dir %2e/{name}"));
		let bytes = send(&app, "PROPFIND", &href, String::new()).await;
		check_href(&bytes, &href, &format!("/dir %2e/{name}"));
	}
}

#[tokio::test]
async fn report_href_preserves_percent_space_and_unicode_wire() {
	let dir = tempfile::tempdir().expect("tempdir");
	let root = dir.path().join("accounts/alice/dav/book %2e");
	std::fs::create_dir_all(&root).expect("mkdir");
	let app = app(dir.path());
	for (namespace, prefix, extension) in [
		("urn:ietf:params:xml:ns:caldav", "calendar", "ics"),
		("urn:ietf:params:xml:ns:carddav", "addressbook", "vcf"),
	] {
		for (name, encoded) in [
			("a%2eb", "a%252eb"),
			("a space", "a%20space"),
			("café", "caf%C3%A9"),
		] {
			let name = format!("{name}.{extension}");
			let href = format!("/book%20%252e/{encoded}.{extension}");
			std::fs::write(root.join(&name), b"body").expect("write");
			for report in [
				format!("<C:{prefix}-query xmlns:C=\"{namespace}\"/>"),
				format!(
					"<C:{prefix}-multiget xmlns:C=\"{namespace}\" xmlns:D=\"DAV:\"><D:href>{href}</D:href></C:{prefix}-multiget>"
				),
			] {
				let bytes = send(&app, "REPORT", "/book%20%252e/", report).await;
				check_href(&bytes, &href, &format!("/book %2e/{name}"));
			}
		}
	}
}
