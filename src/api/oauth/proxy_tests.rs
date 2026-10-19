use super::tests::{keys, state_with_authz};
use super::*;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use tower::ServiceExt;

async fn post(app: &axum::Router, path: &str, peer: &str, forwarded: &str, form: &str) -> Response {
	let mut request = Request::builder()
		.method("POST")
		.uri(path)
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.header("x-forwarded-for", forwarded)
		.body(Body::from(form.to_owned()))
		.unwrap();
	request
		.extensions_mut()
		.insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
	app.clone().oneshot(request).await.unwrap()
}

#[tokio::test]
async fn forwarded_oauth_grants_are_counted_per_client_with_retry_after() {
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys())
		.with_trusted_proxies(vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()]);
	let app = crate::api::router(state.clone());
	for _ in 0..10 {
		assert_eq!(
			post(
				&app,
				"/oauth/device_authorization",
				"10.0.0.1:80",
				"192.0.2.99, 198.51.100.1, 10.0.0.2",
				"client_id=cli"
			)
			.await
			.status(),
			StatusCode::OK
		);
	}
	let response = post(
		&app,
		"/oauth/device_authorization",
		"10.0.0.1:80",
		"198.51.100.1",
		"client_id=cli",
	)
	.await;
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
	let retry: u64 = response.headers()[header::RETRY_AFTER]
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	assert!((590..=600).contains(&retry));
	assert_eq!(
		post(
			&app,
			"/oauth/device_authorization",
			"10.0.0.1:80",
			"198.51.100.2",
			"client_id=cli"
		)
		.await
		.status(),
		StatusCode::OK
	);
	let devices = state.authz().unwrap().devices.lock().unwrap();
	assert_eq!(
		devices
			.values()
			.filter(|g| g.client
				== Some((
					false,
					u64::from(u32::from(std::net::Ipv4Addr::new(198, 51, 100, 1)))
				)))
			.count(),
		10
	);
}

#[tokio::test]
async fn oauth_grants_ignore_untrusted_forwarding_and_group_forwarded_ipv6() {
	for (peer, prefix) in [
		("192.0.2.1:80", "198.51.100."),
		("10.0.0.1:80", "2001:db8:1:2::"),
	] {
		let dir = tempfile::tempdir().unwrap();
		let state = state_with_authz(dir.path(), &keys())
			.with_trusted_proxies(vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()]);
		let app = crate::api::router(state);
		for host in 1..=10 {
			assert_eq!(
				post(
					&app,
					"/oauth/device_authorization",
					peer,
					&format!("{prefix}{host}"),
					"client_id=cli"
				)
				.await
				.status(),
				StatusCode::OK
			);
		}
		assert_eq!(
			post(
				&app,
				"/oauth/device_authorization",
				peer,
				&format!("{prefix}99"),
				"client_id=cli"
			)
			.await
			.status(),
			StatusCode::TOO_MANY_REQUESTS
		);
	}
}

#[tokio::test]
async fn oauth_retry_after_matches_poll_deadline_and_grant_expiry() {
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys());
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	let authz = state.authz().unwrap();
	{
		let mut devices = authz.devices.lock().unwrap();
		for n in 0..10 {
			devices.insert(
				format!("grant-{n}"),
				DeviceGrant {
					user_code: format!("USER-{n}"),
					approved_account: None,
					expires_at: now + 47 + n,
					next_poll_at: now + 47,
					client: Some(device::client_bucket("192.0.2.1".parse().unwrap())),
				},
			);
		}
	}
	let app = crate::api::router(state.clone());
	let response = post(
		&app,
		"/oauth/device_authorization",
		"192.0.2.1:80",
		"",
		"client_id=cli",
	)
	.await;
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
	let seconds: u64 = response.headers()[header::RETRY_AFTER]
		.to_str()
		.unwrap()
		.parse()
		.unwrap();
	assert!((45..=47).contains(&seconds));
	let response = post(
		&app,
		"/oauth/token",
		"192.0.2.1:80",
		"",
		"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=grant-0",
	)
	.await;
	assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
	assert_eq!(response.headers()[header::RETRY_AFTER], "5");
}

#[tokio::test]
async fn oauth_password_checks_use_the_forwarded_client_address() {
	let dir = tempfile::tempdir().unwrap();
	let state = state_with_authz(dir.path(), &keys())
		.with_trusted_proxies(vec![crate::cidr::Cidr::parse("10.0.0.0/8").unwrap()]);
	let secret = uuid::Uuid::now_v7().simple().to_string();
	state
		.store()
		.add_app_password(
			"alice",
			crate::directory_store::AppPassword {
				label: "proxy-client".into(),
				hash: crate::smtp::auth::hash_password(&secret).unwrap(),
				expires_at: None,
				ip_cidr: Some("198.51.100.0/24".into()),
				save_sent: None,
			},
		)
		.unwrap();
	let now = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap()
		.as_secs();
	state.authz().unwrap().devices.lock().unwrap().insert(
		"approval-grant".into(),
		DeviceGrant {
			user_code: "USER-CODE".into(),
			approved_account: None,
			expires_at: now + 600,
			next_poll_at: 0,
			client: None,
		},
	);
	let app = crate::api::router(state);
	for (path, fields) in [
		(
			"/oauth/authorize",
			"client_id=cli&code_challenge_method=S256&code_challenge=challenge",
		),
		("/oauth/device/approve", "user_code=USER-CODE"),
	] {
		let form = format!("login=alice@example.org&password={secret}&{fields}");
		assert_eq!(
			post(&app, path, "10.0.0.1:80", "203.0.113.1", &form)
				.await
				.status(),
			StatusCode::BAD_REQUEST
		);
		assert_eq!(
			post(&app, path, "192.0.2.1:80", "198.51.100.1", &form)
				.await
				.status(),
			StatusCode::BAD_REQUEST
		);
		assert_eq!(
			post(&app, path, "10.0.0.1:80", "198.51.100.1, 10.0.0.2", &form)
				.await
				.status(),
			StatusCode::OK
		);
	}
}
