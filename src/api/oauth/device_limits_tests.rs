//! `POST /oauth/device_authorization` is public, so the grants it creates are
//! bounded: per client, overall, and expired ones are swept.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use tower::ServiceExt;

use super::tests::{keys, state_with_authz};
use crate::api::router;

async fn start(app: &axum::Router, peer: &str) -> StatusCode {
	let mut request = Request::builder()
		.method("POST")
		.uri("/oauth/device_authorization")
		.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
		.body(Body::from("client_id=cli"))
		.expect("request");
	let peer: std::net::IpAddr = peer.parse().expect("peer");
	request
		.extensions_mut()
		.insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
			peer, 4000,
		))));
	app.clone()
		.oneshot(request)
		.await
		.expect("response")
		.status()
}

#[tokio::test]
async fn one_client_cannot_hold_more_than_its_share_of_grants() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_authz(dir.path(), &keys()));
	for _ in 0..10 {
		assert_eq!(start(&app, "198.51.100.1").await, StatusCode::OK);
	}
	assert_eq!(
		start(&app, "198.51.100.1").await,
		StatusCode::TOO_MANY_REQUESTS,
		"the eleventh from one client is refused"
	);
	assert_eq!(
		start(&app, "198.51.100.2").await,
		StatusCode::OK,
		"another client is not"
	);
}

fn grant(client: Option<(bool, u64)>, expires_at: u64) -> super::DeviceGrant {
	super::DeviceGrant {
		user_code: "AAAA-AAAA".to_string(),
		approved_account: None,
		expires_at,
		next_poll_at: 0,
		client,
	}
}

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("clock")
		.as_secs()
}

#[tokio::test]
async fn the_total_is_capped_whoever_asks() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		let mut devices = authz.devices.lock().unwrap();
		for n in 0..super::device::MAX_DEVICE_GRANTS {
			devices.insert(
				format!("dc{n}"),
				grant(Some((false, n as u64)), now() + 600),
			);
		}
	}
	let app = router(state);
	assert_eq!(
		start(&app, "198.51.100.77").await,
		StatusCode::TOO_MANY_REQUESTS
	);
}

#[tokio::test]
async fn expired_grants_nobody_polled_for_are_swept_when_the_caps_are_hit() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	let me = super::device::client_bucket("198.51.100.5".parse().expect("ip"));
	{
		let mut devices = authz.devices.lock().unwrap();
		for n in 0..super::device::MAX_GRANTS_PER_CLIENT {
			devices.insert(format!("old{n}"), grant(Some(me), 1));
		}
		for n in 0..super::device::MAX_DEVICE_GRANTS - super::device::MAX_GRANTS_PER_CLIENT {
			devices.insert(format!("fill{n}"), grant(Some((false, n as u64 + 10)), 1));
		}
	}
	let app = router(state.clone());
	assert_eq!(start(&app, "198.51.100.5").await, StatusCode::OK);
	assert!(
		authz.devices.lock().unwrap().len() < 100,
		"the expired ones are gone"
	);
}
