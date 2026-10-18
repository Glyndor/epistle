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

#[tokio::test]
async fn many_prefixes_of_one_ipv6_allocation_cannot_exhaust_the_pool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let app = router(state_with_authz(dir.path(), &keys()));
	let mut accepted = 0;
	for slash64 in 0..200u32 {
		for host in 1..=super::device::MAX_GRANTS_PER_CLIENT {
			let peer = format!("2001:db8:aa:{slash64:x}::{host:x}");
			if start(&app, &peer).await == StatusCode::OK {
				accepted += 1;
			}
		}
	}
	assert!(
		accepted <= super::device::MAX_GRANTS_PER_NET,
		"one /48 holds {accepted} grants"
	);
	assert_eq!(start(&app, "198.51.100.9").await, StatusCode::OK);
}

#[tokio::test]
async fn a_full_pool_drops_the_oldest_pending_grant_of_the_heaviest_net() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	let heavy = super::device::client_bucket("2001:db8:bb::1".parse().expect("ip"));
	{
		let mut devices = authz.devices.lock().unwrap();
		// One /48 holding half the pool, the oldest of it first.
		for n in 0..5_000u64 {
			let mut g = grant(Some((true, heavy.1 + (n % 60_000))), now() + 100 + n);
			g.user_code = format!("H{n}");
			// The oldest of them was approved meanwhile.
			g.approved_account = (n == 0).then(|| "alice".to_string());
			devices.insert(format!("heavy{n}"), g);
		}
		// Everybody else: one each, one of them already approved.
		for n in 0..(super::device::MAX_DEVICE_GRANTS - 5_000) as u64 {
			let mut g = grant(Some((false, n + 10)), now() + 1);
			g.approved_account = (n == 0).then(|| "alice".to_string());
			devices.insert(format!("other{n}"), g);
		}
	}
	let app = router(state.clone());
	assert_eq!(start(&app, "198.51.100.200").await, StatusCode::OK);
	let devices = authz.devices.lock().unwrap();
	assert_eq!(devices.len(), super::device::MAX_DEVICE_GRANTS);
	assert!(devices.contains_key("other0"), "the approved grant stays");
	assert!(
		devices.contains_key("heavy0"),
		"an approved one is never evicted"
	);
	assert!(
		!devices.contains_key("heavy1"),
		"the oldest pending grant of the heaviest net went"
	);
}

#[tokio::test]
async fn a_pool_of_only_approved_grants_refuses_instead_of_evicting() {
	let dir = tempfile::tempdir().expect("tempdir");
	let state = state_with_authz(dir.path(), &keys());
	let authz = state.authz().expect("authz");
	{
		let mut devices = authz.devices.lock().unwrap();
		for n in 0..super::device::MAX_DEVICE_GRANTS as u64 {
			let mut g = grant(Some((false, n + 10)), now() + 600);
			g.approved_account = Some("alice".to_string());
			devices.insert(format!("ok{n}"), g);
		}
	}
	let app = router(state);
	assert_eq!(
		start(&app, "198.51.100.201").await,
		StatusCode::TOO_MANY_REQUESTS
	);
}
