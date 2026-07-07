//! Tests for app-password authentication through the directory: the fallback
//! when the primary password fails, with expiry and CIDR enforcement, and the
//! no-user-enumeration-oracle property.

use super::*;
use crate::directory_store::AppPassword;

/// A directory with one account `alice` and a known primary password.
fn directory_with_primary() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[("alice@example.org".to_string(), "alice".to_string())],
	)
	.with_password_hashes([(
		"alice".to_string(),
		crate::smtp::auth::tests::hash("primary-secret"),
	)])
}

fn app_password(label: &str, secret: &str) -> AppPassword {
	AppPassword {
		label: label.to_string(),
		hash: crate::smtp::auth::tests::hash(secret),
		expires_at: None,
		ip_cidr: None,
	}
}

fn ip(text: &str) -> std::net::IpAddr {
	text.parse().expect("ip")
}

#[test]
fn primary_password_still_authenticates() {
	let dir = directory_with_primary();
	assert_eq!(
		dir.authenticate("alice", "primary-secret").as_deref(),
		Some("alice")
	);
}

#[test]
fn valid_app_password_authenticates() {
	let dir = directory_with_primary()
		.with_app_passwords([("alice".to_string(), app_password("phone", "app-secret"))]);
	// The primary password fails, the app password succeeds.
	assert_eq!(
		dir.authenticate("alice", "app-secret").as_deref(),
		Some("alice")
	);
}

#[test]
fn wrong_app_password_rejected() {
	let dir = directory_with_primary()
		.with_app_passwords([("alice".to_string(), app_password("phone", "app-secret"))]);
	assert!(dir.authenticate("alice", "wrong").is_none());
}

#[test]
fn expired_app_password_rejected() {
	let mut app = app_password("phone", "app-secret");
	app.expires_at = Some(1); // long past
	let dir = directory_with_primary().with_app_passwords([("alice".to_string(), app)]);
	assert!(dir.authenticate("alice", "app-secret").is_none());
}

#[test]
fn app_password_ip_outside_cidr_rejected_inside_accepted() {
	let mut app = app_password("phone", "app-secret");
	app.ip_cidr = Some("203.0.113.0/24".to_string());
	let dir = directory_with_primary().with_app_passwords([("alice".to_string(), app)]);

	// Inside the allowlist: accepted.
	assert_eq!(
		dir.authenticate_with_ip("alice", "app-secret", Some(ip("203.0.113.9")))
			.as_deref(),
		Some("alice")
	);
	// Outside: rejected.
	assert!(
		dir.authenticate_with_ip("alice", "app-secret", Some(ip("198.51.100.1")))
			.is_none()
	);
	// No IP with a CIDR set: rejected (the wrapper passes None).
	assert!(dir.authenticate("alice", "app-secret").is_none());
}

#[test]
fn unknown_account_is_no_oracle() {
	let dir = directory_with_primary()
		.with_app_passwords([("alice".to_string(), app_password("phone", "app-secret"))]);
	// An unknown account behaves exactly like a wrong password: None, whether
	// or not the secret happens to match a real app password.
	assert!(dir.authenticate("nobody", "app-secret").is_none());
	assert!(dir.authenticate("nobody", "primary-secret").is_none());
	assert!(
		dir.authenticate_with_ip("nobody", "app-secret", Some(ip("203.0.113.9")))
			.is_none()
	);
}

#[test]
fn app_password_for_other_account_does_not_cross_over() {
	let dir = Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
		],
	)
	.with_password_hashes([
		(
			"alice".to_string(),
			crate::smtp::auth::tests::hash("alice-primary"),
		),
		(
			"bob".to_string(),
			crate::smtp::auth::tests::hash("bob-primary"),
		),
	])
	.with_app_passwords([("alice".to_string(), app_password("phone", "alice-app"))]);
	// alice's app password must not authenticate bob.
	assert!(dir.authenticate("bob", "alice-app").is_none());
}
