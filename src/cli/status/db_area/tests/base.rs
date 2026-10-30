//! Tests for the database check. A real PostgreSQL is used only when
//! `DATABASE_URL` is set (as in `tests/database_bans.rs`); the rest use a
//! closed port and a listener that never answers.

use std::time::{Duration, Instant};

use tokio::net::TcpListener;

use super::{check, evaluate};
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::config::Database;

fn database(url: &str) -> Database {
	let toml = format!("url = {url:?}\ntls = \"insecure\"\n");
	toml::from_str(&toml).expect("database section")
}

#[tokio::test]
async fn without_a_database_section_there_is_nothing_to_check() {
	let dir = tempfile::tempdir().expect("tempdir");
	let report = check(&ctx(dir.path(), "")).await;
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "no [database] is configured");
}

#[tokio::test]
async fn a_refused_connection_fails_within_the_limit_not_after_the_pool_deadline() {
	// A socket bound but never listening refuses every connection and keeps
	// the port, so a test running in parallel cannot take it over (a
	// dropped listener frees the port and another test's listener may then
	// answer and reset the connection instead).
	let reserved = tokio::net::TcpSocket::new_v4().expect("socket");
	reserved
		.bind("127.0.0.1:0".parse().expect("address"))
		.expect("bind");
	let port = reserved.local_addr().expect("addr").port();
	let url = format!("postgres://epistle@127.0.0.1:{port}/epistle?sslmode=disable");
	let began = Instant::now();
	let report = evaluate(&database(&url), Duration::from_millis(400)).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(
		report.detail,
		"cannot reach PostgreSQL within 400ms (refused, or no answer)"
	);
	assert!(began.elapsed() < Duration::from_secs(3), "waited too long");
	drop(reserved);
}

#[tokio::test]
async fn a_server_that_accepts_but_never_answers_is_cut_off_at_the_limit() {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	tokio::spawn(async move {
		let mut held = Vec::new();
		while let Ok((stream, _)) = listener.accept().await {
			held.push(stream);
		}
	});
	let url = format!("postgres://epistle@127.0.0.1:{port}/epistle?sslmode=disable");
	let began = Instant::now();
	let report = evaluate(&database(&url), Duration::from_millis(300)).await;
	assert_eq!(report.status, Level::Fail);
	assert_eq!(
		report.detail,
		"cannot reach PostgreSQL within 300ms (refused, or no answer)"
	);
	assert!(began.elapsed() < Duration::from_secs(3), "waited too long");
}

#[tokio::test]
async fn a_malformed_url_is_reported_without_echoing_it() {
	let report = evaluate(&database("not a url"), Duration::from_secs(5)).await;
	assert_eq!(report.status, Level::Fail);
	assert!(
		report
			.detail
			.starts_with("database url is not a valid Postgres URL"),
		"{}",
		report.detail
	);
}

#[tokio::test]
async fn a_reachable_server_answers_select_1() {
	let Some(url) = std::env::var("DATABASE_URL").ok().filter(|u| !u.is_empty()) else {
		eprintln!("skipping: DATABASE_URL not set");
		return;
	};
	let report = evaluate(&database(&url), Duration::from_secs(5)).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "connected, SELECT 1 answered");
}
