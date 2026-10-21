//! Tests for the ports check against local fake listeners.

use std::net::{IpAddr, Ipv4Addr};

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use super::check;
use crate::cli::status::report::Level;
use crate::cli::status::test_support::ctx;
use crate::config::{Listener, ListenerKind};

async fn banner(bytes: &'static [u8]) -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
	let port = listener.local_addr().expect("addr").port();
	tokio::spawn(async move {
		while let Ok((mut stream, _)) = listener.accept().await {
			let _ = stream.write_all(bytes).await;
			tokio::spawn(async move {
				let mut sink = [0u8; 64];
				while let Ok(n) = tokio::io::AsyncReadExt::read(&mut stream, &mut sink).await {
					if n == 0 {
						break;
					}
				}
			});
		}
	});
	port
}

fn listener(kind: ListenerKind, addr: IpAddr, port: u16) -> Listener {
	Listener {
		kind,
		addr,
		port: Some(port),
	}
}

fn with_listeners(dir: &std::path::Path, listeners: Vec<Listener>) -> crate::cli::status::Ctx {
	let mut ctx = ctx(dir, "");
	ctx.config.as_mut().expect("config").listeners = listeners;
	ctx
}

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[tokio::test]
async fn listeners_that_greet_correctly_are_ok() {
	let smtp = banner(b"220 mail.example.org ESMTP\r\n").await;
	let imap = banner(b"* OK ready\r\n").await;
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = with_listeners(
		dir.path(),
		vec![
			listener(ListenerKind::Smtp, LOOPBACK, smtp),
			listener(ListenerKind::Imap, LOOPBACK, imap),
		],
	);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.detail, "2 of 2 listeners answer");
	assert_eq!(report.items[0].name, format!("smtp 127.0.0.1:{smtp}"));
	assert_eq!(report.items[0].detail, "answers");
}

#[tokio::test]
async fn a_closed_port_fails_the_area() {
	let smtp = banner(b"220 hello\r\n").await;
	let closed = {
		let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
		listener.local_addr().expect("addr").port()
	};
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = with_listeners(
		dir.path(),
		vec![
			listener(ListenerKind::Smtp, LOOPBACK, smtp),
			listener(ListenerKind::Imap, LOOPBACK, closed),
		],
	);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
	assert_eq!(report.detail, "1 of 2 listeners answer");
	assert_eq!(report.items[0].status, Level::Ok);
	assert_eq!(report.items[1].status, Level::Fail);
	assert!(
		report.items[1].detail.starts_with("connect:"),
		"{}",
		report.items[1].detail
	);
}

#[tokio::test]
async fn a_wrong_greeting_fails_that_listener() {
	let port = banner(b"* BYE go away\r\n").await;
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = with_listeners(
		dir.path(),
		vec![listener(ListenerKind::Imap, LOOPBACK, port)],
	);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Fail);
	assert!(
		report.items[0]
			.detail
			.contains("expected IMAP `* OK` greeting"),
		"{}",
		report.items[0].detail
	);
}

#[tokio::test]
async fn a_wildcard_bind_is_probed_on_loopback() {
	let port = banner(b"220 hello\r\n").await;
	let dir = tempfile::tempdir().expect("tempdir");
	let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
	let ctx = with_listeners(dir.path(), vec![listener(ListenerKind::Smtp, any, port)]);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert_eq!(report.items[0].name, format!("smtp 127.0.0.1:{port}"));
}

/// Without a configured certificate there is nothing to pin a TLS listener
/// to, so `status` reports it failed for the same reason `epistle probe` does.
#[tokio::test]
async fn a_tls_listener_without_a_configured_certificate_fails() {
	let port = banner(b"").await;
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = with_listeners(
		dir.path(),
		vec![listener(ListenerKind::Imaps, LOOPBACK, port)],
	);
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Fail, "{report:?}");
}

#[tokio::test]
async fn no_listeners_is_a_warning() {
	let dir = tempfile::tempdir().expect("tempdir");
	let ctx = with_listeners(dir.path(), Vec::new());
	let report = check(&ctx).await;
	assert_eq!(report.status, Level::Warn);
	assert_eq!(report.detail, "no listeners are enabled");
}

#[test]
fn unchecked_publications_warn_and_do_not_fail_the_restart_check() {
	let line = |ok, warning, error| crate::cli::probe::ProbeLine {
		kind: "api",
		addr: "10.0.0.1:8025".to_string(),
		ok,
		warning,
		error,
	};
	let report = super::report(
		vec![line(
			false,
			Some("not checkable from here".to_string()),
			None,
		)],
		1,
	);
	assert_eq!(report.status, Level::Warn);
	assert!(
		report
			.detail
			.contains("0 of 1 listeners answer; 1 not checkable from here")
	);
	assert!(!crate::cli::status::report::any_failed(&[(
		crate::cli::status::CheckArea::Ports,
		report
	)]));
	let report = super::report(
		vec![line(false, None, Some("connect: refused".to_string()))],
		1,
	);
	assert_eq!(report.status, Level::Fail);
	let report = super::report(vec![line(true, None, None)], 1);
	assert_eq!(report.status, Level::Ok);
	assert_eq!(report.detail, "1 of 1 listeners answer");
}

#[test]
fn restart_prints_uncheckable_listeners_and_retains_real_failures() {
	use crate::cli::status::CheckArea;
	use crate::cli::status::report::{AreaReport, Item};
	let warning = Item::new("api", Level::Warn, "not checkable from here");
	for failed in [false, true] {
		let mut items = vec![warning.clone()];
		if failed {
			items.push(Item::new("smtp", Level::Fail, "connect: refused"));
		}
		let report = AreaReport::from_items(items, "summary");
		let mut output = Vec::new();
		let failures =
			super::super::restart_failures(vec![(CheckArea::Ports, report)], &mut output);
		assert_eq!(failures.len(), usize::from(failed));
		let text = String::from_utf8(output).unwrap();
		assert!(text.contains("api: not checkable from here"), "{text}");
	}
}
