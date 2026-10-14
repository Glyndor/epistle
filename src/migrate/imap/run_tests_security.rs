//! `migrate imap` against a server that is hostile, broken or not secure:
//! oversized responses, plaintext, injected STARTTLS data, bad
//! certificates and refused logins.

use zeroize::Zeroizing;

use super::fake_server::{FakeServer, Fault, Mode};
use super::run_tests::{Quiet, folders, large, local, migrate, settings, source, target};
use super::wire::WireError;
use super::*;

#[tokio::test]
async fn a_literal_over_the_limit_fails_cleanly() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut settings = settings();
	settings.limits.literal = 4 * 1024 * 1024;
	server.set_fault(Fault::HugeLiteral {
		size: 4 * 1024 * 1024 + 1,
	});
	let (_, error) = migrate(&server, dir.path(), &settings).await;
	assert!(
		matches!(
			error,
			Some(MigrateError::Client(ClientError::Wire(WireError::LiteralTooLarge { size, .. }))) if size == 4 * 1024 * 1024 + 1
		),
		"{error:?}"
	);
	assert!(
		local(dir.path(), "INBOX").is_empty(),
		"nothing of the batch is stored"
	);
}

#[tokio::test]
async fn a_literal_just_inside_the_limit_is_accepted() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut settings = settings();
	settings.limits.literal = large().len();
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.folders[0].too_large, 0);
	settings.limits.literal = large().len() - 1;
	let other = tempfile::tempdir().expect("tempdir");
	let (summary, error) = migrate(&server, other.path(), &settings).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		summary.folders[0].too_large, 1,
		"an honest oversize message is skipped, not fatal"
	);
}

#[tokio::test]
async fn a_line_over_the_limit_fails_cleanly() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let settings = settings();
	server.set_fault(Fault::LongLine {
		size: settings.limits.line + 1,
	});
	let (_, error) = migrate(&server, dir.path(), &settings).await;
	assert!(
		matches!(error, Some(MigrateError::Client(ClientError::Wire(WireError::LineTooLong(limit)))) if limit == settings.limits.line),
		"{error:?}"
	);
	assert!(local(dir.path(), "INBOX").is_empty());
}

#[tokio::test]
async fn plaintext_is_refused_unless_asked_for() {
	let server = FakeServer::start(Mode::Plain, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	for security in [Security::Tls, Security::StartTls] {
		let mut target = target(dir.path());
		let (_, error) = run(
			&source(&server, security),
			&mut target,
			&settings(),
			&mut Quiet::default(),
		)
		.await;
		let error = error.expect("refused");
		match security {
			Security::StartTls => assert!(
				matches!(error, MigrateError::Client(ClientError::NoStartTls)),
				"{error:?}"
			),
			_ => assert!(
				matches!(error, MigrateError::Client(ClientError::Tls(_))),
				"{error:?}"
			),
		}
	}
	assert_eq!(
		server.logins(),
		0,
		"no credential reached a plaintext server"
	);
	let mut target = target(dir.path());
	let (summary, error) = run(
		&source(&server, Security::Plaintext),
		&mut target,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(error.is_none(), "{error:?}");
	assert!(summary.copied > 0, "the explicit opt-in still works");
	assert_eq!(server.logins(), 1);
}

#[tokio::test]
async fn starttls_upgrades_before_login() {
	let server = FakeServer::start(Mode::StartTls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut target = target(dir.path());
	let (summary, error) = run(
		&source(&server, Security::StartTls),
		&mut target,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.folders[0].copied, 3);
}

#[tokio::test]
async fn a_wrong_password_is_refused_without_echoing_it() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut source = source(&server, Security::Tls);
	source.password = Zeroizing::new(crate::test_fixtures::wrong_password().to_string());
	let mut target = target(dir.path());
	let (_, error) = run(&source, &mut target, &settings(), &mut Quiet::default()).await;
	let error = error.expect("refused");
	assert!(
		matches!(error, MigrateError::Client(ClientError::Auth(_))),
		"{error:?}"
	);
	assert!(!format!("{error} {error:?}").contains(source.password.as_str()));
}

#[tokio::test]
async fn starttls_refuses_data_injected_before_the_handshake() {
	let server = FakeServer::start(Mode::StartTlsInjected, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut target = target(dir.path());
	let (_, error) = run(
		&source(&server, Security::StartTls),
		&mut target,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(
		matches!(&error, Some(MigrateError::Client(ClientError::Protocol(text))) if text.contains("after accepting STARTTLS")),
		"{error:?}"
	);
	assert_eq!(server.logins(), 0);
}

#[tokio::test]
async fn an_untrusted_certificate_is_refused_unless_told_to_skip() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut untrusted = source(&server, Security::Tls);
	untrusted.endpoint.verify = Verify::Roots { extra: Vec::new() };
	let mut target = target(dir.path());
	let (_, error) = run(&untrusted, &mut target, &settings(), &mut Quiet::default()).await;
	assert!(
		matches!(error, Some(MigrateError::Client(ClientError::Tls(_)))),
		"{error:?}"
	);
	let mut wrong_name = source(&server, Security::Tls);
	wrong_name.endpoint.host = "other.example.org".to_string();
	let (_, error) = run(&wrong_name, &mut target, &settings(), &mut Quiet::default()).await;
	assert!(
		matches!(error, Some(MigrateError::Client(ClientError::Tls(_)))),
		"{error:?}"
	);
	assert_eq!(server.logins(), 0);
	let mut skipping = source(&server, Security::Tls);
	skipping.endpoint.verify = Verify::Skip;
	skipping.endpoint.host = "other.example.org".to_string();
	let (summary, error) = run(&skipping, &mut target, &settings(), &mut Quiet::default()).await;
	assert!(error.is_none(), "{error:?}");
	assert!(summary.copied > 0);
	let _ = server.cert();
}
