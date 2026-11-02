//! An issued pair that is not usable must not replace the one in use.

use super::*;

fn good_pair(dir: &Path) -> (String, String) {
	let (cert, key) = issued_certificate(2030, 10, 28);
	fs::create_dir_all(dir.join("acme")).expect("ACME directory");
	let (cert, key) = (cert.pem(), key.serialize_pem());
	fs::write(cert_path(dir), &cert).expect("certificate file");
	fs::write(key_path(dir), &key).expect("key file");
	(cert, key)
}

fn reloadable(cert: &str, key: &str) -> ReloadableAcceptor {
	ReloadableAcceptor::new(
		crate::tls::acceptor_from_pem(cert.as_bytes(), key.as_bytes()).expect("acceptor"),
	)
}

#[test]
fn a_chain_the_key_does_not_belong_to_leaves_the_pair_in_use_alone() {
	let dir = tempfile::tempdir().expect("directory");
	let (cert, key) = good_pair(dir.path());
	let reloadable = reloadable(&cert, &key);
	let (other_cert, _) = issued_certificate(2031, 1, 1);
	let (_, own_key) = issued_certificate(2031, 1, 1);

	let refused = install(
		dir.path(),
		&other_cert.pem(),
		&own_key.serialize_pem(),
		Some(&reloadable),
	);

	assert!(matches!(refused, Err(AcmeError::Protocol(_))));
	assert_eq!(
		fs::read_to_string(cert_path(dir.path())).expect("cert"),
		cert
	);
	assert_eq!(fs::read_to_string(key_path(dir.path())).expect("key"), key);
}

#[test]
fn a_chain_that_does_not_parse_leaves_the_pair_in_use_alone() {
	let dir = tempfile::tempdir().expect("directory");
	let (cert, key) = good_pair(dir.path());
	let reloadable = reloadable(&cert, &key);

	let refused = install(dir.path(), "not a certificate", &key, Some(&reloadable));

	assert!(refused.is_err());
	assert_eq!(
		fs::read_to_string(cert_path(dir.path())).expect("cert"),
		cert
	);
	assert_eq!(fs::read_to_string(key_path(dir.path())).expect("key"), key);
}

#[test]
fn a_good_pair_replaces_both_files_and_keeps_their_modes() {
	use std::os::unix::fs::PermissionsExt;
	let dir = tempfile::tempdir().expect("directory");
	let (cert, key) = good_pair(dir.path());
	let reloadable = reloadable(&cert, &key);
	let (new_cert, new_key) = issued_certificate(2031, 1, 1);
	let (new_cert, new_key) = (new_cert.pem(), new_key.serialize_pem());

	install(dir.path(), &new_cert, &new_key, Some(&reloadable)).expect("install");

	assert_eq!(
		fs::read_to_string(cert_path(dir.path())).expect("cert"),
		new_cert
	);
	assert_eq!(
		fs::read_to_string(key_path(dir.path())).expect("key"),
		new_key
	);
	let mode = |path: PathBuf| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
	assert_eq!(mode(key_path(dir.path())), 0o600);
	assert_eq!(mode(cert_path(dir.path())), 0o644);
}

/// The certificates container presents nothing: the files are the whole
/// result, judged the same way before they replace the pair on disk.
#[test]
fn without_an_acceptor_a_good_pair_still_replaces_the_files() {
	let dir = tempfile::tempdir().expect("directory");
	good_pair(dir.path());
	let (new_cert, new_key) = issued_certificate(2031, 1, 1);
	let (new_cert, new_key) = (new_cert.pem(), new_key.serialize_pem());

	install(dir.path(), &new_cert, &new_key, None).expect("install");

	assert_eq!(
		fs::read_to_string(cert_path(dir.path())).expect("cert"),
		new_cert
	);
	assert_eq!(
		fs::read_to_string(key_path(dir.path())).expect("key"),
		new_key
	);
}

#[test]
fn without_an_acceptor_a_mismatched_pair_is_still_refused() {
	let dir = tempfile::tempdir().expect("directory");
	let (cert, key) = good_pair(dir.path());
	let (other_cert, _) = issued_certificate(2031, 1, 1);
	let (_, own_key) = issued_certificate(2031, 1, 1);

	let refused = install(
		dir.path(),
		&other_cert.pem(),
		&own_key.serialize_pem(),
		None,
	);

	assert!(matches!(refused, Err(AcmeError::Protocol(_))));
	assert_eq!(
		fs::read_to_string(cert_path(dir.path())).expect("cert"),
		cert
	);
	assert_eq!(fs::read_to_string(key_path(dir.path())).expect("key"), key);
}
