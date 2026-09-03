//! Tests for the backup archive builder.

use super::helpers::*;
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn tar_gz_round_trips_entries() {
	let entries = vec![
		("data/a.eml".to_string(), 0o644, b"hello".to_vec()),
		("data/sub/b.eml".to_string(), 0o644, b"world!!".to_vec()),
	];
	let archive = tar_gz(&entries).expect("build");
	let files = read_tar(&gunzip(&archive));
	assert_eq!(files.len(), 2);
	assert_eq!(files[0].0, "data/a.eml");
	assert_eq!(files[0].1, b"hello");
	assert_eq!(files[1].1, b"world!!");
}

#[test]
fn ustar_header_checksum_is_valid() {
	let header = ustar_header("data/x", 0o644, 5).expect("header");
	// The stored checksum equals the sum of the header with the field spaced.
	let stored = usize::from_str_radix(
		String::from_utf8_lossy(&header[148..154])
			.trim_matches('\0')
			.trim(),
		8,
	)
	.expect("octal");
	let mut spaced = header;
	spaced[148..156].copy_from_slice(b"        ");
	let computed: usize = spaced.iter().map(|&b| b as usize).sum();
	assert_eq!(stored, computed);
}

#[test]
fn header_rejects_overlong_name() {
	let long = "data/".to_string() + &"x".repeat(200);
	assert!(ustar_header(&long, 0o644, 0).is_err());
}

#[test]
fn run_archives_the_data_dir() {
	let dir = tempfile::tempdir().expect("tempdir");
	let new = dir.path().join("accounts").join("alice").join("new");
	std::fs::create_dir_all(&new).expect("dirs");
	std::fs::write(new.join("m1.eml"), b"Subject: hi\r\n\r\nbody").expect("write");

	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut out = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(run(&config, &mut out, &mut warnings), ExitCode::SUCCESS);
	let files = read_tar(&gunzip(&out));
	assert!(
		files.iter().any(|(n, _)| n.ends_with("alice/new/m1.eml")),
		"message archived: {:?}",
		files.iter().map(|(n, _)| n).collect::<Vec<_>>()
	);
}

/// A private key written with 0o600 and a publicly-readable file written with
/// 0o644 must round-trip with their respective modes — not collapse to a single
/// default, not get force-clamped to 0o600, not lose the 0o644 readable bits.
#[test]
fn run_preserves_per_file_modes() {
	let dir = tempfile::tempdir().expect("tempdir");

	let private = dir.path().join("dkim").join("private.pem");
	std::fs::create_dir_all(private.parent().unwrap()).expect("dirs");
	std::fs::write(&private, b"-----BEGIN PRIVATE KEY-----\nfake\n-----END\n").expect("write");
	std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).expect("chmod");

	let public_file = dir.path().join("readme.txt");
	std::fs::write(&public_file, b"public content\n").expect("write");
	std::fs::set_permissions(&public_file, std::fs::Permissions::from_mode(0o644)).expect("chmod");

	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let mut out = Vec::new();
	let mut warnings = Vec::new();
	assert_eq!(run(&config, &mut out, &mut warnings), ExitCode::SUCCESS);
	let entries = read_tar_entries(&gunzip(&out));

	let find = |suffix: &str| -> u32 {
		entries
			.iter()
			.find(|(name, _, _)| name.ends_with(suffix))
			.unwrap_or_else(|| {
				panic!(
					"{} not in archive (have {:?})",
					suffix,
					entries.iter().map(|(n, _, _)| n).collect::<Vec<_>>()
				)
			})
			.1
	};

	let private_mode = find("dkim/private.pem");
	assert_eq!(
		private_mode, 0o600,
		"private.pem: expected mode 0o600, found {:o}",
		private_mode
	);

	let public_mode = find("readme.txt");
	assert_eq!(
		public_mode, 0o644,
		"readme.txt: expected mode 0o644, found {:o}",
		public_mode
	);
}

/// `tar -tzvf` must accept the archive as a real USTAR file — not just our
/// in-process parser. We write the archive to disk, invoke the system `tar`,
/// and assert the listing shows each file with its source mode.
#[test]
fn archive_is_a_valid_tar_for_system_tar() {
	let dir = tempfile::tempdir().expect("tempdir");

	let private = dir.path().join("dkim").join("private.pem");
	std::fs::create_dir_all(private.parent().unwrap()).expect("dirs");
	std::fs::write(&private, b"PRIVATE").expect("write");
	std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600)).expect("chmod");

	let public_file = dir.path().join("readme.txt");
	std::fs::write(&public_file, b"PUBLIC").expect("write");
	std::fs::set_permissions(&public_file, std::fs::Permissions::from_mode(0o644)).expect("chmod");

	let toml = format!(
		"hostname = \"mail.example.org\"\ndata_dir = \"{}\"\n",
		dir.path().display()
	);
	let config: Config = toml::from_str(&toml).expect("config");

	let archive_path = dir.path().join("backup.tar.gz");
	let mut file = std::fs::File::create(&archive_path).expect("create archive");
	let mut warnings = Vec::new();
	assert_eq!(
		run(&config, &mut file, &mut warnings),
		ExitCode::SUCCESS,
		"backup run failed"
	);

	let output = std::process::Command::new("tar")
		.args(["-tzvf", archive_path.to_str().expect("utf-8")])
		.output()
		.expect("invoke tar");
	assert!(
		output.status.success(),
		"tar -tzvf failed: status={:?} stderr={}",
		output.status,
		String::from_utf8_lossy(&output.stderr)
	);
	let listing = String::from_utf8_lossy(&output.stdout);

	// `tar -tv` renders permissions as `-rw-------` (0600) and `-rw-r--r--` (0644).
	assert!(
		listing.contains("private.pem") && listing.contains("-rw-------"),
		"tar listing did not show 0600 for private.pem: {listing}"
	);
	assert!(
		listing.contains("readme.txt") && listing.contains("-rw-r--r--"),
		"tar listing did not show 0644 for readme.txt: {listing}"
	);
}
