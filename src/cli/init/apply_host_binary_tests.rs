//! Tests that the apply path refuses to write the compose
//! file when the host binary is missing or not statically
//! linked, except in custom image mode (where no host binary is
//! bind-mounted).

use std::path::{Path, PathBuf};

use super::*;
use crate::cli::init::answers::{Mode, Services as AnswersServices};

fn answers_with_image(image: Option<&str>) -> Answers {
	let mut answers = Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		acme: None,
		dns: None,
		services: AnswersServices {
			imap: true,
			submission: true,
			pop3: false,
			managesieve: false,
			webdav: false,
			api: false,
			database: false,
		},
		image: image.map(str::to_string),
	};
	answers.normalise();
	answers
}

/// Write a synthetic statically linked 64-bit LE ELF with only a
/// single `PT_LOAD` program header and no `PT_INTERP`. Mirrors
/// the structure the production `Cargo.toml` builds with the
/// musl target.
fn static_elf_bytes() -> Vec<u8> {
	let mut buf = Vec::new();
	buf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00]);
	buf.resize(16 + 52, 0);
	let header = &mut buf[16..];
	header[0..2].copy_from_slice(&2_u16.to_le_bytes()); // e_type = ET_EXEC
	header[2..4].copy_from_slice(&62_u16.to_le_bytes()); // e_machine = EM_X86_64
	header[4..8].copy_from_slice(&1_u32.to_le_bytes()); // e_version
	// e_phoff lives at h[16..24] of the ehdr (file offset 32-39).
	// Place the program-header table at offset 68 so it does not
	// overlap the e_type/e_machine fields the decoder also reads.
	header[16..24].copy_from_slice(&68_u64.to_le_bytes());
	// e_ehsize, e_phentsize, e_phnum follow.
	header[36..38].copy_from_slice(&64_u16.to_le_bytes()); // e_ehsize
	header[38..40].copy_from_slice(&56_u16.to_le_bytes()); // e_phentsize
	header[40..42].copy_from_slice(&1_u16.to_le_bytes()); // e_phnum = 1
	buf.resize(68 + 56, 0);
	let phdr = &mut buf[68..];
	phdr[0..4].copy_from_slice(&1_u32.to_le_bytes()); // p_type = PT_LOAD
	buf
}

fn stage_tempdir() -> tempfile::TempDir {
	tempfile::tempdir().unwrap()
}

fn lay_fake_binary(into: &Path, name: &str, bytes: &[u8]) -> PathBuf {
	let path = into.join(name);
	std::fs::write(&path, bytes).unwrap();
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::Permissions::from_mode(0o755);
		std::fs::set_permissions(&path, mode).unwrap();
	}
	path
}

/// The happy path: when the answers leave `image` unset, init
/// can render the compose for inspection against a real
/// statically linked ELF on disk.
#[test]
fn default_mode_renders_the_compose_for_a_static_host_binary() {
	let dir = stage_tempdir();
	let host = lay_fake_binary(dir.path(), "epistle", &static_elf_bytes());
	let answers = answers_with_image(None);
	let rendered = super::render_for_with_host_binary(&answers, false, &host).expect("render");
	let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
	assert_eq!(
		value["services"]["mail"]["entrypoint"][0], "/usr/bin/epistle",
		"default mode must set the entrypoint to the host binary path the test staged"
	);
}

/// When the staged "host" binary is dynamically linked, the
/// render hook used by the apply phase must refuse rather than
/// emit a broken compose.
#[test]
fn default_mode_refuses_a_dynamic_host_binary() {
	let dir = stage_tempdir();
	let dynamic = {
		let mut bytes = static_elf_bytes();
		// Replace the PT_LOAD type with PT_INTERP (3) at the
		// phdr offset the static layout uses (68). The phdr's
		// `p_type` is the first 4 bytes of the entry.
		let phdr_type_offset = 68;
		bytes[phdr_type_offset..phdr_type_offset + 4].copy_from_slice(&3_u32.to_le_bytes());
		bytes
	};
	let host = lay_fake_binary(dir.path(), "epistle", &dynamic);
	let answers = answers_with_image(None);
	let error = super::render_for_with_host_binary(&answers, false, &host)
		.expect_err("dynamic host binary must be refused");
	let message = error.to_string();
	assert!(
		message.contains("PT_INTERP") || message.to_lowercase().contains("static"),
		"the refusal must name PT_INTERP or static; got {message:?}"
	);
}

/// When the staged "host" binary is missing, the render hook
/// used by the apply phase must refuse rather than emit a
/// broken compose.
#[test]
fn default_mode_refuses_a_missing_host_binary() {
	let dir = stage_tempdir();
	let host = dir.path().join("does-not-exist");
	let answers = answers_with_image(None);
	let error = super::render_for_with_host_binary(&answers, false, &host)
		.expect_err("missing host binary must be refused");
	let message = error.to_string();
	assert!(
		message.to_lowercase().contains("not found") || message.to_lowercase().contains("cannot"),
		"the refusal must mention not-found or cannot; got {message:?}"
	);
}

/// Custom image mode skips the host-binary check entirely: an
/// operator who pinned their own image is allowed to render the
/// compose even when no host binary is around.
#[test]
fn custom_image_mode_skips_the_host_binary_check() {
	let dir = stage_tempdir();
	let host = dir.path().join("does-not-exist");
	let answers = answers_with_image(Some("localhost/epistle:dev"));
	let _ = super::render_for_with_host_binary(&answers, true, &host)
		.expect("custom image mode must not consult the host binary");
}
