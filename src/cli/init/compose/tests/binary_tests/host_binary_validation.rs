//! Tests for the host-binary ELF static-link validator. The
//! init phase calls into this when the answers leave the `mail`
//! image unset: the default compose shape runs the host
//! `/usr/bin/epistle` inside the distroless base, so the binary
//! at that path has to be a statically linked ELF with no
//! `PT_INTERP` program header (the base image ships no dynamic
//! loader and shell-outs to `file`/`ldd` are not allowed). The
//! tests build tiny ELF fixtures by writing the header bytes
//! directly, so no third-party binary ships in the repository.

use std::io::Write;

use super::ElfLinkKind;

/// Write a single 64-bit program header (the `Elf64_Phdr`) at
/// `at` inside `buf`. `p_type` and `p_filesz` are the only two
/// fields the decoder looks at; the rest are zeroed because the
/// test does not exercise the loader.
fn write_phdr64(buf: &mut [u8], at: usize, p_type: u32, p_filesz: u64) {
	buf[at..at + 4].copy_from_slice(&p_type.to_le_bytes());
	// p_flags
	buf[at + 4..at + 8].copy_from_slice(&0_u32.to_le_bytes());
	// p_offset, p_vaddr, p_paddr
	buf[at + 8..at + 16].copy_from_slice(&0_u64.to_le_bytes());
	buf[at + 16..at + 24].copy_from_slice(&0_u64.to_le_bytes());
	buf[at + 24..at + 32].copy_from_slice(&0_u64.to_le_bytes());
	// p_filesz / p_memsz (equal here)
	buf[at + 32..at + 40].copy_from_slice(&p_filesz.to_le_bytes());
	buf[at + 40..at + 48].copy_from_slice(&p_filesz.to_le_bytes());
	// p_align
	buf[at + 48..at + 56].copy_from_slice(&0_u64.to_le_bytes());
}

/// Write the e_ident block (16 bytes) at the start of `buf` and
/// advance to the position where the rest of the ELF header will
/// live.
fn write_ident(buf: &mut Vec<u8>, class: u8, data: u8) {
	buf.resize(16, 0);
	let ident = &mut buf[..16];
	ident[0] = 0x7f;
	ident[1] = b'E';
	ident[2] = b'L';
	ident[3] = b'F';
	ident[4] = class;
	ident[5] = data;
	ident[6] = 1; // EV_CURRENT
	ident[7] = 0;
}

/// Build a 64-bit statically linked ELF header that has either
/// zero or one `PT_LOAD` program headers and no other program
/// header types. Returns the bytes.
fn static_elf() -> Vec<u8> {
	let mut buf = Vec::new();
	write_ident(&mut buf, 2, 1); // ELFCLASS64, ELFDATA2LSB
	let header_start = buf.len();
	buf.resize(header_start + 52, 0);
	let h = &mut buf[header_start..];
	// e_type = ET_EXEC (2)
	h[0..2].copy_from_slice(&2_u16.to_le_bytes());
	// e_machine = EM_X86_64 (62)
	h[2..4].copy_from_slice(&62_u16.to_le_bytes());
	// e_version = EV_CURRENT (1)
	h[4..8].copy_from_slice(&1_u32.to_le_bytes());
	// e_entry stays zero
	// e_phoff = 68 (right after the ehdr) so the program header
	// table does not overlap the e_type/e_machine fields the
	// decoder also reads.
	h[16..24].copy_from_slice(&68_u64.to_le_bytes());
	// e_shoff, e_flags stay zero
	// e_ehsize = 64
	h[36..38].copy_from_slice(&64_u16.to_le_bytes());
	// e_phentsize = 56
	h[38..40].copy_from_slice(&56_u16.to_le_bytes());
	// e_phnum = 1
	h[40..42].copy_from_slice(&1_u16.to_le_bytes());
	// e_shentsize, e_shnum, e_shstrndx stay zero
	// Append one PT_LOAD program header at offset 68.
	let phdr_offset = 68;
	buf.resize(phdr_offset + 56, 0);
	write_phdr64(&mut buf, phdr_offset, 1, 0);
	buf
}

/// Build a 64-bit dynamically linked ELF: a single PT_INTERP
/// program header (the marker of dynamic linking). The header
/// identifies the file as ET_DYN rather than ET_EXEC because
/// that is what a PIE-built dynamic link produces.
fn dynamic_elf() -> Vec<u8> {
	let mut buf = Vec::new();
	write_ident(&mut buf, 2, 1);
	let header_start = buf.len();
	buf.resize(header_start + 52, 0);
	let h = &mut buf[header_start..];
	// e_type = ET_DYN (3)
	h[0..2].copy_from_slice(&3_u16.to_le_bytes());
	h[2..4].copy_from_slice(&62_u16.to_le_bytes());
	h[4..8].copy_from_slice(&1_u32.to_le_bytes());
	h[16..24].copy_from_slice(&68_u64.to_le_bytes());
	h[36..38].copy_from_slice(&64_u16.to_le_bytes());
	h[38..40].copy_from_slice(&56_u16.to_le_bytes());
	h[40..42].copy_from_slice(&1_u16.to_le_bytes());
	// One PT_INTERP (type 3) program header at offset 68.
	let phdr_offset = 68;
	buf.resize(phdr_offset + 56, 0);
	write_phdr64(&mut buf, phdr_offset, 3, 0);
	buf
}

#[test]
fn decoder_rejects_a_non_elf_file() {
	assert_eq!(
		super::classify_elf_link(b"#!/bin/sh\necho hello"),
		ElfLinkKind::NotElf,
		"a script with no ELF magic must classify as NotElf"
	);
}

#[test]
fn decoder_rejects_a_truncated_elf_header() {
	assert_eq!(
		super::classify_elf_link(&[0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00]),
		ElfLinkKind::Malformed,
		"a truncated ELF header must classify as Malformed"
	);
}

#[test]
fn decoder_accepts_a_static_elf_with_no_program_headers() {
	// e_phnum = 0: an ELF whose own program-header table is
	// empty cannot reference PT_INTERP, so the decoder must
	// return Static.
	let mut bytes = static_elf();
	// Drop the program header section (it sits at offset 68 in
	// the static layout) so we end up with just the ELF header.
	bytes.truncate(16 + 52);
	// e_phnum lives at h[40..42] (file offset 56-57).
	let h = &mut bytes[16..];
	h[40..42].copy_from_slice(&0_u16.to_le_bytes());
	assert_eq!(
		super::classify_elf_link(&bytes),
		ElfLinkKind::Static,
		"a header-only ELF with no program headers is statically linked"
	);
}

#[test]
fn decoder_accepts_a_static_elf_with_a_pt_load_only() {
	let bytes = static_elf();
	assert_eq!(
		super::classify_elf_link(&bytes),
		ElfLinkKind::Static,
		"a PT_LOAD-only ELF must classify as Static"
	);
}

#[test]
fn decoder_rejects_a_dynamic_elf_with_a_pt_interp_header() {
	let bytes = dynamic_elf();
	assert_eq!(
		super::classify_elf_link(&bytes),
		ElfLinkKind::Dynamic,
		"an ELF carrying PT_INTERP must classify as Dynamic"
	);
}

#[test]
fn decoder_rejects_a_32_bit_elf_it_does_not_know_how_to_handle() {
	// A 32-bit ELF (EI_CLASS = ELFCLASS32) must not be
	// mis-decoded: the decoder was written for the 64-bit case
	// the project ships.
	let mut bytes = static_elf();
	bytes[4] = 0x01; // ELFCLASS32
	assert_eq!(
		super::classify_elf_link(&bytes),
		ElfLinkKind::Malformed,
		"a 32-bit ELF must classify as Malformed (the project ships no 32-bit binary)"
	);
}

#[test]
fn decoder_rejects_a_big_endian_elf() {
	let mut bytes = static_elf();
	bytes[5] = 0x02; // ELFDATA2MSB
	assert_eq!(
		super::classify_elf_link(&bytes),
		ElfLinkKind::Malformed,
		"a big-endian ELF must classify as Malformed (the project ships LE only)"
	);
}

#[test]
fn validator_passes_a_static_elf_with_a_real_file() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("epistle");
	let mut file = std::fs::File::create(&path).unwrap();
	file.write_all(&static_elf()).unwrap();
	drop(file);
	assert!(
		super::validate_host_binary_for(&path).is_none(),
		"a real PT_LOAD-only ELF on disk must validate"
	);
}

#[test]
fn validator_rejects_a_dynamic_elf_with_a_real_file() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("epistle");
	let mut file = std::fs::File::create(&path).unwrap();
	file.write_all(&dynamic_elf()).unwrap();
	drop(file);
	let error = super::validate_host_binary_for(&path).expect("a dynamic ELF must be refused");
	assert!(
		error.contains("PT_INTERP") || error.to_lowercase().contains("static"),
		"the rejection must name PT_INTERP or static; got {error:?}"
	);
}

#[test]
fn validator_rejects_a_missing_file() {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("does-not-exist");
	let error = super::validate_host_binary_for(&path).expect("a missing path must be refused");
	assert!(
		error.contains(&path.display().to_string())
			|| error.to_lowercase().contains("not found")
			|| error.to_lowercase().contains("cannot"),
		"the rejection must name the missing path or a not-found / cannot-read cause; got {error:?}"
	);
}
