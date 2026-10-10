//! The host-binary ELF static-link decoder and the validator
//! init uses to refuse an apply whose answers leave the mail
//! image unset. The default compose shape runs the host's
//! statically linked `/usr/bin/epistle` bind-mounted read-only
//! into the distroless base; the base image ships no dynamic
//! loader, so the validator must read the ELF bytes on disk and
//! refuse anything that is not a 64-bit, little-endian ELF with
//! no `PT_INTERP` program header. Shelling out to `file`/`ldd`
//! would not be portable; this is plain Rust.

use std::path::Path;

/// How the host binary parses under the in-tree ELF static-link
/// check. `Static` is the only success state; `Dynamic` and
/// `Malformed` are refused with a message that names the .deb the
/// operator is supposed to install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfLinkKind {
	/// File does not start with the ELF magic bytes.
	NotElf,
	/// File looks like an ELF but is missing bytes the decoder
	/// needs (truncated, wrong endianness, wrong EI_CLASS).
	Malformed,
	/// A real ELF whose program-header table contains a
	/// `PT_INTERP` entry, which the distroless base has no
	/// dynamic loader to satisfy.
	Dynamic,
	/// A real ELF with no `PT_INTERP` program header. Accepted.
	Static,
}

/// Look at the bytes of a candidate host binary and decide
/// whether they describe a statically linked 64-bit LSB ELF. The
/// decode is the minimum to spot `PT_INTERP`: the `e_ident`
/// magic (`\x7fELF`, `EI_CLASS == ELFCLASS64`,
/// `EI_DATA == ELFDATA2LSB`), the fixed-size ELF64 header to
/// read `e_phoff` and `e_phnum`, then each program-header table
/// entry to look for `p_type == PT_INTERP`. Any `PT_INTERP` is
/// enough to return `Dynamic`. No `PT_INTERP` (zero or more
/// `PT_LOAD` headers, no dynamic-loader entries) returns
/// `Static`. The distroless base image ships no `/lib64/ld-linux*`
/// or libc, so a dynamic binary cannot run inside the default
/// compose shape and the validator must refuse it.
pub fn classify_elf_link(bytes: &[u8]) -> ElfLinkKind {
	// A truncated file with no ELF magic is genuinely not an
	// ELF. A file that starts with the magic bytes but runs out
	// before `EI_NIDENT` is a different case: it looks like an
	// ELF the operator meant to ship but did not finish writing,
	// and the validator's caller needs to point at it. Return
	// `Malformed` so the diagnostics separate the two shapes
	// rather than collapsing them into `NotElf`.
	const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
	if bytes.len() < 4 || bytes[..4] != ELFMAG {
		return ElfLinkKind::NotElf;
	}
	if bytes.len() < 16 {
		return ElfLinkKind::Malformed;
	}
	// The project ships a 64-bit, little-endian ELF built from
	// a musl target. Any other class or endianness is refused
	// rather than guessed at: a future musl switch to a
	// different `e_machine` is the kind of change that needs a
	// human review, not a silent acceptance.
	if bytes[4] != 2 {
		// ELFCLASS64
		return ElfLinkKind::Malformed;
	}
	if bytes[5] != 1 {
		// ELFDATA2LSB
		return ElfLinkKind::Malformed;
	}
	// ELF64 header: 64 bytes total, but only the bytes we need
	// (`e_phoff` at offset 32, `e_phnum` at offset 56) plus a
	// little tail are read here.
	const EHDR_SIZE: usize = 64;
	if bytes.len() < EHDR_SIZE {
		return ElfLinkKind::Malformed;
	}
	let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
	let e_phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
	let e_phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;
	if e_phnum == 0 {
		return ElfLinkKind::Static;
	}
	const PHDR_SIZE: usize = 56;
	if e_phentsize < PHDR_SIZE {
		return ElfLinkKind::Malformed;
	}
	let Some(end) = e_phoff.checked_add(e_phentsize.saturating_mul(e_phnum)) else {
		return ElfLinkKind::Malformed;
	};
	if end > bytes.len() {
		return ElfLinkKind::Malformed;
	}
	const PT_INTERP: u32 = 3;
	let mut at = e_phoff;
	for _ in 0..e_phnum {
		let p_type = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
		if p_type == PT_INTERP {
			return ElfLinkKind::Dynamic;
		}
		at += e_phentsize;
	}
	ElfLinkKind::Static
}

/// Read the file at `path`, classify its ELF static-link status,
/// and return `Some(message)` if the file is missing or not a
/// static ELF. `None` means the binary is acceptable. The
/// `path` argument is taken explicitly so tests can point the
/// validator at a fixture; production callers pass
/// `super::HOST_EPSTLE_PATH`.
pub fn validate_host_binary_for(path: &Path) -> Option<String> {
	let bytes = match std::fs::read(path) {
		Ok(bytes) => bytes,
		Err(error) => {
			return Some(format!(
				"{} cannot be read: {}; install the epistle .deb (which carries the statically linked binary) or set `image` in the answers to a custom mail image",
				path.display(),
				error,
			));
		}
	};
	match classify_elf_link(&bytes) {
		ElfLinkKind::Static => None,
		ElfLinkKind::NotElf => Some(format!(
			"{} is not an ELF binary; the default compose shape runs the host's statically linked `/usr/bin/epistle` inside the distroless base and needs the binary the epistle .deb ships; install it or set `image` in the answers",
			path.display()
		)),
		ElfLinkKind::Malformed => Some(format!(
			"{} is not a 64-bit, little-endian ELF; the default compose shape runs the host's statically linked `/usr/bin/epistle` inside the distroless base and needs the binary the epistle .deb ships; install it or set `image` in the answers",
			path.display()
		)),
		ElfLinkKind::Dynamic => Some(format!(
			"{} carries a PT_INTERP program header so it is dynamically linked; the default compose shape runs the host's statically linked `/usr/bin/epistle` inside the distroless base, which has no dynamic loader; install the .deb (which links against musl) or set `image` in the answers",
			path.display()
		)),
	}
}
