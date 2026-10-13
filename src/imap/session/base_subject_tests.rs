use super::{MAX_SUBJECT, base_subject, extract};
use std::time::{Duration, Instant};

#[test]
fn prefixes_trailers_and_blobs_are_removed() {
	for (raw, base) in [
		("a", "A"),
		("[foo] Fwd: [bar] Re: fw: b (fWd)  (fwd)", "B"),
		("Re: [FWD: c]", "C"),
		("[xyz]", "[XYZ]"),
		("=?iso-8859-1?q?_?=", ""),
		("Re: =?utf-8?q?b?=", "B"),
		("=?iso-8859-1?q?RE:_C?=", "C"),
		("=?us-ascii?b?UmU6IGM=?=", "C"),
		("Ad: Re: Ad: Re: Ad: x", "AD: RE: AD: RE: AD: X"),
		("re: [fwd: [fwd: re: [fwd: babylon]]]", "BABYLON"),
		("b  (a)", "B (A)"),
		("Re:\tRe :  hi", "HI"),
		("[a] [b]", "[B]"),
		("[a][b] x", "X"),
		("[a] [b] re [c]: x", "X"),
		("fwd x", "FWD X"),
		("", ""),
	] {
		assert_eq!(base_subject(raw), base, "{raw}");
	}
}

#[test]
fn only_the_first_8_kib_count() {
	let long = |tail: &str| format!("{}{tail}", "x".repeat(MAX_SUBJECT));
	assert_eq!(base_subject(&long("a")), base_subject(&long("b")));
	assert_eq!(base_subject(&long("a")).len(), MAX_SUBJECT);
	// The cut lands on a character boundary.
	let wide = format!("a{}", "\u{e9}".repeat(MAX_SUBJECT));
	assert!(base_subject(&wide).len() <= MAX_SUBJECT);
}

/// A 1 MiB subject of each shape that makes a step rescan what the previous
/// one left: a leader repeated, blobs with no leader after them, nested
/// `[fwd: ...]` wrappers, and trailers. Each must take well under a second
/// both through the 8 KiB cap and, to show the steps are linear on their
/// own, straight through the extraction with no cap.
#[test]
fn hostile_subjects_take_linear_time() {
	let mebibyte = 1 << 20;
	let nested = mebibyte / 7;
	for subject in [
		"re:".repeat(mebibyte / 3),
		"[a]".repeat(mebibyte / 3),
		"[a] ".repeat(mebibyte / 4) + "x",
		format!("{}x{}", "[fwd: ".repeat(nested), "]".repeat(nested)),
		format!("{}x", "fwd ".repeat(mebibyte / 4)),
		format!("x{}", " (fwd)".repeat(mebibyte / 6)),
	] {
		for (path, run) in [
			("capped", base_subject as fn(&str) -> String),
			("uncapped", extract),
		] {
			let started = Instant::now();
			run(&subject);
			let took = started.elapsed();
			assert!(
				took < Duration::from_millis(500),
				"{path} took {took:?} for {}",
				&subject[..12]
			);
		}
	}
}
