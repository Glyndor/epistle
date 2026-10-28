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
/// The fastest of three runs, so a busy machine adds as little noise as it
/// can to a timing comparison.
fn fastest(run: fn(&str) -> String, subject: &str) -> Duration {
	(0..3)
		.map(|_| {
			let started = Instant::now();
			run(subject);
			started.elapsed()
		})
		.min()
		.unwrap_or_default()
}

/// Growth, not wall clock: eight times the input must cost about eight
/// times the work. A quadratic path costs about 64 times, and an absolute
/// bound failed on a loaded machine even when the code was linear.
/// The short run is floored at 5 ms so a few microseconds of scheduler
/// noise on a busy machine cannot make the ratio look quadratic.
#[test]
fn hostile_subjects_take_linear_time() {
	let small = 1 << 14;
	let shapes: [fn(usize) -> String; 6] = [
		|n| "re:".repeat(n / 3),
		|n| "[a]".repeat(n / 3),
		|n| "[a] ".repeat(n / 4) + "x",
		|n| format!("{}x{}", "[fwd: ".repeat(n / 7), "]".repeat(n / 7)),
		|n| format!("{}x", "fwd ".repeat(n / 4)),
		|n| format!("x{}", " (fwd)".repeat(n / 6)),
	];
	for shape in shapes {
		let (short, long) = (shape(small), shape(small * 8));
		for (path, run) in [
			("capped", base_subject as fn(&str) -> String),
			("uncapped", extract),
		] {
			let base = fastest(run, &short).max(Duration::from_millis(5));
			let grown = fastest(run, &long);
			assert!(
				grown < base * 24 && grown < Duration::from_secs(5),
				"{path} went from {base:?} to {grown:?} for {}",
				&long[..12]
			);
		}
	}
}

#[test]
fn reply_and_forward_markers_are_reported() {
	use super::base_subject_and_reply;
	for (raw, base, reply) in [
		("foo", "FOO", false),
		("Re: foo", "FOO", true),
		("[list] Fwd: foo", "FOO", true),
		("foo (fwd)", "FOO", true),
		("[fwd: foo]", "FOO", true),
		("[list] foo", "FOO", false),
		("Ref: foo", "REF: FOO", false),
		("re:", "", true),
	] {
		assert_eq!(
			base_subject_and_reply(raw),
			(base.to_string(), reply),
			"{raw:?}"
		);
	}
}
