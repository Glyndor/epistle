//! A run cut short, a copy that does not verify, and the journal.

use super::fixture::fixture;
use super::*;

fn acme() -> KeyOwner {
	KeyOwner::Tenant("acme".into())
}

/// Stands in for a crash just before the `n`th rename.
struct CutBefore(usize);

impl Hooks for CutBefore {
	fn before_replace(&mut self, _original: &Path) -> std::io::Result<()> {
		if self.0 == 0 {
			return Err(std::io::Error::other("power cut"));
		}
		self.0 -= 1;
		Ok(())
	}
}

/// Damages the new copy after it is written, as a bad disk would.
struct Corrupt;

impl Hooks for Corrupt {
	fn after_temp_write(&mut self, temp: &Path) -> std::io::Result<()> {
		let mut bytes = std::fs::read(temp)?;
		let last = bytes.len() - 1;
		bytes[last] ^= 0x01;
		std::fs::write(temp, bytes)
	}
}

#[test]
fn a_run_cut_short_loses_nothing_and_the_next_run_finishes_it() {
	let fx = fixture();
	let crypto = fx.crypto();
	let bodies: Vec<Vec<u8>> = (0..4)
		.map(|n| format!("message {n}").into_bytes())
		.collect();
	let paths: Vec<_> = bodies
		.iter()
		.enumerate()
		.map(|(n, body)| fx.store("alice", &format!("new/{n:04}.eml"), body))
		.collect();

	let cut = rekey_account(
		&crypto,
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut CutBefore(2),
	);
	assert!(cut.is_err(), "the cut stops the run");
	// Two files were rewritten, the third is mid-flight, the rest untouched:
	// every one of them still opens to its own bytes.
	for (path, body) in paths.iter().zip(&bodies) {
		let stored = std::fs::read(path).expect("read");
		assert_eq!(
			&crypto.decode(&stored).expect("readable after the cut"),
			body
		);
	}
	let temps = fx
		.files()
		.into_iter()
		.filter(|path| path.to_string_lossy().ends_with(TEMP_SUFFIX))
		.count();
	assert_eq!(temps, 1, "the cut left its temporary file behind");

	let totals = rekey_account(
		&crypto,
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut NoHooks,
	)
	.expect("resume");
	assert_eq!((totals.rewritten, totals.already), (2, 2));
	assert_eq!(
		fx.files(),
		paths,
		"no temporary file left, no copy duplicated"
	);
	for (path, body) in paths.iter().zip(&bodies) {
		let stored = std::fs::read(path).expect("read");
		assert!(matches!(
			crate::storage::envelope_kind(&stored),
			EnvelopeKind::V2(_)
		));
		assert_eq!(&crypto.decode(&stored).expect("open"), body);
	}
}

#[test]
fn a_temporary_file_whose_original_is_gone_is_removed_on_the_next_run() {
	let fx = fixture();
	let crypto = fx.crypto();
	let kept = fx.store("alice", "new/0001.eml", b"kept");
	let expunged = fx.store("alice", "new/0002.eml", b"expunged");
	let cut = rekey_account(
		&crypto,
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut CutBefore(1),
	);
	assert!(cut.is_err());
	// The message the cut was rewriting is expunged before the next run.
	std::fs::remove_file(&expunged).expect("expunge");
	rekey_account(
		&crypto,
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut NoHooks,
	)
	.expect("resume");
	assert_eq!(fx.files(), vec![kept], "the orphan temporary file is gone");
}

#[test]
fn a_copy_that_does_not_verify_never_replaces_the_original() {
	let fx = fixture();
	let crypto = fx.crypto();
	let path = fx.store("alice", "new/0001.eml", b"keep me");
	let before = std::fs::read(&path).expect("read");
	let error = rekey_account(
		&crypto,
		fx.data_dir(),
		"alice",
		&acme(),
		false,
		&mut Corrupt,
	)
	.expect_err("verification fails");
	assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
	assert_eq!(
		std::fs::read(&path).expect("read"),
		before,
		"original intact"
	);
	assert_eq!(fx.files(), vec![path], "the bad copy was removed");
}

#[test]
fn the_journal_round_trips_and_disappears_when_removed() {
	let fx = fixture();
	assert_eq!(journal::read(fx.data_dir()).expect("read"), None);
	let mut entry = Journal::new(Direction::Forward);
	entry.done.push("alice".into());
	entry.rewritten = 3;
	journal::write(fx.data_dir(), &entry).expect("write");
	assert_eq!(journal::read(fx.data_dir()).expect("read"), Some(entry));
	journal::remove(fx.data_dir()).expect("remove");
	assert_eq!(journal::read(fx.data_dir()).expect("read"), None);
}
