use std::cell::RefCell;

use super::*;

thread_local! {
	/// The pairs [`shown`] uses on this test's thread instead of the
	/// environment's, which a process reads once.
	pub(in super::super) static OVERRIDE: RefCell<Option<Vec<(String, String)>>> = const { RefCell::new(None) };
}

/// Run `f` with [`shown`] rewriting `staged` to `named`.
pub(crate) fn with_pair<T>(staged: &str, named: &str, f: impl FnOnce() -> T) -> T {
	OVERRIDE.with(|pairs| *pairs.borrow_mut() = Some(vec![(staged.into(), named.into())]));
	let result = f();
	OVERRIDE.with(|pairs| *pairs.borrow_mut() = None);
	result
}

#[test]
fn staged_paths_read_as_the_operators() {
	let encoded = encode(&[
		("/h/.s/0/config".into(), "/etc/mox".into()),
		("/h/.s/0/config/mox.conf".into(), "/etc/mox/mox.conf".into()),
		("/h/.s/1/pw".into(), "/root/pw".into()),
	]);
	let pairs = decode(&encoded);
	assert_eq!(
		replace(
			&pairs,
			"Mox configuration in /h/.s/0/config; passwords are in /h/.s/1/pw"
		),
		"Mox configuration in /etc/mox; passwords are in /root/pw"
	);
	assert_eq!(
		replace(&pairs, "reading /h/.s/0/config/mox.conf: denied"),
		"reading /etc/mox/mox.conf: denied"
	);
	assert_eq!(replace(&[], "unchanged"), "unchanged");
}
