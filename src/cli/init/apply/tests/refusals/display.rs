//! Every `ApplyError` variant the operator can see on stderr must
//! render without panicking and must carry a path, a reason, or a
//! directive. The Display impl is the contract every failure path
//! relies on, so a regression that drops a field or changes a
//! branch silently would otherwise leave the operator looking at
//! a debug-formatted error.

use std::path::Path;

use super::*;

/// Every `ApplyError` variant the operator can see on stderr must
/// render without panicking and must carry a path, a reason, or a
/// directive. The Display impl is the contract every failure path
/// relies on, so a regression that drops a field or changes a
/// branch silently would otherwise leave the operator looking at
/// a debug-formatted error.
#[test]
fn apply_error_display_messages_for_every_variant() {
	let io = std::io::Error::other("disk full");
	let path = Path::new("/tmp/example").to_path_buf();
	let cases = vec![
		(ApplyError::KeysDir(path.clone(), io), "keys directory"),
		(
			ApplyError::KeyWrite(path.clone(), std::io::Error::other("nope")),
			"key file",
		),
		(ApplyError::OAuthPairIncomplete("a".to_string()), "a"),
		(ApplyError::OAuthPairMismatch, "do not correspond"),
		(ApplyError::CertPairIncomplete("b".to_string()), "b"),
		(ApplyError::ConfigEncode("c".to_string()), "c"),
		(ApplyError::ConfigInvalid("d".to_string()), "d"),
		(
			ApplyError::ConfigRead(path.clone(), std::io::Error::other("perm")),
			"perm",
		),
		(
			ApplyError::ConfigWrite(path.clone(), std::io::Error::other("disk")),
			"disk",
		),
		(
			ApplyError::ConfigDir(path.clone(), std::io::Error::other("mkdir")),
			"mkdir",
		),
		(ApplyError::ConfigSymlink(path.clone()), "symlink"),
	];
	for (error, expected_fragment) in cases {
		let rendered = format!("{error}");
		assert!(
			rendered.contains(expected_fragment),
			"error {error:?} must render with `{expected_fragment}`: {rendered}"
		);
	}
}
