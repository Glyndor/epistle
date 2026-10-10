//! The answers-image validator. The apply phase trusts what the
//! validator passed, so a regression here surfaces only when an
//! operator types an image the apply path never sees; the tests
//! here drive the validator through every shape the production
//! path can be asked to render (empty, whitespace, registry-port
//! forms, short references, compose interpolation).

use super::*;
use crate::cli::init::Answers;
use crate::cli::init::answers::Invalid;

#[test]
fn image_validation_rejects_empty_and_whitespace() {
	// The answers validator catches empty / whitespace-only
	// `image` values; the compose writer itself trusts
	// what the validator passed.
	let mut answers = minimal_answers();
	answers.image = Some("".to_string());
	assert!(answers.validate().is_err());
	answers.image = Some("with space".to_string());
	assert!(answers.validate().is_err());
	answers.image = Some("localhost/epistle:dev".to_string());
	assert!(answers.validate().is_ok());
}

/// The default `image` resolved when the operator does not set one
/// pins the `<MAJOR.MINOR>` prefix of `CARGO_PKG_VERSION` (not
/// the full `X.Y.Z` patch, not `latest`, and not an untagged
/// reference). The override path uses whatever the operator
/// typed verbatim, as long as the override itself carries a
/// tag that is not `latest` or a `@sha256:` digest.
#[test]
fn image_default_and_override_resolve_to_the_expected_references() {
	let version = env!("CARGO_PKG_VERSION");
	let mut parts = version.split('.');
	let major = parts.next().expect("major");
	let minor = parts.next().expect("minor");
	let expected_default = format!("ghcr.io/glyndor/epistle:{}.{}", major, minor);
	let default = super::default_image();
	assert_eq!(
		default, expected_default,
		"the default image must pin the MAJOR.MINOR of CARGO_PKG_VERSION; \
		 a release of 0.9.0 must produce ghcr.io/glyndor/epistle:0.9"
	);
	assert!(
		!default.contains("latest") && default.contains(':'),
		"the default must carry a tag that is not 'latest'; got {default}"
	);
	assert!(
		!default.contains('@'),
		"the default uses a tag, not a digest; got {default}"
	);
	let from_none = super::resolve_image(None);
	assert_eq!(from_none, default);
	let image = super::resolve_image(Some("localhost/epistle:dev"));
	assert_eq!(image, "localhost/epistle:dev");
	let pinned = super::resolve_image(Some(
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000",
	));
	assert_eq!(
		pinned,
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	);
}

/// Every image the compose writer pins must carry either a
/// `<MAJOR.MINOR>`-style tag (not `latest`) or a `@sha256:`
/// digest. The answers validator catches operator overrides
/// that miss the rule; the default image is also covered by
/// `image_default_and_override_resolve_to_the_expected_references`.
#[test]
fn image_validator_rejects_untagged_or_latest_references() {
	fn first_invalid(answers: &Answers) -> Invalid {
		answers
			.validate()
			.expect_err("the answers must fail validation")
			.into_iter()
			.next()
			.expect("at least one error")
	}
	// No tag at all: a `localhost/epistle` reference defaults to
	// `:latest` on the daemon, which the validator refuses.
	let mut answers = minimal_answers();
	answers.image = Some("localhost/epistle".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Explicit `:latest`: no better than no tag.
	answers.image = Some("localhost/epistle:latest".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Digest without the `sha256:` algorithm: refused.
	answers.image = Some("localhost/epistle@md5:deadbeef".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// A pinned tag and a sha256 digest are both accepted.
	answers.image = Some("localhost/epistle:1.2.3".to_string());
	assert!(answers.validate().is_ok());
	answers.image = Some(
		"localhost/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
			.to_string(),
	);
	assert!(answers.validate().is_ok());
}

/// The tag separator is the last `:` after the last `/`; a `:`
/// before the last `/` is a registry-port separator and must
/// not be read as a tag. The previous `rsplit_once(':')` shape
/// mistook the registry port for a tag and let
/// `localhost:5000/epistle` through (the daemon would then
/// default to `:latest`), and let
/// `localhost/epistle:${TAG:-latest}` through (the compose
/// writer would have emitted the literal `$`, which the daemon
/// then refuses). The new shape catches both, plus the explicit
/// `localhost:5000/epistle:1.2` accept case.
#[test]
fn image_validator_handles_registry_port_and_compose_interpolation() {
	fn first_invalid(answers: &Answers) -> Invalid {
		answers
			.validate()
			.expect_err("the answers must fail validation")
			.into_iter()
			.next()
			.expect("at least one error")
	}
	let mut answers = minimal_answers();
	// Registry port, no tag: refused. The old shape saw the
	// `:` between `localhost` and `5000` and read `5000/epistle`
	// as the tag, which is neither `latest` nor empty and so
	// slipped through; the daemon would then default to
	// `:latest` and pull a moving reference.
	answers.image = Some("localhost:5000/epistle".to_string());
	assert!(matches!(first_invalid(&answers), Invalid::ImageUntagged(_)));
	// Registry port with an explicit tag: accepted. The
	// `:` after the last `/` separates the tag, and the `5000`
	// is read as the registry port.
	answers.image = Some("localhost:5000/epistle:1.2".to_string());
	assert!(answers.validate().is_ok());
	// Digest form, with a real registry: accepted. The
	// `:` in `sha256:` is the digest algorithm separator, not
	// a tag separator.
	answers.image = Some(
		"ghcr.io/glyndor/epistle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
			.to_string(),
	);
	assert!(answers.validate().is_ok());
	// Compose interpolation: refused. The literal `$` would
	// land in the rendered compose file, the daemon would
	// refuse the reference, and the operator would see a
	// fail at `podup up` time rather than at `init` time.
	answers.image = Some("localhost/epistle:${TAG:-latest}".to_string());
	assert!(matches!(
		first_invalid(&answers),
		Invalid::ImageMalformed(_)
	));
	// Bare `$` somewhere else in the reference: also refused.
	answers.image = Some("ghcr.io/glyndor/$epistle:1.2".to_string());
	assert!(matches!(
		first_invalid(&answers),
		Invalid::ImageMalformed(_)
	));
}

/// A reference that has no path component (no `/` in the
/// reference at all, e.g. `epistle:dev`, the form a local
/// build with `podman build -t epistle:dev .` produces) has
/// no registry-port branch: the only `:` in the reference is
/// the tag separator. The previous shape
/// (`image.rfind('/').and_then(...)` returning `None` when
/// the reference has no `/`) read a missing `/` as a missing
/// tag and refused every short reference with
/// `ImageUntagged`; the operator had to spell out
/// `localhost/epistle:dev` for a local build, which is
/// surprising because `podman build -t epistle:dev .` is the
/// recipe in the project docs. The fix finds the last `:` in
/// the segment after the last `/` (or in the whole reference
/// when there is no `/`); `epistle:dev` now parses with tag
/// `dev` and the override is accepted.
#[test]
fn image_validator_accepts_a_short_reference_with_no_path() {
	let mut answers = minimal_answers();
	// Short reference, no `/`, with a non-latest tag: accepted.
	// This is the form `podman build -t epistle:dev .`
	// produces and the local bring-up recipe in the project
	// docs uses.
	answers.image = Some("epistle:dev".to_string());
	assert!(
		answers.validate().is_ok(),
		"a short reference like `epistle:dev` must validate: {:?}",
		answers.validate()
	);
	// Short reference, no `/`, no tag: still refused.
	answers.image = Some("epistle".to_string());
	assert!(matches!(
		answers
			.validate()
			.expect_err("an untagged short reference must fail")
			.into_iter()
			.next()
			.expect("at least one error"),
		Invalid::ImageUntagged(_)
	));
	// Short reference, no `/`, explicit `:latest`: refused
	// (`:latest` is no better than no tag).
	answers.image = Some("epistle:latest".to_string());
	assert!(matches!(
		answers
			.validate()
			.expect_err("an explicit `:latest` must fail")
			.into_iter()
			.next()
			.expect("at least one error"),
		Invalid::ImageUntagged(_)
	));
}
