//! Answers unit tests for the empty/whitespace-only DNS token sources.
//!
//! Lifted out of `answers_tests.rs` to keep it under the per-file
//! line limit. The assistant already trims before storing an empty
//! prompt answer as `None`; the file path used to keep the literal
//! `Some("")` and treat it as a present source. The shared validator
//! now treats an empty or whitespace-only value in any of the three
//! sources (`token`, `token_file`, `token_env`) as absent, so the
//! assistant and the file path reject the same input with the same
//! sentence.

use std::path::PathBuf;

use super::*;
use Mode::*;

fn minimal(mode: Mode) -> Answers {
	Answers {
		mode,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: None,
		public_ipv6: None,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: None,
	}
}

/// Empty `dns.token` in the answers file must NOT count as a present
/// token source: the assistant already trims before storing, so an
/// empty line on the prompt stays empty in the file, and the file
/// must reject it with the same `DnsTokenMissing` the assistant would
/// have produced.
#[test]
fn empty_dns_token_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some(String::new()),
		token_file: None,
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("empty token must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token` (a stray space the operator hit on the
/// keyboard by accident) must NOT count as a present source either.
#[test]
fn whitespace_only_dns_token_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some("   ".to_string()),
		token_file: None,
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Empty `dns.token_file` in the answers file must NOT count as a
/// present source: the file path preserves the literal string the
/// operator wrote, and `token_file = ""` is the same shape an empty
/// prompt would produce.
#[test]
fn empty_dns_token_file_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::new()),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("empty token_file must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token_file must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token_file` (a stray path with spaces) must
/// NOT count as a present source either.
#[test]
fn whitespace_only_dns_token_file_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("   ")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token_file must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token_file must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Empty `dns.token_env` in the answers file must NOT count as a
/// present source.
#[test]
fn empty_dns_token_env_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: None,
		token_env: Some(String::new()),
	});
	let errors = answers
		.validate()
		.expect_err("empty token_env must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"empty token_env must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// Whitespace-only `dns.token_env` must NOT count as a present source.
#[test]
fn whitespace_only_dns_token_env_field_is_treated_as_absent() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: None,
		token_env: Some("   ".to_string()),
	});
	let errors = answers
		.validate()
		.expect_err("whitespace token_env must count as absent");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsTokenMissing)),
		"whitespace token_env must surface as DnsTokenMissing, got {errors:?}"
	);
}

/// The assistant and the file path must reject the same empty value
/// with the same `Invalid` variant: `token_file = ""` from the file
/// and the assistant (which never stores an empty value as Some) both
/// surface as `DnsTokenMissing` after a non-empty provider/zone have
/// been supplied.
#[test]
fn empty_token_file_in_file_and_assistant_produce_the_same_invalid() {
	let from_file = {
		let mut answers = minimal(Automatic);
		answers.dns = Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::new()),
			token_env: None,
		});
		answers.validate().expect_err("file: empty token_file")
	};
	// The assistant never stores an empty value as Some: it calls
	// `(!token.is_empty()).then_some(...)`. So the assistant shape
	// is `None`, not `Some("")`. The validator must reject the
	// assistant shape with the same variant.
	let from_assistant = {
		let mut answers = minimal(Automatic);
		answers.dns = Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: None,
			token_env: None,
		});
		answers.validate().expect_err("assistant: empty token_file")
	};
	let file_has_missing = from_file
		.iter()
		.any(|e| matches!(e, Invalid::DnsTokenMissing));
	let assistant_has_missing = from_assistant
		.iter()
		.any(|e| matches!(e, Invalid::DnsTokenMissing));
	assert!(
		file_has_missing && assistant_has_missing,
		"both paths must surface DnsTokenMissing: file={from_file:?}, assistant={from_assistant:?}"
	);
}

/// A Unicode zone with its Unicode domain must validate: the
/// previous shape compared the raw U-label zone against an A-label
/// domain and rejected a perfectly aligned pair. The shared
/// validator now normalises the zone before the scope check, so the
/// two spellings of one domain produce the same outcome.
#[test]
fn unicode_dns_zone_with_its_unicode_domain_validates() {
	let mut answers = minimal(Automatic);
	answers.domains = vec!["bücher.example.org".to_string()];
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "bücher.example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let result = answers.validate();
	assert!(
		result.is_ok(),
		"unicode zone with matching unicode domain must validate, got {result:?}"
	);
}

/// A zone that is not a valid domain name (`zone = "invalid"`) must
/// surface as `Invalid::DnsZoneMalformed` from the file path. The
/// shared validator runs `crate::domain::normalize` on the zone
/// before the scope check; the same shape would be rejected by the
/// assistant because `ask_domain` runs the same normaliser on
/// every prompt line.
#[test]
fn invalid_dns_zone_in_answers_file_fails_validation() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "invalid".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("invalid zone must surface as DnsZoneMalformed");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsZoneMalformed { .. })),
		"invalid zone must surface as DnsZoneMalformed, got {errors:?}"
	);
}

/// A zone with a confusable look-alike (Cyrillic that looks like
/// `paypal.com`) must surface as `DnsZoneMalformed`. The same shape
/// in the assistant is rejected by `ask_domain` because the prompt
/// helper runs the same normaliser.
#[test]
fn confusable_dns_zone_in_answers_file_fails_validation() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "\u{0440}\u{0430}\u{04cf}pal.com".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("confusable zone must surface as DnsZoneMalformed");
	let has_zone_invalid = errors
		.iter()
		.any(|e| matches!(e, Invalid::DnsZoneMalformed { .. }));
	let has_zone_scope = errors.iter().any(|e| {
		matches!(
			e,
			Invalid::DnsZoneMalformed {
				reason,
				..
			} if reason.contains("confusable")
		)
	});
	assert!(
		has_zone_invalid && has_zone_scope,
		"confusable zone must surface as DnsZoneMalformed with the confusable reason: {errors:?}"
	);
}

/// `config_path = "/"` is absolute and so passed the absolute check,
/// but the apply phase would discover it has no file name only after
/// creating the data directory and writing every key. The validator
/// now catches the missing file name before any effect, so the run
/// exits 2 with nothing on disk.
#[test]
fn config_path_root_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/");
	let errors = answers
		.validate()
		.expect_err("config_path = `/` must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"root config_path must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = "."` (current directory) has no file name to stage
/// next to. Same shape as the root case: the validator catches it
/// before any effect.
#[test]
fn config_path_current_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from(".");
	// `path.file_name()` on `.` returns None, which is the right shape
	// to test; but `.` is not absolute, so absolute check fires first.
	// Use an absolute equivalent that the absolute check passes but
	// `file_name()` returns None for. The apply phase's
	// `write_validated_config` accepts `/` (no file name) and rejects
	// `/.` (file name = `.`), so we test the second shape against the
	// validator's same rule.
	answers.config_path = PathBuf::from("/.");
	let errors = answers
		.validate()
		.expect_err("config_path = `/.` must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/.` config_path must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path == data_dir` would let the staging step land the
/// config inside the data directory and overwrite a key. The
/// validator catches the equality before any effect.
#[test]
fn config_path_equals_data_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle");
	let errors = answers
		.validate()
		.expect_err("config_path == data_dir must be rejected by the validator");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathEqualsDataDir)),
		"config_path == data_dir must surface as ConfigPathEqualsDataDir, got {errors:?}"
	);
}

/// `config_path = "/x/etc/."` (text ending in `/.`) must surface as
/// `ConfigPathNoFileName` from the validator: the last
/// `Path::components()` slot is `CurDir`, not `Normal`. The shape
/// would otherwise pass through to the apply phase, write every
/// key, then fail at the staging step with `Is a directory`.
#[test]
fn config_path_trailing_dot_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/.");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/.` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/.` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// Acceptance half of the trailing-dot pair: a `config_path` whose
/// last component is a real file name must validate. Without this
/// test, a path-check that refused every absolute path would still
/// satisfy the rejection test above.
#[test]
fn config_path_real_file_name_validates() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/x/etc/mail.toml` must validate, got {:?}",
		answers.validate()
	);
}

/// `config_path = "/x/etc/.."` (text ending in `/..`) must surface
/// as `ConfigPathNoFileName`: the last `components()` slot is
/// `ParentDir`. Without this check the staging step would try to
/// stage a sibling of the parent and the apply phase would still
/// fail after every key was written.
#[test]
fn config_path_dot_dot_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/..");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/..` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/..` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = "/x/etc/"` (text ending in a bare `/`) must
/// surface as `ConfigPathNoFileName`: `Path::components()` for
/// that path returns `Normal("etc")` as the last entry, so the
/// components check alone would not catch it. The validator's
/// trailing-separator rule handles the literal string.
#[test]
fn config_path_trailing_slash_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("/x/etc/");
	let errors = answers
		.validate()
		.expect_err("config_path = `/x/etc/` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNoFileName)),
		"`/x/etc/` must surface as ConfigPathNoFileName, got {errors:?}"
	);
}

/// `config_path = <data_dir>/keys/s1.pem` would let the staging
/// step land a temp file inside the keys directory the same run is
/// about to write. The validator catches the componentwise
/// containment before any effect.
#[test]
fn config_path_inside_keys_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/keys/s1.pem");
	let errors = answers
		.validate()
		.expect_err("config_path inside keys dir must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathInsideKeysDir)),
		"config_path inside keys must surface as ConfigPathInsideKeysDir, got {errors:?}"
	);
}

/// Acceptance half of the keys-dir pair: a `config_path` that is
/// a sibling of `keys` (a directory the operator owns) must
/// validate. The `config_path` itself has to live outside
/// `data_dir` (a separate validator check), so the test puts it
/// at `/etc/epistle/mail.toml` with `data_dir = /var/lib/epistle`
/// the standard layout the operator runs in production.
#[test]
fn config_path_data_dir_sibling_validates() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/etc/epistle/mail.toml` next to `/var/lib/epistle` must validate, got {:?}",
		answers.validate()
	);
}

/// `config_path = <data_dir>/keys/sub/mail.toml` is deeper inside
/// the keys directory; the validator must refuse with the same
/// `ConfigPathInsideKeysDir` variant.
#[test]
fn config_path_inside_keys_subdir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/keys/sub/mail.toml");
	let errors = answers
		.validate()
		.expect_err("config_path inside keys/sub must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathInsideKeysDir)),
		"config_path inside keys/sub must surface as ConfigPathInsideKeysDir, got {errors:?}"
	);
}

/// A `keysfoo` directory next to `keys` is a sibling the operator
/// owns, not a componentwise child of `keys`. The validator must
/// accept it: the prefix match is on the basename, not the
/// component. The config file has to live outside `data_dir`
/// (a separate validator check), so the test puts the sibling
/// `keysfoo` directory under `/var/lib`, next to the
/// data_dir, and points the config inside it.
#[test]
fn config_path_keys_prefix_sibling_validates() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/keysfoo/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"`/var/lib/keysfoo/mail.toml` next to `/var/lib/epistle` must validate, got {:?}",
		answers.validate()
	);
}

/// `services.database` is the one field with no `serde(default)`. An
/// answers file that omits it must fail to deserialise with an error
/// the operator can act on; a silent default would let a hand-typed
/// file skip the choice.
#[test]
fn services_database_is_required() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n\
		[services]\n\
		imap = true\n\
		submission = true\n";
	let result: Result<Answers, _> = toml::from_str(toml_text);
	let error = result.expect_err("missing services.database must fail to deserialise");
	let rendered = error.to_string();
	assert!(
		rendered.contains("services.database") || rendered.contains("database"),
		"the parser error must name the missing field, got: {rendered}"
	);
}

/// Both `database = true` and `database = false` are accepted. The
/// `Services` Default impl covers `false`; a hand-typed `true` in an
/// answers file is the other half the operator can ask for.
#[test]
fn services_database_true_and_false_accepted() {
	let base = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n\
		[services]\n\
		imap = true\n\
		submission = true\n";
	let with_true = format!("{base}database = true\n");
	let parsed: Answers = toml::from_str(&with_true).expect("database = true parses");
	assert!(parsed.services.database);
	assert!(parsed.validate().is_ok(), "database = true must validate");
	let with_false = format!("{base}database = false\n");
	let parsed: Answers = toml::from_str(&with_false).expect("database = false parses");
	assert!(!parsed.services.database);
	assert!(parsed.validate().is_ok(), "database = false must validate");
}

/// The whole `[services]` table is required: an answers file that
/// omits it must fail to deserialise with an error that names the
/// missing section. A silent default would let a hand-typed file
/// skip the explicit choice of `database = true | false` and the
/// stack would come up without the postgres antispam features the
/// operator might have wanted. The error path is the parser, not
/// the validator: serde rejects the missing struct field before
/// any application code runs.
#[test]
fn services_table_is_required() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n";
	let result: Result<Answers, _> = toml::from_str(toml_text);
	let error = result.expect_err("a missing [services] table must fail to deserialise");
	let rendered = error.to_string();
	assert!(
		rendered.contains("services"),
		"the parser error must name the missing field, got: {rendered}"
	);
}

/// `config_path` inside `data_dir` would produce a compose file
/// that mounts the same path twice (the data-directory bind
/// mount and the config-directory bind mount land at the same
/// destination), and podman refuses the container at
/// `podup up` time. The validator catches the overlap so the
/// operator sees the refusal before any effect.
#[test]
fn config_path_inside_data_dir_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/var/lib/epistle/etc/mail.toml");
	let errors = answers
		.validate()
		.expect_err("config_path inside data_dir must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"config_path inside data_dir must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// The reverse direction: `data_dir` inside `config_path`'s
/// directory would mount the same destination twice in the
/// other order. The validator catches it too.
#[test]
fn data_dir_inside_config_path_parent_is_rejected_by_the_validator() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/etc/epistle/data");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	let errors = answers
		.validate()
		.expect_err("data_dir inside config_path's parent must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"data_dir inside config_path's parent must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// Acceptance half of the overlap pair: a `config_path` whose
/// parent is a sibling of `data_dir` (the typical
/// `/var/lib/epistle` and `/etc/epistle` split) must validate.
#[test]
fn config_path_and_data_dir_siblings_validate() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/var/lib/epistle");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	assert!(
		answers.validate().is_ok(),
		"the standard sibling layout must validate, got {:?}",
		answers.validate()
	);
}

/// Two paths that look textually disjoint but resolve to the same
/// directory through `.` and `..` components must still be caught
/// by the overlap check. The previous shape walked `Path::components`
/// verbatim and saw `spare` and `..` as separate components, so
/// `data_dir = "/srv/epistle/data"` and
/// `config_path = "/srv/epistle/spare/../data/mail.toml"` looked
/// disjoint and slipped past the validator. The compose file
/// would then mount `/srv/epistle/data` on both sides of the
/// colon and podman would refuse the container.
#[test]
fn config_path_resolved_through_parent_dir_is_rejected() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/srv/epistle/data");
	answers.config_path = PathBuf::from("/srv/epistle/spare/../data/mail.toml");
	let errors = answers
		.validate()
		.expect_err("an equivalent config_path must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigMountsOverlap { .. })),
		"lexically equivalent paths must surface as ConfigMountsOverlap, got {errors:?}"
	);
}

/// A `..` that cannot be resolved lexically (the path tries to
/// escape its own root, e.g. `data_dir = "/../foo"`) is refused
/// as `PathParentEscapesRoot`. The validator cannot normalise
/// the path without rewriting it to a location the operator did
/// not type, and silently doing so would land a file where the
/// operator did not look.
#[test]
fn data_dir_with_unresolvable_parent_is_rejected() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("/../foo");
	answers.config_path = PathBuf::from("/etc/epistle/mail.toml");
	let errors = answers
		.validate()
		.expect_err("a parent_dir that escapes the root must be rejected");
	assert!(
		errors.iter().any(
			|e| matches!(e, Invalid::PathParentEscapesRoot { field, .. } if field == "data_dir")
		),
		"unresolvable .. must surface as PathParentEscapesRoot, got {errors:?}"
	);
}

/// A `$` inside `data_dir` or `config_path` is a compose-time
/// interpolation token. The compose file mounts both paths
/// verbatim on both sides of the colon, so `podup config`
/// resolves the `$VAR` against the host environment (to the
/// empty string when unset) while the rendered `mail.toml`
/// keeps the literal `$VAR` in its `data` and key paths. The
/// container then cannot find the keys the host generated.
/// The validator refuses the shape as `PathInterpolated`
/// before any effect so the operator has to write the
/// resolved path directly.
#[test]
fn data_dir_with_dollar_is_rejected_as_compose_interpolation() {
	let mut answers = minimal(Manual);
	// The exact input from the report: a `data_dir` that
	// interpolates an unset `TENANT`. `podup config` resolves
	// the mount to `/tmp/mail-/data` while `mail.toml` keeps
	// the literal `$TENANT` in its data and key paths; the
	// container then cannot find the keys the host generated.
	answers.data_dir = PathBuf::from("/tmp/mail-$TENANT/data");
	let errors = answers
		.validate()
		.expect_err("a `data_dir` containing `$` must be rejected");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PathInterpolated { field, .. } if field == "data_dir")),
		"interpolated `data_dir` must surface as PathInterpolated, got {errors:?}"
	);
}

#[test]
fn config_path_with_dollar_is_rejected_as_compose_interpolation() {
	let mut answers = minimal(Manual);
	// Same shape on `config_path`: compose would interpolate
	// the `$VAR` in the mount source while `mail.toml` keeps
	// the literal in the `--config` argument. The validator
	// catches the `$` before any effect.
	answers.config_path = PathBuf::from("/etc/$TENANT/mail.toml");
	let errors = answers
		.validate()
		.expect_err("a `config_path` containing `$` must be rejected");
	assert!(
		errors.iter().any(
			|e| matches!(e, Invalid::PathInterpolated { field, .. } if field == "config_path")
		),
		"interpolated `config_path` must surface as PathInterpolated, got {errors:?}"
	);
}
