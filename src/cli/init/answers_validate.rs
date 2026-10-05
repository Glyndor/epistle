//! The validation routine for `Answers`. Lives in a sibling so
//! `answers.rs` keeps under the per-file line limit; the entry point
//! is `Answers::validate` which delegates here.

use std::path::{Path, PathBuf};

use crate::dns::provider::ScopedSecret;

use super::{Answers, DnsAnswers, Invalid, Mode, Services, Warning};

/// What `hostname` validation found. `Ok` returns the normalised
/// A-label; `Err` carries the rejection text that the operator sees.
enum HostnameCheck {
	Ok(String),
	Err(Invalid),
}

fn check_hostname(hostname: &str) -> HostnameCheck {
	match crate::domain::normalize(hostname) {
		Ok(norm) => HostnameCheck::Ok(norm),
		Err(why) => {
			let reason = match why {
				crate::domain::DomainError::Invalid => "is not a valid FQDN".to_string(),
				crate::domain::DomainError::Confusable => {
					"is confusable with another name".to_string()
				}
			};
			HostnameCheck::Err(Invalid::Hostname(reason))
		}
	}
}

fn check_domain(value: &str) -> Result<String, Invalid> {
	match crate::domain::normalize(value) {
		Ok(norm) => Ok(norm),
		Err(why) => {
			let reason = match why {
				crate::domain::DomainError::Invalid => "is not a valid FQDN".to_string(),
				crate::domain::DomainError::Confusable => {
					"is confusable with another name".to_string()
				}
			};
			Err(Invalid::Domain {
				value: value.to_string(),
				reason,
			})
		}
	}
}

fn check_domains(domains: &[String], errors: &mut Vec<Invalid>) -> Vec<String> {
	let mut seen: Vec<String> = Vec::new();
	if domains.is_empty() {
		errors.push(Invalid::DomainsEmpty);
		return seen;
	}
	for domain in domains {
		match check_domain(domain) {
			Ok(norm) => {
				if let Some(existing) = seen.iter().find(|existing| *existing == &norm) {
					errors.push(Invalid::DomainsDuplicate {
						a: existing.clone(),
						b: norm.clone(),
					});
				} else {
					seen.push(norm);
				}
			}
			Err(error) => errors.push(error),
		}
	}
	seen
}

fn check_public_ips(answers: &Answers, errors: &mut Vec<Invalid>) {
	if let Some(ip) = answers.public_ipv4
		&& let Some(why) = crate::config::non_global_ipv4_reason(ip)
	{
		errors.push(Invalid::PublicIpv4 {
			value: ip.to_string(),
			reason: why.to_string(),
		});
	}
	if let Some(ip) = answers.public_ipv6
		&& let Some(why) = crate::config::non_global_ipv6_reason(ip)
	{
		errors.push(Invalid::PublicIpv6 {
			value: ip.to_string(),
			reason: why.to_string(),
		});
	}
}

fn check_dns(
	mode: Mode,
	dns: Option<&DnsAnswers>,
	domains: &[String],
	errors: &mut Vec<Invalid>,
	warnings: &mut Vec<Warning>,
) {
	match (mode, dns) {
		(Mode::Automatic, None) => errors.push(Invalid::DnsRequired),
		(Mode::Manual, Some(_)) => errors.push(Invalid::DnsForbidden),
		(Mode::Automatic, Some(dns)) => {
			if dns.provider.trim().is_empty() {
				errors.push(Invalid::DnsProviderMissing);
			}
			if dns.zone.trim().is_empty() {
				errors.push(Invalid::DnsZoneMissing);
			} else {
				// Validate `dns.zone` through the same normaliser that
				// ran on `domains`, so the zone is stored as its
				// A-label and the scope check compares like with like.
				// The file path used to keep the raw string and then
				// hand it to `ScopedSecret::authorizes`, which
				// compared the U-label against an A-label domain and
				// rejected a Unicode zone whose equivalent U-label
				// matched. The assistant uses the same domain function
				// on its prompts, so it never produced this shape.
				// The shared validator must accept the same shapes.
				match crate::domain::normalize(&dns.zone) {
					Ok(zone_norm) => {
						let scope = ScopedSecret::new(zone_norm.clone(), "x");
						for domain in domains {
							if !scope.authorizes(domain) {
								errors.push(Invalid::DnsZoneScope {
									domain: domain.clone(),
									zone: dns.zone.clone(),
								});
							}
						}
					}
					Err(why) => {
						let reason = match why {
							crate::domain::DomainError::Invalid => {
								"is not a valid FQDN".to_string()
							}
							crate::domain::DomainError::Confusable => {
								"is confusable with another name".to_string()
							}
						};
						errors.push(Invalid::DnsZoneMalformed {
							value: dns.zone.clone(),
							reason,
						});
					}
				}
			}
			// An empty or whitespace-only value in any of the three
			// sources counts as absent, so the assistant and the file
			// path reject the same input with the same sentence. The
			// assistant already trims before storing; the file path
			// preserves the literal, hence this branch.
			let token_present = dns.token.as_deref().is_some_and(|v| !v.trim().is_empty());
			let token_file_present = dns.token_file.as_deref().is_some_and(|p| {
				let s = p.to_string_lossy();
				!s.trim().is_empty()
			});
			let token_env_present = dns
				.token_env
				.as_deref()
				.is_some_and(|v| !v.trim().is_empty());
			let provided = [token_present, token_file_present, token_env_present]
				.iter()
				.filter(|x| **x)
				.count();
			match provided {
				0 => errors.push(Invalid::DnsTokenMissing),
				1 => {}
				_ => errors.push(Invalid::DnsTokenAmbiguous),
			}
			if token_present {
				warnings.push(Warning {
					field: "dns.token".to_string(),
					message:
						"inline token in the answers file; prefer dns.token_file or dns.token_env"
							.to_string(),
				});
			}
		}
		(Mode::Manual, None) => {}
	}
}

fn check_absolute_paths(data_dir: &Path, config_path: &Path, errors: &mut Vec<Invalid>) {
	// Compose interpolates `$VAR` (and `${VAR}`) inside any value
	// it parses, including path-shaped strings. The compose file
	// we emit mounts `data_dir` and `config_path.parent()` on
	// both sides of the colon, so a `$VAR` in the source path
	// resolves at `podup config` time (to the empty string when
	// the variable is unset, or to whatever the host environment
	// happens to carry) while the rendered `mail.toml` keeps
	// the literal `$VAR` in its `data` and key paths. The
	// container then cannot find the keys the host generated.
	// The validator refuses the shape before any effect so the
	// operator has to write the resolved path directly. The
	// check walks the path as a string (not a `Path` slice) so
	// it catches a `$` in any component, including one that
	// `Path::components` would already have collapsed away.
	if let Some(text) = data_dir.to_str()
		&& text.contains('$')
	{
		errors.push(Invalid::PathInterpolated {
			field: "data_dir".to_string(),
			value: text.to_string(),
		});
		return;
	}
	if let Some(text) = config_path.to_str()
		&& text.contains('$')
	{
		errors.push(Invalid::PathInterpolated {
			field: "config_path".to_string(),
			value: text.to_string(),
		});
		return;
	}
	if !data_dir.is_absolute() {
		errors.push(Invalid::DataDirNotAbsolute);
	}
	if !config_path.is_absolute() {
		errors.push(Invalid::ConfigPathNotAbsolute);
		return;
	}
	// `config_path = "/"` is absolute, so the check above accepts it,
	// but the apply phase rejects it at the staging step (no file
	// name to stage next to). By then the data directory and every
	// key have already been written. The validator catches the same
	// shape earlier so nothing is touched.
	if !path_has_a_file_name(config_path) {
		errors.push(Invalid::ConfigPathNoFileName);
	}
	// Writing the config into the data directory would overwrite a
	// key with the staging temp or the renamed config. The validator
	// catches the equality before any effect, so the operator can
	// fix the answer and rerun.
	if data_dir == config_path {
		errors.push(Invalid::ConfigPathEqualsDataDir);
	}
	// `init` owns `<data_dir>/keys` and lands the staging step
	// inside `config_path.parent()`. A `config_path` that resolves
	// inside the keys directory would race the staging temp against
	// a key the same run is about to write. The component comparison
	// keeps a path whose name only *starts* with `keys` (a
	// sibling directory the operator owns) accepted.
	if path_is_inside_keys_dir(data_dir, config_path) {
		errors.push(Invalid::ConfigPathInsideKeysDir);
	}
	// The compose file mounts `data_dir` and `config_path.parent()`
	// (the directory holding `mail.toml`) at the same path on both
	// sides of the colon. When the two paths overlap, the rendered
	// compose file carries two volumes with the same destination and
	// podman refuses the container. Catching both directions here
	// keeps the apply phase from ever landing that file on disk.
	//
	// The comparison lexically normalises `.` and `..` first, so
	// `data_dir = "/srv/epistle/data"` and
	// `config_path = "/srv/epistle/spare/../data/mail.toml"` are
	// caught even though the textual forms look disjoint. When
	// both paths resolve to something on disk, the helper also
	// canonicalises them so a symlink at one of the components
	// (e.g. `/var/run` -> `/run`) is followed to the same
	// underlying directory. A `..` that cannot be resolved
	// lexically (the path tries to escape its own root, e.g.
	// `data_dir = "/../foo"`) is refused separately so the
	// operator sees the shape of the mistake rather than a
	// silent rewrite to a path they did not type.
	let normalised_data_dir = match lexically_normalised(data_dir) {
		Ok(path) => path,
		Err(()) => {
			errors.push(Invalid::PathParentEscapesRoot {
				field: "data_dir".to_string(),
				value: data_dir.display().to_string(),
			});
			return;
		}
	};
	let normalised_config_dir = match config_path
		.parent()
		.and_then(|dir| lexically_normalised(dir).ok())
	{
		Some(path) => path,
		None => {
			errors.push(Invalid::PathParentEscapesRoot {
				field: "config_path".to_string(),
				value: config_path.display().to_string(),
			});
			return;
		}
	};
	let (left, right) = if normalised_data_dir.exists() && normalised_config_dir.exists() {
		match (
			normalised_data_dir.canonicalize(),
			normalised_config_dir.canonicalize(),
		) {
			(Ok(l), Ok(r)) => (l, r),
			// A canonicalisation failure on a path that exists
			// is rare (an unreadable parent on Linux), and the
			// apply phase will surface it with its own
			// diagnostic. The lexical comparison is still the
			// correct verdict in the meantime.
			_ => (normalised_data_dir, normalised_config_dir),
		}
	} else {
		(normalised_data_dir, normalised_config_dir)
	};
	if paths_overlap(&left, &right) {
		errors.push(Invalid::ConfigMountsOverlap {
			data_dir: left.display().to_string(),
			config_dir: right.display().to_string(),
		});
	}
}

/// Lexically normalise `path` by resolving `.` and `..` components
/// without touching the filesystem. Returns `Err(())` when a `..`
/// cannot pop a `Normal` component (i.e. the path tries to climb
/// above its own root, as in `data_dir = "/../foo"` or
/// `"/a/../../b"`). Silently rewriting the path would land a
/// file at a location the operator did not type, and the operator
/// almost certainly meant to write the normalised form
/// directly. `Path::components` exposes `..` as
/// `Component::ParentDir` and `.` as `Component::CurDir`; the
/// algorithm pushes `Normal` components onto a stack, pops on
/// `ParentDir`, ignores `CurDir`, and resets the stack on
/// `RootDir` / `Prefix` so a Windows drive letter followed by
/// `..` does not consume the drive.
fn lexically_normalised(path: &Path) -> Result<PathBuf, ()> {
	let mut stack: Vec<std::path::Component<'_>> = Vec::new();
	for component in path.components() {
		match component {
			std::path::Component::RootDir | std::path::Component::Prefix(_) => {
				stack.clear();
				stack.push(component);
			}
			std::path::Component::CurDir => {}
			std::path::Component::ParentDir => {
				let can_pop = matches!(stack.last(), Some(std::path::Component::Normal(_)));
				if can_pop {
					stack.pop();
				} else {
					// Either the stack is empty (a relative path
					// that climbs above its starting directory,
					// which the absolute-path check has already
					// rejected) or the top is a RootDir / Prefix
					// (a parent_dir at the root, which would
					// resolve to the root itself). Either way,
					// the operator wrote a parent component the
					// normalisation cannot apply, and silently
					// dropping it would rewrite the path to a
					// location the operator did not type.
					return Err(());
				}
			}
			std::path::Component::Normal(_) => stack.push(component),
		}
	}
	let mut out = PathBuf::new();
	for component in stack {
		out.push(component.as_os_str());
	}
	Ok(out)
}

/// True when `a` and `b` refer to the same directory or one is a
/// strict componentwise prefix of the other. The componentwise
/// comparison keeps a path whose name only *starts* with a
/// component of the other (a sibling the operator owns) accepted.
/// The inputs are expected to have been lexically normalised
/// (and, where they exist on disk, canonicalised) by the caller;
/// raw operator paths with `.` or `..` components are not safe to
/// compare here.
fn paths_overlap(a: &Path, b: &Path) -> bool {
	let mut ac = a.components();
	let mut bc = b.components();
	loop {
		match (ac.next(), bc.next()) {
			(Some(x), Some(y)) if x == y => continue,
			(Some(_), Some(_)) => return false,
			(None, Some(_)) | (Some(_), None) => return true,
			(None, None) => return true,
		}
	}
}

/// True when `path` ends with a normal file-name component: not the
/// root, not `.` or `..`, not an empty string, not a trailing
/// separator or a separator followed by `.` or `..`. The apply
/// phase requires the same shape to find a sibling staging file; the
/// validator catches the missing piece earlier. `Path::components()`
/// silently elides a trailing `/.` to its parent, so the textual check
/// below is what surfaces that shape.
fn path_has_a_file_name(path: &Path) -> bool {
	if let Some(text) = path.as_os_str().to_str()
		&& (text.ends_with('/') || text.ends_with("/.") || text.ends_with("/.."))
	{
		return false;
	}
	matches!(
		path.components().next_back(),
		Some(std::path::Component::Normal(_))
	)
}

/// True when `<data_dir>/keys` is a strict componentwise prefix of
/// `config_path`. The comparison walks `Path::components` so a path
/// like `<data_dir>/keysfoo/mail.toml` does not match: `keys` is a
/// sibling directory, not a prefix component.
fn path_is_inside_keys_dir(data_dir: &Path, config_path: &Path) -> bool {
	let keys_dir = data_dir.join("keys");
	let mut kc = keys_dir.components();
	let mut cc = config_path.components();
	loop {
		match (kc.next(), cc.next()) {
			(Some(a), Some(b)) if a == b => continue,
			(Some(_), _) => return false,
			(None, Some(_)) => return true,
			(None, None) => return false,
		}
	}
}

fn check_services(services: &Services, errors: &mut Vec<Invalid>, warnings: &mut Vec<Warning>) {
	if !services.imap && !services.submission {
		warnings.push(Warning {
			field: "services".to_string(),
			message: "the server will receive mail that nobody can read".to_string(),
		});
	}
	if services.api {
		// `init` cannot mint a management API credential. The plan
		// would still add an api listener and `Config::load` would
		// reject the resulting config because no `[api]` section was
		// written. Refuse the request up front so the operator sees a
		// validation error and never gets a half-written key tree.
		errors.push(Invalid::ApiUnsupported);
	}
}

fn check_image(image: Option<&str>, errors: &mut Vec<Invalid>) {
	let Some(image) = image else {
		return;
	};
	// The compose file pins the image as a single string. An empty
	// value would resolve to a bare `image:` key, and whitespace
	// would split the value across two array entries. The default
	// is empty (`None`); the operator either leaves it alone or
	// passes a fully-formed reference.
	if image.is_empty() || image.chars().any(char::is_whitespace) {
		errors.push(Invalid::ImageMalformed(image.to_string()));
		return;
	}
	// The compose writer emits the reference verbatim; compose's own
	// `${VAR}` interpolation would happen at `podup` time and the
	// image epistle generates must not depend on a variable the
	// container image cannot resolve. An `image =
	// "localhost/epistle:${TAG:-latest}"` line in the answers
	// file, for instance, would let `podup` resolve `${TAG:-latest}`
	// to `latest` and pull a moving reference.
	if image.contains('$') {
		errors.push(Invalid::ImageMalformed(image.to_string()));
		return;
	}
	// The reference must carry a tag that is not `latest` or a
	// `@sha256:` digest. An untagged reference would default to
	// `:latest` and break reproducible installs; an explicit
	// `:latest` is no better.
	if let Some(at_idx) = image.find('@') {
		let digest = &image[at_idx + 1..];
		if !digest.starts_with("sha256:") || digest.len() <= "sha256:".len() {
			errors.push(Invalid::ImageUntagged(image.to_string()));
		}
		return;
	}
	// The tag separator is the last `:` that comes after the
	// last `/`. A `:` that comes before the last `/` is the
	// registry-port separator (`localhost:5000/epistle`); the
	// old `rsplit_once(':')` shape mistook the registry port
	// for a tag and let `localhost:5000/epistle` through. A
	// reference with no `/` (e.g. `epistle:dev`, the form a
	// local build with `podman build -t epistle:dev .`
	// produces) has no path component at all, so the
	// registry-port branch is impossible: the only `:` in the
	// reference is the tag separator. The shape walks the
	// reference, splits off the path part (everything up to
	// and including the last `/`, or the whole reference when
	// no `/` is present), then takes the last `:` of what
	// remains as the tag separator. A reference with no `:`
	// after the last `/` is untagged and refused; so is an
	// empty tag.
	let path_end = image.rfind('/').map(|slash| slash + 1).unwrap_or(0);
	let rest = &image[path_end..];
	let Some(colon_idx) = rest.rfind(':') else {
		errors.push(Invalid::ImageUntagged(image.to_string()));
		return;
	};
	let tag = &rest[colon_idx + 1..];
	if tag.is_empty() || tag == "latest" {
		errors.push(Invalid::ImageUntagged(image.to_string()));
	}
}

fn check_hostname_vs_domains(
	hostname_norm: &Option<String>,
	domains: &[String],
	errors: &mut Vec<Invalid>,
) {
	if let Some(hostname) = hostname_norm {
		let normalised: Vec<String> = domains
			.iter()
			.filter_map(|d| crate::domain::normalize(d).ok())
			.collect();
		if normalised.iter().any(|d| d == hostname) {
			errors.push(Invalid::Hostname(
				"must not equal any domain in `domains`".to_string(),
			));
		}
	}
}

/// Validate the answers, collecting every problem instead of stopping
/// at the first one. Used by both the `--answers` file path and the
/// assistant path so the two never disagree.
///
/// Returns `Ok(warnings)` when every required rule passes. Warnings
/// (e.g. an inline API token) are non-fatal but always surfaced.
pub(crate) fn validate(answers: &Answers) -> Result<Vec<Warning>, Vec<Invalid>> {
	let mut errors: Vec<Invalid> = Vec::new();
	let mut warnings: Vec<Warning> = Vec::new();

	let hostname_norm = match check_hostname(&answers.hostname) {
		HostnameCheck::Ok(norm) => Some(norm),
		HostnameCheck::Err(error) => {
			errors.push(error);
			None
		}
	};
	let normalised_domains = check_domains(&answers.domains, &mut errors);
	check_hostname_vs_domains(&hostname_norm, &normalised_domains, &mut errors);
	check_public_ips(answers, &mut errors);
	// Use the normalised domains for the scope check so a Unicode
	// zone compares against an A-label domain with the same shape.
	check_dns(
		answers.mode,
		answers.dns.as_ref(),
		&normalised_domains,
		&mut errors,
		&mut warnings,
	);
	check_absolute_paths(&answers.data_dir, &answers.config_path, &mut errors);
	check_services(&answers.services, &mut errors, &mut warnings);
	check_image(answers.image.as_deref(), &mut errors);

	if errors.is_empty() {
		Ok(warnings)
	} else {
		Err(errors)
	}
}
