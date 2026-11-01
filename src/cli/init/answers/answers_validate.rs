//! The validation routine for `Answers`. Lives in a sibling so
//! `src/cli/init/answers/mod.rs` keeps under the per-file line limit; the entry point
//! is `Answers::validate` which delegates here.

use std::path::Path;

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
		Err(why) => HostnameCheck::Err(Invalid::Hostname(format!(
			"{:?}: {}",
			crate::util::address_reason::shorten(hostname),
			crate::util::address_reason::name_refusal(hostname, why, "mail.example.org")
		))),
	}
}

fn check_domain(value: &str) -> Result<String, Invalid> {
	crate::domain::normalize(value).map_err(|why| Invalid::Domain {
		value: crate::util::address_reason::shorten(value),
		reason: crate::util::address_reason::name_refusal(value, why, "example.org"),
	})
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
			} else if !crate::config::is_supported_provider(&dns.provider) {
				errors.push(Invalid::DnsProviderUnsupported {
					value: dns.provider.clone(),
					supported: crate::config::SUPPORTED_PROVIDERS.join(", "),
				});
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
						let reason = crate::util::address_reason::name_refusal(
							&dns.zone,
							why,
							"example.org",
						);
						errors.push(Invalid::DnsZoneMalformed {
							value: crate::util::address_reason::shorten(&dns.zone),
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
			// The path is mounted by compose, which interpolates `$VAR`, and
			// written into `mail.toml`, whose loader expands `${VAR}` and
			// stops when the variable is unset. A reference to a variable the
			// run does not have therefore passed every question and failed
			// after the keys were written, so the shape is refused here.
			if let Some(text) = dns.token_file.as_deref().and_then(Path::to_str)
				&& text.contains('$')
			{
				errors.push(Invalid::PathInterpolated {
					field: "dns.token_file".to_string(),
					value: text.to_string(),
				});
			}
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

pub(super) use super::paths::lexically_normalised;

fn check_services(services: &Services, _errors: &mut Vec<Invalid>, warnings: &mut Vec<Warning>) {
	if !services.imap && !services.submission {
		warnings.push(Warning {
			field: "services".to_string(),
			message: "the server will receive mail that nobody can read".to_string(),
		});
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
	super::paths::check_absolute_paths(&answers.data_dir, &answers.config_path, &mut errors);
	if let Err(error) = super::data_dir::check(&answers.data_dir) {
		errors.push(error);
	}
	check_services(&answers.services, &mut errors, &mut warnings);
	check_image(answers.image.as_deref(), &mut errors);
	if let Some(first) = &answers.first_account
		&& let Err(why) = first.check(&normalised_domains)
	{
		errors.push(Invalid::FirstAccount(why));
	}
	for (field, reason) in crate::cli::init::resources::problems(&answers.resources) {
		errors.push(Invalid::Resources { field, reason });
	}

	if errors.is_empty() {
		Ok(warnings)
	} else {
		Err(errors)
	}
}
