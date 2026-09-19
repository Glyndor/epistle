//! The validation routine for `Answers`. Lives in a sibling so
//! `answers.rs` keeps under the per-file line limit; the entry point
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
						errors.push(Invalid::DnsZoneInvalid {
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
			let token_present = dns
				.token
				.as_deref()
				.is_some_and(|v| !v.trim().is_empty());
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
}

/// True when `path` ends with a normal file-name component: not the
/// root, not `.` or `..`, not an empty string. The apply phase
/// requires the same shape to find a sibling staging file; the
/// validator catches the missing piece earlier.
fn path_has_a_file_name(path: &Path) -> bool {
	let Some(name) = path.file_name() else {
		return false;
	};
	let s = match name.to_str() {
		Some(s) => s,
		None => return false,
	};
	if s.is_empty() || s == "." || s == ".." {
		return false;
	}
	true
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

	if errors.is_empty() {
		Ok(warnings)
	} else {
		Err(errors)
	}
}
