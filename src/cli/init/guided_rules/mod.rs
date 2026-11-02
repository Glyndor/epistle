//! Presentation of shared answer validation failures for inline retries.

use super::answers::{Answers, Invalid};

/// Run the canonical validator, selecting only failures for this question.
/// No acceptance rule is reimplemented here.
pub(super) fn check(answers: &Answers, question: &str) -> Result<(), String> {
	let errors = answers.validate().err().unwrap_or_default();
	for error in errors {
		let (field, rule) = match error {
			Invalid::Hostname(rule) => ("domains", rule),
			Invalid::Domain { reason, .. } => ("domains", reason),
			Invalid::DomainsEmpty => ("domains", "at least one domain is required".into()),
			Invalid::DomainsDuplicate { .. } => (
				"domains",
				"domains must be distinct after normalization".into(),
			),
			Invalid::DataDirNotAbsolute => ("data_dir", "must be an absolute path".into()),
			Invalid::DataDirUnsafe { suggested } => (
				"data_dir",
				format!("must exclude the user home and host runtime directories; use {suggested}"),
			),
			Invalid::DataDirHomeUnavailable(why) => ("data_dir", why),
			Invalid::ConfigPathNotAbsolute => ("config_path", "must be an absolute path".into()),
			Invalid::ConfigPathNoFileName => {
				("config_path", "must end with a usable file name".into())
			}
			Invalid::ConfigPathEqualsDataDir
			| Invalid::ConfigPathInsideKeysDir
			| Invalid::ConfigMountsOverlap { .. } => (
				"config_path",
				"configuration and data directories must not overlap".into(),
			),
			Invalid::PathInterpolated { field, .. } => {
				if field == question {
					return Err("paths must not contain compose interpolation ($)".into());
				}
				continue;
			}
			Invalid::PathControl { field, .. } => {
				if field == question {
					return Err("paths must not contain control characters".into());
				}
				continue;
			}
			Invalid::PathParentEscapesRoot { field, .. } => {
				if field == question {
					return Err("path must not escape its root".into());
				}
				continue;
			}
			Invalid::ImageMalformed(_) | Invalid::ImageUntagged(_) => (
				"image",
				"use a whitespace-free image pinned to a tag other than latest or a sha256 digest"
					.into(),
			),
			Invalid::DnsProviderMissing | Invalid::DnsProviderUnsupported { .. } => (
				"DNS provider",
				format!(
					"choose a supported provider: {}",
					crate::config::SUPPORTED_PROVIDERS.join(", ")
				),
			),
			Invalid::DnsZoneMissing
			| Invalid::DnsZoneMalformed { .. }
			| Invalid::DnsZoneScope { .. } => (
				"DNS zone",
				"use a valid DNS zone containing every served domain".into(),
			),
			_ => continue,
		};
		if field == question {
			return Err(rule);
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests;
