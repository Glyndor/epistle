//! Answers unit tests.

use super::*;

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
	}
}

use Mode::*;
use std::path::PathBuf;

#[test]
fn minimal_manual_answers_validate_with_no_warnings() {
	let answers = minimal(Manual);
	let result = answers.validate();
	assert!(
		matches!(result, Ok(ref w) if w.is_empty()),
		"got {result:?}"
	);
}

#[test]
fn manual_mode_rejects_dns_section() {
	let mut answers = minimal(Manual);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let result = answers.validate();
	let errors = result.expect_err("manual with dns must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsForbidden)),
		"got {errors:?}"
	);
}

#[test]
fn automatic_mode_requires_dns_section() {
	let mut answers = minimal(Automatic);
	answers.dns = None;
	let errors = answers
		.validate()
		.expect_err("automatic without dns must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DnsRequired)),
		"got {errors:?}"
	);
}

#[test]
fn hostname_equal_to_a_domain_is_an_error() {
	let mut answers = minimal(Manual);
	answers.hostname = "example.org".to_string();
	let errors = answers
		.validate()
		.expect_err("hostname == domain must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::Hostname(_))),
		"got {errors:?}"
	);
}

#[test]
fn duplicate_domains_are_an_error() {
	let mut answers = minimal(Manual);
	answers.domains = vec!["example.org".to_string(), "EXAMPLE.org".to_string()];
	let errors = answers
		.validate()
		.expect_err("duplicate domains must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DomainsDuplicate { .. })),
		"got {errors:?}"
	);
}

#[test]
fn empty_domains_is_an_error() {
	let mut answers = minimal(Manual);
	answers.domains.clear();
	let errors = answers.validate().expect_err("empty domains must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::DomainsEmpty)),
		"got {errors:?}"
	);
}

#[test]
fn invalid_domain_is_an_error() {
	let mut answers = minimal(Manual);
	answers.domains = vec!["not a domain".to_string()];
	let errors = answers.validate().expect_err("invalid domain must error");
	assert!(
		errors.iter().any(|e| matches!(e, Invalid::Domain { .. })),
		"got {errors:?}"
	);
}

#[test]
fn private_ipv4_is_an_error() {
	let mut answers = minimal(Manual);
	answers.public_ipv4 = Some(Ipv4Addr::new(192, 168, 0, 1));
	let errors = answers.validate().expect_err("private IPv4 must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PublicIpv4 { .. })),
		"got {errors:?}"
	);
}

#[test]
fn loopback_ipv6_is_an_error() {
	let mut answers = minimal(Manual);
	answers.public_ipv6 = Some(Ipv6Addr::LOCALHOST);
	let errors = answers.validate().expect_err("loopback IPv6 must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::PublicIpv6 { .. })),
		"got {errors:?}"
	);
}

#[test]
fn inline_dns_token_warns_but_does_not_error() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: Some("inline-secret".to_string()),
		token_file: None,
		token_env: None,
	});
	let warnings = answers
		.validate()
		.expect("inline token should warn, not error");
	assert!(
		warnings.iter().any(|w| w.field == "dns.token"),
		"got {warnings:?}"
	);
}

#[test]
fn multiple_dns_token_sources_is_an_error() {
	let mut answers = minimal(Automatic);
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: Some("CF_TOKEN".to_string()),
	});
	let errors = answers
		.validate()
		.expect_err("two token sources must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsTokenAmbiguous)),
		"got {errors:?}"
	);
}

#[test]
fn automatic_dns_outside_zone_is_an_error() {
	let mut answers = minimal(Automatic);
	answers.domains = vec!["example.com".to_string()];
	answers.dns = Some(DnsAnswers {
		provider: "cloudflare".to_string(),
		zone: "example.org".to_string(),
		token: None,
		token_file: Some(PathBuf::from("/run/secrets/cf")),
		token_env: None,
	});
	let errors = answers
		.validate()
		.expect_err("domain outside zone must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DnsZoneScope { .. })),
		"got {errors:?}"
	);
}

#[test]
fn disabling_both_imap_and_submission_warns() {
	let mut answers = minimal(Manual);
	answers.services = Services {
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
	};
	let warnings = answers.validate().expect("must warn, not error");
	assert!(
		warnings.iter().any(|w| w.field == "services"),
		"got {warnings:?}"
	);
}

#[test]
fn non_absolute_data_dir_is_an_error() {
	let mut answers = minimal(Manual);
	answers.data_dir = PathBuf::from("relative/path");
	let errors = answers
		.validate()
		.expect_err("relative data_dir must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::DataDirNotAbsolute)),
		"got {errors:?}"
	);
}

#[test]
fn non_absolute_config_path_is_an_error() {
	let mut answers = minimal(Manual);
	answers.config_path = PathBuf::from("relative/path");
	let errors = answers
		.validate()
		.expect_err("relative config_path must error");
	assert!(
		errors
			.iter()
			.any(|e| matches!(e, Invalid::ConfigPathNotAbsolute)),
		"got {errors:?}"
	);
}

#[test]
fn three_independent_mistakes_report_three_errors() {
	let answers = Answers {
		mode: Manual,
		hostname: "example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
		public_ipv6: None,
		data_dir: PathBuf::from("relative/data"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
	};
	let errors = answers.validate().expect_err("three mistakes must error");
	let count = errors.len();
	assert!(
		count >= 3,
		"expected at least 3 errors, got {count}: {errors:?}"
	);
}

#[test]
fn deserialise_from_template_minimal() {
	let toml_text = "mode = \"manual\"\n\
		hostname = \"mail.example.org\"\n\
		domains = [\"example.org\"]\n\
		data_dir = \"/var/lib/epistle\"\n\
		config_path = \"/etc/epistle/mail.toml\"\n"
		.to_string();
	let parsed: Answers = toml::from_str(&toml_text).expect("deserialise");
	assert_eq!(parsed.hostname, "mail.example.org");
	let warnings = parsed.validate().expect("minimal answers validate");
	assert!(warnings.is_empty());
}

#[test]
fn warning_display_names_field_and_message() {
	// The warning text rendered on stderr is \"<field>: <message>\"; a
	// change that drops either side would leave the operator guessing
	// which answer to revisit.
	let warning = Warning {
		field: "dns.token".to_string(),
		message: "inline token in the answers file".to_string(),
	};
	let rendered = format!("{warning}");
	assert_eq!(rendered, "dns.token: inline token in the answers file");
}

#[test]
fn validate_messages_name_the_field_and_the_reason() {
	// Every Invalid variant renders a message that names the field
	// and the reason the operator has to fix. The Display strings
	// drive the stderr output during `epistle init --answers`, so a
	// change that drops the field name would leave the operator with
	// nothing to act on.
	//
	// Drive each variant through a constructed Answers and format the
	// returned error.
	let hostname_bad = Answers {
		hostname: "not a domain".to_string(),
		..minimal(Manual)
	};
	assert!(
		format!("{}", hostname_bad.validate().expect_err("bad hostname")[0]).contains("hostname"),
		"Hostname display must name the field"
	);

	let empty_domains = Answers {
		domains: vec![],
		..minimal(Manual)
	};
	assert!(
		format!(
			"{}",
			empty_domains.validate().expect_err("empty domains")[0]
		)
		.contains("domains"),
		"DomainsEmpty display must name the field"
	);

	let bad_domain = Answers {
		domains: vec!["not a domain".to_string()],
		..minimal(Manual)
	};
	assert!(
		format!("{}", bad_domain.validate().expect_err("bad domain")[0]).contains("domains"),
		"Domain display must name the field"
	);

	let dup_domains = Answers {
		domains: vec!["example.org".to_string(), "EXAMPLE.org".to_string()],
		..minimal(Manual)
	};
	assert!(
		format!("{}", dup_domains.validate().expect_err("dup domains")[0]).contains("domains"),
		"DomainsDuplicate display must name the field"
	);

	let private_ipv4 = Answers {
		public_ipv4: Some(Ipv4Addr::new(10, 0, 0, 1)),
		..minimal(Manual)
	};
	assert!(
		format!("{}", private_ipv4.validate().expect_err("private v4")[0]).contains("public_ipv4"),
		"PublicIpv4 display must name the field"
	);

	let private_ipv6 = Answers {
		public_ipv6: Some(Ipv6Addr::LOCALHOST),
		..minimal(Manual)
	};
	assert!(
		format!("{}", private_ipv6.validate().expect_err("loopback v6")[0]).contains("public_ipv6"),
		"PublicIpv6 display must name the field"
	);

	// automatic mode without [dns] -> DnsRequired
	let auto_no_dns = Answers {
		mode: Automatic,
		..minimal(Automatic)
	};
	assert!(
		format!(
			"{}",
			auto_no_dns.validate().expect_err("automatic no dns")[0]
		)
		.contains("automatic"),
		"DnsRequired display must name the mode"
	);

	// manual mode with [dns] -> DnsForbidden
	let manual_with_dns = Answers {
		mode: Manual,
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::from("/run/secrets/cf")),
			token_env: None,
		}),
		..minimal(Manual)
	};
	assert!(
		format!(
			"{}",
			manual_with_dns.validate().expect_err("manual with dns")[0]
		)
		.contains("manual"),
		"DnsForbidden display must name the mode"
	);

	// dns with empty zone -> DnsZoneMissing
	let dns_no_zone = Answers {
		mode: Automatic,
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: String::new(),
			token: None,
			token_file: Some(PathBuf::from("/run/secrets/cf")),
			token_env: None,
		}),
		..minimal(Automatic)
	};
	assert!(
		format!("{}", dns_no_zone.validate().expect_err("no zone")[0]).contains("dns.zone"),
		"DnsZoneMissing display must name the field"
	);

	// dns with empty provider -> DnsProviderMissing
	let dns_no_provider = Answers {
		mode: Automatic,
		dns: Some(DnsAnswers {
			provider: String::new(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::from("/run/secrets/cf")),
			token_env: None,
		}),
		..minimal(Automatic)
	};
	assert!(
		format!(
			"{}",
			dns_no_provider.validate().expect_err("no provider")[0]
		)
		.contains("dns.provider"),
		"DnsProviderMissing display must name the field"
	);

	// domain outside zone -> DnsZoneScope
	let dns_out_of_zone = Answers {
		mode: Automatic,
		domains: vec!["example.com".to_string()],
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: Some(PathBuf::from("/run/secrets/cf")),
			token_env: None,
		}),
		..minimal(Automatic)
	};
	assert!(
		format!(
			"{}",
			dns_out_of_zone.validate().expect_err("domain outside zone")[0]
		)
		.contains("dns.zone"),
		"DnsZoneScope display must name the zone"
	);

	// two token sources -> DnsTokenAmbiguous
	let dns_two_tokens = Answers {
		mode: Automatic,
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: Some("x".to_string()),
			token_file: None,
			token_env: Some("EPISLE_DNS".to_string()),
		}),
		..minimal(Automatic)
	};
	assert!(
		format!("{}", dns_two_tokens.validate().expect_err("two tokens")[0]).contains("token"),
		"DnsTokenAmbiguous display must mention the field"
	);

	// no token sources -> DnsTokenMissing
	let dns_no_token = Answers {
		mode: Automatic,
		dns: Some(DnsAnswers {
			provider: "cloudflare".to_string(),
			zone: "example.org".to_string(),
			token: None,
			token_file: None,
			token_env: None,
		}),
		..minimal(Automatic)
	};
	assert!(
		format!("{}", dns_no_token.validate().expect_err("no token")[0]).contains("token"),
		"DnsTokenMissing display must mention the field"
	);

	// relative data_dir -> DataDirNotAbsolute
	let rel_data = Answers {
		data_dir: PathBuf::from("relative/data"),
		..minimal(Manual)
	};
	assert!(
		format!("{}", rel_data.validate().expect_err("rel data")[0]).contains("data_dir"),
		"DataDirNotAbsolute display must name the field"
	);

	// relative config_path -> ConfigPathNotAbsolute
	let rel_config = Answers {
		config_path: PathBuf::from("relative/mail.toml"),
		..minimal(Manual)
	};
	assert!(
		format!("{}", rel_config.validate().expect_err("rel config")[0]).contains("config_path"),
		"ConfigPathNotAbsolute display must name the field"
	);
}
