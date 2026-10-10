//! Display strings for every `Invalid` variant. The full set fits
//! in one large test because every assertion in it shares the same
//! shape (drive a constructed `Answers`, format the returned
//! error, assert the rendered message names the field). Splitting
//! the assertions across many tests would multiply `validate()` and
//! `Answers` boilerplate without buying anything in coverage, so
//! this file is deliberately one long test rather than a fan-out.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::Mode::*;
use super::tests::minimal;
use super::*;

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
