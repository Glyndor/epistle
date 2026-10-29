//! Tests for the Cloudflare orange-cloud check: which names count as mail
//! names, that only a proxied A, AAAA or CNAME is a failure, and the exact
//! message `epistle status` prints.

use super::*;

fn record(name: &str, kind: RecordKind, value: &str, proxied: Option<bool>) -> DnsRecord {
	DnsRecord {
		proxied,
		..DnsRecord::new(name, kind, value, 300)
	}
}

fn proxied_a(name: &str) -> DnsRecord {
	record(name, RecordKind::A, "192.0.2.10", Some(true))
}

fn domains() -> Vec<String> {
	vec!["example.org".to_string()]
}

#[test]
fn the_message_names_the_record_and_the_fix() {
	assert_eq!(
		proxied_message("mail.example.org"),
		"mail.example.org is proxied by Cloudflare (orange cloud): mail clients and other servers cannot reach port 25/465/587/993 through the proxy; set it to DNS only"
	);
}

#[test]
fn every_mail_name_is_checked() {
	let records = vec![
		record("example.org", RecordKind::Mx, "10 mx1.example.org", None),
		record(
			"example.org",
			RecordKind::Mx,
			"20 backup.example.net.",
			None,
		),
		proxied_a("mail.example.org"),
		proxied_a("mx1.example.org"),
		record(
			"backup.example.net",
			RecordKind::Aaaa,
			"2001:db8::1",
			Some(true),
		),
		record(
			"autoconfig.example.org",
			RecordKind::Cname,
			"mail.example.org",
			Some(true),
		),
		proxied_a("autodiscover.example.org"),
		proxied_a("mta-sts.example.org"),
	];
	assert_eq!(
		find_proxied(&domains(), "mail.example.org", &records),
		vec![
			"autoconfig.example.org",
			"autodiscover.example.org",
			"backup.example.net",
			"mail.example.org",
			"mta-sts.example.org",
			"mx1.example.org",
		]
	);
}

#[test]
fn a_name_is_reported_once_whatever_its_record_count() {
	let records = vec![
		proxied_a("mail.example.org"),
		record(
			"mail.example.org",
			RecordKind::Aaaa,
			"2001:db8::1",
			Some(true),
		),
	];
	assert_eq!(
		find_proxied(&domains(), "Mail.Example.org.", &records),
		vec!["mail.example.org"]
	);
}

#[test]
fn dns_only_unknown_and_non_mail_names_pass() {
	let records = vec![
		record("mail.example.org", RecordKind::A, "192.0.2.10", Some(false)),
		record("autoconfig.example.org", RecordKind::A, "192.0.2.10", None),
		// The apex and the website are not mail names unless an MX says so.
		proxied_a("example.org"),
		proxied_a("www.example.org"),
	];
	assert!(find_proxied(&domains(), "mail.example.org", &records).is_empty());
}

#[test]
fn the_apex_counts_when_it_is_its_own_mx_target() {
	let records = vec![
		record("example.org", RecordKind::Mx, "10 example.org.", None),
		proxied_a("example.org"),
	];
	assert_eq!(
		find_proxied(&domains(), "mail.example.org", &records),
		vec!["example.org"]
	);
}

#[test]
fn only_cloudflare_is_proxy_aware() {
	let dir = tempfile::tempdir().expect("tempdir");
	let with = |extra: &str| {
		let path = dir.path().join("epistle.toml");
		std::fs::write(
			&path,
			format!(
				"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n[[listeners]]\nkind = 'smtp'\naddr = '0.0.0.0'\n{extra}",
				dir.path()
			),
		)
		.expect("write");
		std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
			.expect("chmod");
		Config::load(&path).expect("config")
	};
	assert!(proxy_aware_provider(&with(
		"[dns]\nprovider = 'Cloudflare'\nzone = 'example.org'\ntoken_env = 'X'\n"
	)));
	assert!(!proxy_aware_provider(&with(
		"[dns]\nprovider = 'desec'\nzone = 'example.org'\ntoken_env = 'X'\n"
	)));
	assert!(!proxy_aware_provider(&with("")));
}
