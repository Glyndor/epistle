use super::*;

#[test]
fn parses_typical_record() {
	let record =
		parse("v=spf1 ip4:192.0.2.0/24 include:_spf.example.org ~all").expect("valid record");
	assert_eq!(record.directives.len(), 3);
	assert_eq!(
		record.directives[0],
		(
			Qualifier::Pass,
			Mechanism::Ip4 {
				network: "192.0.2.0".parse().expect("ip"),
				prefix: 24
			}
		)
	);
	assert_eq!(record.directives[2], (Qualifier::SoftFail, Mechanism::All));
}

#[test]
fn parses_a_and_mx_with_cidr() {
	let record =
		parse("v=spf1 a mx:mail.example.org/28 a:other.example//64 -all").expect("valid record");
	assert_eq!(
		record.directives[0].1,
		Mechanism::A {
			domain: None,
			prefix4: 32,
			prefix6: 128
		}
	);
	assert_eq!(
		record.directives[1].1,
		Mechanism::Mx {
			domain: Some("mail.example.org".into()),
			prefix4: 28,
			prefix6: 128
		}
	);
	assert_eq!(
		record.directives[2].1,
		Mechanism::A {
			domain: Some("other.example".into()),
			prefix4: 32,
			prefix6: 64
		}
	);
}

#[test]
fn parses_redirect_and_ignores_unknown_modifiers() {
	let record = parse("v=spf1 exp=explain.example.org redirect=_spf.example.org").expect("valid");
	assert_eq!(record.redirect.as_deref(), Some("_spf.example.org"));
	assert!(record.directives.is_empty());
}

#[test]
fn rejects_wrong_version() {
	assert!(parse("v=spf2 -all").is_err());
	assert!(parse("-all").is_err());
}

#[test]
fn rejects_bad_addresses_and_prefixes() {
	assert!(parse("v=spf1 ip4:999.0.2.0/24").is_err());
	assert!(parse("v=spf1 ip4:192.0.2.0/33").is_err());
	assert!(parse("v=spf1 ip6:zzzz::/64").is_err());
	assert!(parse("v=spf1 a/129").is_err());
}

#[test]
fn rejects_unknown_mechanism_and_duplicates() {
	assert!(parse("v=spf1 redirect=a.example redirect=b.example").is_err());
	assert!(parse("v=spf1 include:").is_err());
	assert!(parse("v=spf1 exists:").is_err());
}

#[test]
fn parses_exists_and_ptr() {
	let record = parse("v=spf1 exists:_spf.%{d}.example.org ptr ?all").expect("valid");
	assert_eq!(
		record.directives[0].1,
		Mechanism::Exists {
			domain: "_spf.%{d}.example.org".into()
		}
	);
	assert_eq!(record.directives[1].1, Mechanism::Ptr { domain: None });
	assert_eq!(record.directives[2].1, Mechanism::All);

	let record = parse("v=spf1 ptr:example.org -all").expect("valid");
	assert_eq!(
		record.directives[0].1,
		Mechanism::Ptr {
			domain: Some("example.org".into())
		}
	);
}

#[test]
fn all_qualifiers_parse() {
	let record = parse("v=spf1 +all -all ~all ?all").expect("valid");
	let qualifiers: Vec<Qualifier> = record.directives.iter().map(|(q, _)| *q).collect();
	assert_eq!(
		qualifiers,
		vec![
			Qualifier::Pass,
			Qualifier::Fail,
			Qualifier::SoftFail,
			Qualifier::Neutral
		]
	);
}
