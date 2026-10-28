use super::*;

#[test]
fn parses_typical_record() {
	let record = parse("v=DMARC1; p=reject; adkim=s; aspf=r")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.policy, Policy::Reject);
	assert_eq!(record.subdomain_policy, Policy::Reject);
	assert_eq!(record.dkim_alignment, Alignment::Strict);
	assert_eq!(record.spf_alignment, Alignment::Relaxed);
}

#[test]
fn subdomain_policy_overrides() {
	let record = parse("v=DMARC1; p=reject; sp=none")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.policy, Policy::Reject);
	assert_eq!(record.subdomain_policy, Policy::None);
}

#[test]
fn parses_pct() {
	let record = parse("v=DMARC1; p=quarantine; pct=50")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.policy, Policy::Quarantine);
	assert_eq!(record.pct, 50);
}

#[test]
fn pct_defaults_to_100() {
	let record = parse("v=DMARC1; p=reject")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.pct, 100);
}

#[test]
fn pct_clamped_to_100() {
	let record = parse("v=DMARC1; p=reject; pct=200")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.pct, 100);
}

#[test]
fn pct_zero_parsed() {
	let record = parse("v=DMARC1; p=reject; pct=0")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.pct, 0);
}

#[test]
fn pct_non_numeric_is_error() {
	assert_eq!(parse("v=DMARC1; p=reject; pct=all"), Some(Err(())));
}

#[test]
fn parses_rua_single() {
	let record = parse("v=DMARC1; p=none; rua=mailto:agg@example.org")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.rua, vec!["mailto:agg@example.org"]);
}

#[test]
fn parses_rua_multiple_and_strips_maxsize() {
	let record = parse("v=DMARC1; p=reject; rua=mailto:a@example.org!10m,mailto:b@example.net")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(
		record.rua,
		vec!["mailto:a@example.org", "mailto:b@example.net"]
	);
}

#[test]
fn rua_defaults_to_empty() {
	let record = parse("v=DMARC1; p=none").expect("is dmarc").expect("valid");
	assert!(record.rua.is_empty());
}

#[test]
fn parses_rua_and_pct_together() {
	let record = parse("v=DMARC1; p=quarantine; rua=mailto:agg@example.org; pct=50")
		.expect("is dmarc")
		.expect("valid");
	assert_eq!(record.policy, Policy::Quarantine);
	assert_eq!(record.pct, 50);
	assert_eq!(record.rua, vec!["mailto:agg@example.org"]);
}

#[test]
fn non_dmarc_text_is_none() {
	assert!(parse("v=spf1 -all").is_none());
	assert!(parse("some random text").is_none());
}

#[test]
fn missing_policy_is_error() {
	assert_eq!(parse("v=DMARC1; adkim=s"), Some(Err(())));
}

#[test]
fn malformed_values_are_errors() {
	assert_eq!(parse("v=DMARC1; p=destroy"), Some(Err(())));
	assert_eq!(parse("v=DMARC1; p=none; adkim=x"), Some(Err(())));
	assert_eq!(parse("v=DMARC1; p"), Some(Err(())));
}
