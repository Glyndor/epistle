use super::*;

#[test]
fn parses_mailto_record() {
	let record = parse("v=TLSRPTv1; rua=mailto:tlsrpt@example.com")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(record.rua, vec!["mailto:tlsrpt@example.com"]);
}

#[test]
fn parses_https_record() {
	let record = parse("v=TLSRPTv1; rua=https://reports.example.com/tlsrpt")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(record.rua, vec!["https://reports.example.com/tlsrpt"]);
}

#[test]
fn parses_multiple_uris() {
	let record = parse("v=TLSRPTv1; rua=mailto:a@example.com,https://r.example.net/r")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(
		record.rua,
		vec!["mailto:a@example.com", "https://r.example.net/r"]
	);
}

#[test]
fn drops_unsupported_schemes() {
	let record = parse("v=TLSRPTv1; rua=ftp://example.com/r,mailto:ok@example.com")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(record.rua, vec!["mailto:ok@example.com"]);
}

#[test]
fn ignores_unknown_tags() {
	let record = parse("v=TLSRPTv1; rua=mailto:a@example.com; foo=bar")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(record.rua, vec!["mailto:a@example.com"]);
}

#[test]
fn scheme_match_is_case_insensitive() {
	let record = parse("v=TLSRPTv1; rua=MAILTO:Ops@Example.Com")
		.expect("is tlsrpt")
		.expect("valid");
	// Original casing is preserved; only scheme detection is folded.
	assert_eq!(record.rua, vec!["MAILTO:Ops@Example.Com"]);
}

#[test]
fn non_tlsrpt_text_is_none() {
	assert!(parse("v=DMARC1; p=none").is_none());
	assert!(parse("v=spf1 -all").is_none());
	assert!(parse("random text").is_none());
}

#[test]
fn version_must_be_first() {
	assert!(parse("rua=mailto:a@example.com; v=TLSRPTv1").is_none());
}

#[test]
fn missing_rua_is_error() {
	assert_eq!(parse("v=TLSRPTv1"), Some(Err(())));
}

#[test]
fn rua_with_only_unsupported_schemes_is_error() {
	assert_eq!(parse("v=TLSRPTv1; rua=ftp://example.com/r"), Some(Err(())));
}

#[test]
fn malformed_tag_without_equals_is_error() {
	assert_eq!(parse("v=TLSRPTv1; rua"), Some(Err(())));
}

#[test]
fn trailing_semicolon_is_tolerated() {
	let record = parse("v=TLSRPTv1; rua=mailto:a@example.com;")
		.expect("is tlsrpt")
		.expect("valid");
	assert_eq!(record.rua, vec!["mailto:a@example.com"]);
}
