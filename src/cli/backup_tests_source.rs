#[test]
fn postgres_test_source_contains_no_raw_nul_bytes() {
	let source = include_bytes!("backup_pg_tests.rs");
	assert_eq!(
		source.iter().filter(|&&byte| byte == 0).count(),
		0,
		"Rust test source must contain zero raw NUL bytes"
	);
}
