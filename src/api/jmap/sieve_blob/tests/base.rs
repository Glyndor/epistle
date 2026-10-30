use super::*;

#[test]
fn only_the_ids_this_server_mints_parse() {
	let id = "0123456789abcdef0123456789abcdef";
	assert_eq!(parse(&blob_id(id, 7)), Some((id, 7)));
	for bad in [
		"sieve-",
		"sieve-0123-1",
		"sieve-0123456789abcdef0123456789abcdef",
		"sieve-0123456789abcdef0123456789abcdef-",
		"sieve-0123456789abcdef0123456789abcdef-+1",
		"sieve-0123456789abcdef0123456789abcdef-1-2",
		"sieve-0123456789abcdef0123456789abcdez-1",
		"sieve-0123456789abcdef0123456789abcdef-99999999999999999999999",
		"../sieve-0123456789abcdef0123456789abcdef-1",
	] {
		assert_eq!(parse(bad), None, "{bad}");
	}
}
