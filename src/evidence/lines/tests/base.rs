use super::*;

fn collect(bytes: &[u8]) -> Vec<String> {
	let mut lines = Lines::new(std::io::Cursor::new(bytes.to_vec()));
	let mut out = Vec::new();
	while let Some((_, line)) = lines.next_line().expect("read") {
		out.push(match line {
			Line::Complete(bytes) => format!("ok:{}", bytes.len()),
			Line::TooLong => "too long".to_string(),
			Line::Torn(bytes) => format!("torn:{}", bytes.len()),
		});
	}
	out
}

#[test]
fn complete_long_and_torn_lines_are_told_apart() {
	let mut bytes = b"a\nbb\n".to_vec();
	bytes.extend(vec![b'x'; MAX_LINE + 1]);
	bytes.push(b'\n');
	bytes.extend(vec![b'y'; MAX_LINE]);
	bytes.push(b'\n');
	bytes.extend_from_slice(b"ccc");
	assert_eq!(
		collect(&bytes),
		[
			"ok:1".to_string(),
			"ok:2".to_string(),
			"too long".to_string(),
			format!("ok:{MAX_LINE}"),
			"torn:3".to_string()
		]
	);
}

#[test]
fn a_line_many_times_the_limit_is_drained_not_held() {
	let mut bytes = vec![b'z'; 20 * MAX_LINE];
	bytes.extend_from_slice(b"\nnext\n");
	assert_eq!(collect(&bytes), ["too long", "ok:4"]);
}
