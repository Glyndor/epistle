use super::*;

fn multiline(body: &[u8]) -> Response {
	Response::Multiline {
		status: "s".into(),
		body: body.to_vec(),
	}
}

#[test]
fn a_big_body_comes_in_bounded_pieces_that_join_to_the_encoding() {
	let line = b".dot line\nplain line\r\n";
	let body: Vec<u8> = line
		.iter()
		.copied()
		.cycle()
		.take(3 * WIRE_CHUNK + 7)
		.collect();
	let response = multiline(&body);
	let pieces: Vec<Vec<u8>> = response.wire().collect();
	assert!(pieces.len() >= 4);
	for piece in &pieces {
		// A piece holds one chunk of body, stuffed, plus the status or end.
		assert!(piece.len() <= 2 * WIRE_CHUNK + 32, "{}", piece.len());
	}
	let joined: Vec<u8> = pieces.concat();
	let text = String::from_utf8(joined).expect("text");
	assert!(text.starts_with("+OK s\r\n..dot line\r\nplain line\r\n"));
	assert!(text.ends_with("\r\n.\r\n"));
	assert!(!text.contains("\n\n") && !text.replace("\r\n", "").contains('\n'));
}

#[test]
fn a_chunk_boundary_between_cr_and_lf_adds_no_extra_cr() {
	let mut body = vec![b'a'; WIRE_CHUNK - 1];
	body.extend_from_slice(b"\r\n.x\r\n");
	let text = String::from_utf8(multiline(&body).encode()).expect("text");
	assert!(!text.contains("\r\r"));
	assert!(text.contains("\r\n..x\r\n.\r\n"));
}

#[test]
fn single_line_responses_are_one_piece() {
	for response in [
		Response::Ok("x".into()),
		Response::Err("y".into()),
		Response::Bye("z".into()),
		Response::Continuation,
	] {
		assert_eq!(response.wire().count(), 1);
	}
}
