use super::*;

fn message(headers: &str) -> Vec<u8> {
	format!("From: news@example.org\r\n{headers}Subject: offer\r\n\r\nbody\r\n").into_bytes()
}

const GOOD: &str = "List-Unsubscribe: <mailto:u@example.org>, <https://example.org/u?t=1>\r\n\
	List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n";

#[test]
fn one_click_unsubscribe_is_accepted() {
	assert_eq!(check(&message(GOOD)), Ok(()));
}

#[test]
fn missing_list_unsubscribe_is_refused() {
	let data = message("List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n");
	assert_eq!(check(&data), Err(MarketingRefusal::NoUnsubscribeUri));
}

#[test]
fn a_mailto_only_unsubscribe_is_refused() {
	let data = message(
		"List-Unsubscribe: <mailto:u@example.org>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	assert_eq!(check(&data), Err(MarketingRefusal::NoUnsubscribeUri));
	let plain_http = message(
		"List-Unsubscribe: <http://example.org/u>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	assert_eq!(check(&plain_http), Err(MarketingRefusal::NoUnsubscribeUri));
	let empty_https = message(
		"List-Unsubscribe: <https://>\r\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	assert_eq!(check(&empty_https), Err(MarketingRefusal::NoUnsubscribeUri));
}

#[test]
fn missing_or_wrong_one_click_post_is_refused() {
	let none = message("List-Unsubscribe: <https://example.org/u>\r\n");
	assert_eq!(check(&none), Err(MarketingRefusal::NoOneClick));
	let wrong = message(
		"List-Unsubscribe: <https://example.org/u>\r\nList-Unsubscribe-Post: One-Click\r\n",
	);
	assert_eq!(check(&wrong), Err(MarketingRefusal::NoOneClick));
	let twice = message(
		"List-Unsubscribe: <https://example.org/u>\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n\
		 List-Unsubscribe-Post: List-Unsubscribe=One-Click\r\n",
	);
	assert_eq!(check(&twice), Err(MarketingRefusal::NoOneClick));
}

#[test]
fn the_refusal_is_a_permanent_smtp_reply() {
	let reply = MarketingRefusal::NoOneClick.smtp_reply();
	let text = reply.to_string();
	assert!(text.starts_with("550 5.7.1 marketing mail needs"), "{text}");
}

#[test]
fn bulk_precedence_replaces_the_clients_own() {
	let mut data = message("Precedence: first-class\r\n");
	mark_bulk(&mut data);
	let expected = [b"Precedence: bulk\r\n".as_slice(), &message("")].concat();
	assert!(
		data == expected,
		"the client's Precedence was kept or bulk not added"
	);
	let mut plain = message("");
	mark_bulk(&mut plain);
	let expected = [b"Precedence: bulk\r\n".as_slice(), &message("")].concat();
	assert!(plain == expected, "Precedence: bulk was not added");
}
