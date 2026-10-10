use super::mime_tests_structure::{email, leaf};
use serde_json::{Value, json};

fn body(email: Value) -> Value {
	json!({"textBody":email["textBody"],"htmlBody":email["htmlBody"],
		"attachments":email["attachments"],"hasAttachment":email["hasAttachment"],
		"preview":email["preview"]})
}

#[test]
fn mime_body_plain_text_lists_match_structure() {
	let part = leaf("0", 5, "text/plain", json!("us-ascii"));
	assert_eq!(
		body(email(b"Subject: plain\r\n\r\nHello")),
		json!({"textBody":[part],"htmlBody":[part],"attachments":[],"hasAttachment":false,"preview":"Hello"}),
		"plain body lists and preview must use the MIME leaf"
	);
}

#[test]
fn mime_body_alternative_selects_each_representation() {
	let raw = b"Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello\r\n--b\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello</p>\r\n--b--\r\n";
	assert_eq!(
		body(email(raw)),
		json!({
		"textBody":[leaf("1",5,"text/plain",json!("utf-8"))],
		"htmlBody":[leaf("2",12,"text/html",json!("utf-8"))],
		"attachments":[],"hasAttachment":false,"preview":"Hello"}),
		"alternative must select plain and HTML bodies independently"
	);
}

#[test]
fn mime_body_mixed_classifies_pdf_and_attached_message() {
	let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nHello\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=doc.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0xLjQK\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: nested\r\n\r\nInside\r\n--b--\r\n";
	let text = leaf("1", 5, "text/plain", json!("us-ascii"));
	let mut pdf = leaf("2", 9, "application/pdf", Value::Null);
	pdf["name"] = json!("doc.pdf");
	pdf["disposition"] = json!("attachment");
	assert_eq!(
		body(email(raw)),
		json!({"textBody":[text],"htmlBody":[text],
		"attachments":[pdf,leaf("3",25,"message/rfc822",Value::Null)],
		"hasAttachment":true,"preview":"Hello"}),
		"mixed must classify PDF and attached messages as downloadable leaves"
	);
}

#[test]
fn mime_body_related_and_alternative_share_inline_media_correctly() {
	let raw = b"Content-Type: multipart/alternative; boundary=a\r\n\r\n--a\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\n\r\nPlain\r\n--m\r\nContent-Type: image/png\r\nContent-Disposition: inline\r\n\r\npng\r\n--m--\r\n--a\r\nContent-Type: multipart/related; boundary=r\r\n\r\n--r\r\nContent-Type: text/html\r\n\r\n<p>Rich</p>\r\n--r\r\nContent-Type: image/jpeg\r\n\r\njpeg\r\n--r--\r\n--a--\r\n";
	let text = leaf("2", 5, "text/plain", json!("us-ascii"));
	let mut png = leaf("3", 3, "image/png", Value::Null);
	png["disposition"] = json!("inline");
	let html = leaf("5", 11, "text/html", json!("us-ascii"));
	assert_eq!(
		body(email(raw)),
		json!({"textBody":[text,png],"htmlBody":[html],
		"attachments":[png,leaf("6",4,"image/jpeg",Value::Null)],
		"hasAttachment":true,"preview":"Plain"}),
		"nested alternatives must retain inline media in the correct lists"
	);
}

#[test]
fn mime_body_html_only_preview_is_plain_text() {
	let raw = b"Content-Type: text/html\r\n\r\n<p>Hello &amp; world</p><script>hidden</script>";
	assert_eq!(
		email(raw)["preview"],
		json!("Hello & world"),
		"HTML preview must contain rendered text without markup or scripts"
	);
}

#[test]
fn mime_body_preview_decodes_charset_and_limits_characters() {
	let mut raw = b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\n".to_vec();
	raw.extend(vec![0xe9; 300]);
	assert_eq!(
		email(&raw)["preview"],
		json!("é".repeat(256)),
		"preview must decode the charset and cap at 256 characters"
	);
}
