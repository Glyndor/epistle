//! A feedback report quotes the reported message cut at a fixed size, which
//! can fall between the two bytes of a line ending; what is queued never
//! holds a lone CR.

use super::*;

#[test]
fn a_quote_cut_anywhere_near_the_cap_fits_the_queue() {
	for cut in MAX_EMBEDDED - 3..=MAX_EMBEDDED + 3 {
		for poison in [b"\r".as_slice(), b"\0".as_slice(), b"\r\r\n".as_slice()] {
			let mut reported = b"From: a@example.net\r\n\r\n".to_vec();
			reported.resize(cut, b'x');
			reported.extend_from_slice(poison);
			reported.extend_from_slice(&[b'y'; 50]);
			let report = Report {
				report_to: "abuse@example.org",
				feedback_type: FeedbackType::Abuse,
				original_mail_from: "a@example.net",
				source_ip: Some("192.0.2.1"),
				reported_message: &reported,
			};
			let message = build("mail.example.org", &report, std::time::UNIX_EPOCH);
			assert!(!crate::util::header_block::has_unframed_byte(&message.data));
		}
	}
}
