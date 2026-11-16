//! Builders for the reports, the directory and the settings the tests share.

use super::*;

pub(crate) const HOSTNAME: &str = "mail.example.org";

pub(crate) const PROVIDER: &str = "fbl@arf.example.net";

pub(crate) fn directory() -> Directory {
	Directory::new(
		["example.org".to_string()],
		[
			("alice@example.org".to_string(), "alice".to_string()),
			("bob@example.org".to_string(), "bob".to_string()),
			("fbl@example.org".to_string(), "fbl".to_string()),
		],
	)
}

pub(crate) fn reports(extra: &str) -> Reports {
	let section =
		format!("fbl_mailbox = \"fbl@example.org\"\nfbl_senders = [\"{PROVIDER}\"]\n{extra}");
	toml::from_str(&section).expect("reports")
}

pub(crate) fn fbl(extra: &str) -> Fbl {
	Fbl::new(&reports(extra), HOSTNAME, vec!["s1".to_string()]).expect("fbl")
}

/// The headers of the message the report is about: sent by `from` to `to`
/// with the `Feedback-ID` line given, a `Message-ID` and a DKIM signature of
/// the domain of `from`.
pub(crate) fn original(from: &str, to: &str, feedback_id: Option<&str>) -> String {
	let domain = from.rsplit_once('@').map_or("example.org", |(_, d)| d);
	let mut headers = format!(
		"DKIM-Signature: v=1; a=ed25519-sha256; d={domain}; s=s1; h=from:to; bh=x; b=y\r\n\
		 From: Alice <{from}>\r\nTo: {to}\r\nMessage-ID: <1@{domain}>\r\n\
		 Subject: Hello\r\n"
	);
	if let Some(id) = feedback_id {
		headers.push_str(&format!("Feedback-ID: {id}\r\n"));
	}
	headers
}

/// A report whose machine part holds `fields` and whose third part quotes
/// `quoted`.
pub(crate) fn report(fields: &str, quoted: &str) -> Vec<u8> {
	format!(
		"From: {PROVIDER}\r\nTo: fbl@example.org\r\nSubject: complaint\r\n\
		 Content-Type: multipart/report; report-type=feedback-report; boundary=\"bd\"\r\n\
		 \r\n--bd\r\nContent-Type: text/plain\r\n\r\nThis is a spam complaint.\r\n\
		 --bd\r\nContent-Type: message/feedback-report\r\n\r\n{fields}\r\n\
		 --bd\r\nContent-Type: message/rfc822\r\n\r\n{quoted}\r\nbody\r\n--bd--\r\n"
	)
	.into_bytes()
}

pub(crate) fn complaint_fields(recipient: &str) -> String {
	format!(
		"Feedback-Type: abuse\r\nUser-Agent: Example/1.0\r\nVersion: 1\r\n\
		 Original-Rcpt-To: <{recipient}>\r\nSource-IP: 192.0.2.7\r\n"
	)
}

/// A complaint about a message `alice` sent as transactional mail.
pub(crate) fn valid_report(recipient: &str) -> Vec<u8> {
	report(
		&complaint_fields(recipient),
		&original(
			"alice@example.org",
			recipient,
			Some("epistle:transactional:example.org"),
		),
	)
}

/// The `Authentication-Results` this server stamps when `spf` and `dkim_d`
/// are what it verified.
pub(crate) fn stamp(spf: Option<&str>, dkim_d: Option<&str>) -> String {
	let mut methods = Vec::new();
	if let Some(domain) = spf {
		methods.push(format!("spf=pass smtp.mailfrom={domain}"));
	}
	if let Some(d) = dkim_d {
		methods.push(format!("dkim=pass header.d={d}"));
	}
	format!(
		"Authentication-Results: {HOSTNAME}; {}\r\n",
		methods.join("; ")
	)
}

/// A message from the enrolled provider whose SPF this server verified.
pub(crate) fn verified(data: Vec<u8>) -> AcceptedMessage {
	stamped_with(data, &stamp(Some("arf.example.net"), None))
}

/// `data` behind the given trace header, from the enrolled provider.
pub(crate) fn stamped_with(data: Vec<u8>, header: &str) -> AcceptedMessage {
	let mut stamped = header.as_bytes().to_vec();
	stamped.extend_from_slice(&data);
	AcceptedMessage {
		reverse_path: PROVIDER.into(),
		recipients: vec!["fbl@example.org".into()],
		data: stamped,
		sender_verified: true,
		..AcceptedMessage::default()
	}
}
