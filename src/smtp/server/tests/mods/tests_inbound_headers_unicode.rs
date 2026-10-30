use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::tests_auth::directory_with_password;
use super::*;
use crate::smtp::sink::MemorySink;

const PLAIN: &str =
	"From: eve@sender.example\r\nTo: alice@example.org\r\nSubject: hi\r\n\r\nbody\r\n";

/// A reserved field whose name carries a trailing non-ASCII whitespace
/// character (the 19 code points of `char::is_whitespace` outside ASCII)
/// reaches the SMTP boundary unchanged by mail-parser 0.11.9 and by the
/// earlier strip pass; the in-place strip now folds the same bytes DKIM
/// and ARC-AMS fold with `name.trim_end()`. The end-to-end check confirms
/// two things: the message is accepted by DATA and BDAT (so legitimate
/// mail that carries trailing Unicode whitespace outside a reserved
/// field is not refused), and the bytes the sink receives do not carry a
/// canonical reserved name according to the real DKIM parser.
#[tokio::test]
async fn unicode_whitespace_after_a_reserved_field_is_removed_on_data_and_bdat() {
	const NAMES: &[&str] = &[
		"Authentication-Results",
		"Received-SPF",
		"Delivered-To",
		"Return-Path",
		"Epistle-Class",
	];
	const UNICODE_WS: &[char] = &[
		'\u{0085}', '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}',
		'\u{2004}', '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}',
		'\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
	];
	for name in NAMES {
		for ws in UNICODE_WS {
			let value = if *name == "Authentication-Results" {
				"mail.example.org; dkim=pass; forged".to_string()
			} else {
				"forged".to_string()
			};
			let payload = format!("{name}{ws}: {value}\r\n{PLAIN}");
			for bdat in [false, true] {
				let sink = Arc::new(MemorySink::new());
				let server = Server::new("mail.example.org", sink.clone())
					.with_directory(directory_with_password());
				let (client, stream) = tokio::io::duplex(256 * 1024);
				let task = tokio::spawn(async move {
					server
						.handle(stream, Some("192.0.2.7".parse().expect("ip")))
						.await
				});
				let mut script =
					"EHLO prior.example\r\nMAIL FROM:<eve@sender.example>\r\nRCPT TO:<alice@example.org>\r\n"
						.to_string();
				if bdat {
					script.push_str(&format!("BDAT {} LAST\r\n{payload}QUIT\r\n", payload.len()));
				} else {
					script.push_str(&format!("DATA\r\n{payload}.\r\nQUIT\r\n"));
				}
				let (mut read, mut write) = tokio::io::split(client);
				write.write_all(script.as_bytes()).await.expect("write");
				write.shutdown().await.expect("shutdown");
				let mut output = String::new();
				read.read_to_string(&mut output).await.expect("read");
				task.await.expect("task").expect("server");
				assert!(
					output.contains("250 2.0.0 ok\r\n221"),
					"BDAT={bdat}, {name:?} {ws:?}: {output}"
				);
				let messages = sink.messages();
				assert_eq!(messages.len(), 1, "BDAT={bdat}, {name:?} {ws:?}");
				let data = &messages[0].data;
				let dkim_names = crate::dkim::header_names(data);
				assert!(
					!dkim_names.iter().any(|n| n == *name),
					"DKIM must not read canonical {name:?} from delivered bytes ({ws:?}, BDAT={bdat})"
				);
				let parsed = mail_parser::MessageParser::default()
					.parse(data)
					.expect("delivered parses");
				assert!(
					parsed.headers().value(*name).is_none(),
					"mail-parser must not read {name:?} from delivered bytes ({ws:?}, BDAT={bdat})"
				);
			}
		}
	}
}
