//! Whether a message is itself a delivery status report.
//!
//! A report is never sent for a report. The null reverse-path stops the ones
//! this server writes, but a report from another host often carries a
//! reverse-path of its own, and the fields of its header block are all there
//! is to tell it apart.

/// Whether the header block of `data` declares a `multipart/report` of the
/// `delivery-status` kind (RFC 3464).
pub(super) fn is_delivery_report(data: &[u8]) -> bool {
	let end = data
		.windows(4)
		.position(|w| w == b"\r\n\r\n")
		.unwrap_or(data.len());
	let block = String::from_utf8_lossy(&data[..end]);
	let mut unfolded: Vec<String> = Vec::new();
	for line in block.split("\r\n") {
		match (line.starts_with([' ', '\t']), unfolded.last_mut()) {
			(true, Some(previous)) => {
				previous.push(' ');
				previous.push_str(line.trim());
			}
			_ => unfolded.push(line.to_string()),
		}
	}
	unfolded.iter().any(|field| {
		let Some((name, value)) = field.split_once(':') else {
			return false;
		};
		let value = value.to_ascii_lowercase();
		name.trim().eq_ignore_ascii_case("content-type")
			&& value.contains("multipart/report")
			&& value.contains("delivery-status")
	})
}
