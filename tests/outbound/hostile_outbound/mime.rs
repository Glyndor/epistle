//! Adversarial MIME structures against the bounded attachment walker.

use epistle::antispam::attachments::rules::{Extensions, Reason};
use epistle::antispam::attachments::walk::{self, Limits, Stop};
use epistle::antispam::attachments::{self, Budget, Report};

use super::harness::bounded;

fn inspect(raw: &[u8]) -> Report {
	attachments::inspect(raw, &Extensions::default(), Budget::bytes(1 << 20))
}

fn multipart(count: usize) -> Vec<u8> {
	let mut raw = b"Content-Type: multipart/mixed; boundary=p\r\n\r\n".to_vec();
	for index in 0..count {
		raw.extend_from_slice(
			format!("--p\r\nContent-Type: application/octet-stream; name={index}.bin\r\n\r\nx\r\n")
				.as_bytes(),
		);
	}
	raw.extend_from_slice(b"--p--\r\n");
	raw
}

#[test]
fn hundred_thousand_nested_multiparts_stop_at_depth_ten() {
	bounded(|| {
		let mut raw = Vec::new();
		for index in 0..100_000 {
			raw.extend_from_slice(
				format!("Content-Type: multipart/mixed; boundary=b{index}\r\n\r\n--b{index}\r\n")
					.as_bytes(),
			);
		}
		raw.extend_from_slice(b"Content-Type: text/plain\r\n\r\nhidden\r\n");
		let report = inspect(&raw);
		assert_eq!(report.stopped, Some(Stop::TooDeep));
		assert_eq!(report.reasons(), [Reason::ScanLimit]);
		assert!(report.parts.is_empty());
	});
}

#[test]
fn hundred_thousand_nested_messages_stop_without_recursive_stack_growth() {
	bounded(|| {
		let raw = b"Content-Type: message/rfc822\r\n\r\n".repeat(100_000);
		let report = inspect(&raw);
		assert_eq!(report.stopped, Some(Stop::TooDeep));
		assert_eq!(report.reasons(), [Reason::ScanLimit]);
		assert!(report.parts.is_empty());
	});
}

#[test]
fn thousand_parts_including_container_fit_but_next_part_stops() {
	bounded(|| {
		let allowed = inspect(&multipart(999));
		assert_eq!(allowed.stopped, None);
		assert_eq!(allowed.parts.len(), 999);
		for count in [1000, 10_000] {
			let report = inspect(&multipart(count));
			assert_eq!(report.stopped, Some(Stop::TooManyParts));
			assert_eq!(report.parts.len(), 999);
			assert!(report.reasons().contains(&Reason::ScanLimit));
		}
	});
}

#[test]
fn ten_thousand_headers_hit_header_byte_limit_before_parsing() {
	bounded(|| {
		let mut raw = b"X-Padding: 1234567890\r\n".repeat(10_000);
		raw.extend_from_slice(b"Content-Type: text/plain\r\n\r\nbody");
		let report = inspect(&raw);
		assert_eq!(report.stopped, Some(Stop::HeaderTooLarge));
		assert_eq!(report.reasons(), [Reason::ScanLimit]);
		assert!(report.parts.is_empty());
	});
}

#[test]
fn megabyte_boundary_is_stopped_before_mail_parser() {
	bounded(|| {
		let mut raw = b"Content-Type: multipart/mixed; boundary=\"".to_vec();
		raw.extend(std::iter::repeat_n(b'x', 1 << 20));
		raw.extend_from_slice(b"\"\r\n\r\nbody");
		let report = inspect(&raw);
		assert_eq!(report.stopped, Some(Stop::HeaderTooLarge));
		assert!(report.parts.is_empty());
	});
}

#[test]
fn boundary_longer_than_998_is_opaque_and_ambiguous() {
	bounded(|| {
		let raw = format!(
			"Content-Type: multipart/mixed; boundary=\"{}\"\r\n\r\npayload",
			"x".repeat(999)
		);
		let report = inspect(raw.as_bytes());
		assert!(report.reasons().contains(&Reason::AmbiguousMime));
		assert_eq!(report.parts.len(), 1);
	});
}

#[test]
fn fifty_thousand_near_boundary_matches_are_bounded_and_ambiguous() {
	bounded(|| {
		let boundary = "q".repeat(70);
		let mut raw = format!("Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n--{boundary}\r\nContent-Type: text/plain\r\n\r\n").into_bytes();
		raw.extend(format!("--{boundary}junk\r\n").repeat(50_000).as_bytes());
		raw.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
		let report = inspect(&raw);
		assert_eq!(report.stopped, None);
		assert!(report.ambiguous);
		assert!(report.reasons().contains(&Reason::AmbiguousMime));
		assert!(report.reasons().contains(&Reason::ScanLimit));
		assert!(report.parts.len() <= 1);
	});
}

#[test]
fn base64_expansion_exhausts_decode_budget_and_keeps_only_sniff_prefix() {
	bounded(|| {
		let mut raw = b"Content-Type: application/octet-stream; name=a.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n".to_vec();
		raw.extend(b"QUFB".repeat(100_000));
		let limits = Limits {
			max_depth: 10,
			max_parts: 1000,
			max_decoded: 1024,
			deadline: None,
		};
		let mut count = 0;
		let walked = walk::walk(&raw, &limits, |leaf| {
			count += 1;
			assert!(leaf.truncated);
			assert_eq!(leaf.content.len(), attachments::sniff::SNIFF_WINDOW);
			assert!(leaf.content.iter().all(|b| *b == b'A'));
		});
		assert_eq!(walked.stopped, None);
		assert_eq!(count, 1);
		let report = attachments::inspect(&raw, &Extensions::default(), Budget::bytes(1024));
		assert!(report.reasons().contains(&Reason::ScanLimit));
	});
}

#[test]
fn expired_scan_deadline_reports_unread_content_as_scan_limit() {
	bounded(|| {
		let budget = Budget {
			max_decoded: 1 << 20,
			deadline: Some(std::time::Instant::now()),
		};
		let report = attachments::inspect(&multipart(10_000), &Extensions::default(), budget);
		assert_eq!(report.stopped, Some(Stop::OutOfTime));
		assert_eq!(report.reasons(), [Reason::ScanLimit]);
		assert!(report.parts.is_empty());
	});
}

#[test]
fn traversal_attachment_names_cannot_hide_dangerous_extension() {
	bounded(|| {
		for name in [
			"../../payload.exe",
			"..\\..\\payload.exe",
			"/tmp/payload.exe",
		] {
			let raw = format!(
				"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''{}\r\n\r\nhello",
				name.replace('\\', "%5C")
			);
			let report = inspect(raw.as_bytes());
			assert_eq!(report.parts.len(), 1);
			assert!(
				report.reasons().contains(&Reason::DangerousExtension),
				"{name}: {report:?}"
			);
		}
	});
}

#[test]
fn nul_in_rfc2231_filename_does_not_hide_executable_suffix() {
	bounded(|| {
		let raw = b"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''payload.exe%00.txt\r\n\r\nhello";
		let report = inspect(raw);
		assert_eq!(report.parts.len(), 1);
		assert!(report.parts[0].names.iter().any(|name| name.contains('\0')));
		assert!(report.reasons().contains(&Reason::DangerousExtension));
	});
}
