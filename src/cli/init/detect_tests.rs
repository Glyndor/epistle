//! The answers-file side of detection: which addresses get filled, when
//! the detector is consulted at all, and the NAT hint.

use std::cell::Cell;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::super::answers::{Mode, Services};
use super::super::answers_none::Declined;
use super::*;

/// A detector with a scripted answer that counts its calls.
pub(in crate::cli::init) struct Scripted {
	pub(in crate::cli::init) answer: Option<Detected>,
	pub(in crate::cli::init) calls: Cell<usize>,
}

impl Scripted {
	pub(in crate::cli::init) fn found(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Self {
		Self {
			answer: Some((v4, v6)),
			calls: Cell::new(0),
		}
	}
	/// A detector whose interface walk fails.
	pub(in crate::cli::init) fn failing() -> Self {
		Self {
			answer: None,
			calls: Cell::new(0),
		}
	}
}

impl Detector for Scripted {
	fn detect(&self) -> std::io::Result<Detected> {
		self.calls.set(self.calls.get() + 1);
		self.answer
			.ok_or_else(|| std::io::Error::other("getifaddrs refused"))
	}
}

/// A detector that must never be consulted.
pub(in crate::cli::init) struct MustNotDetect;

impl Detector for MustNotDetect {
	fn detect(&self) -> std::io::Result<Detected> {
		panic!("the detector was called although every address was given");
	}
}

pub(in crate::cli::init) fn v4() -> Ipv4Addr {
	"8.8.8.8".parse().expect("v4")
}

pub(in crate::cli::init) fn v6() -> Ipv6Addr {
	"2606:4700::1111".parse().expect("v6")
}

fn answers(public_ipv4: Option<Ipv4Addr>, public_ipv6: Option<Ipv6Addr>) -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4,
		public_ipv6,
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: None,
		acme: None,
	}
}

fn fill(answers: &mut Answers, detector: &dyn Detector) -> String {
	let mut out = Vec::new();
	fill_missing(answers, Declined::default(), detector, &mut out);
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn both_missing_are_filled_from_one_detection_and_reported() {
	let detector = Scripted::found(Some(v4()), Some(v6()));
	let mut filled = answers(None, None);
	let text = fill(&mut filled, &detector);
	assert_eq!(filled.public_ipv4, Some(v4()));
	assert_eq!(filled.public_ipv6, Some(v6()));
	assert_eq!(
		detector.calls.get(),
		1,
		"one interface walk for both families"
	);
	assert_eq!(
		text,
		"detected public_ipv4 = 8.8.8.8 (not in the answers file)\n\
		 detected public_ipv6 = 2606:4700::1111 (not in the answers file)\n"
	);
}

#[test]
fn addresses_the_file_names_skip_the_detector_entirely() {
	let other_v4: Ipv4Addr = "1.1.1.1".parse().expect("v4");
	let mut filled = answers(Some(other_v4), Some(v6()));
	let text = fill(&mut filled, &MustNotDetect);
	assert_eq!(filled.public_ipv4, Some(other_v4));
	assert_eq!(filled.public_ipv6, Some(v6()));
	assert_eq!(text, "", "nothing to report when the file names both");
}

#[test]
fn a_named_address_is_kept_while_the_missing_one_is_filled() {
	let named: Ipv4Addr = "1.1.1.1".parse().expect("v4");
	let detector = Scripted::found(Some(v4()), Some(v6()));
	let mut filled = answers(Some(named), None);
	let text = fill(&mut filled, &detector);
	assert_eq!(
		filled.public_ipv4,
		Some(named),
		"the file's IPv4 must not be replaced by the detected one"
	);
	assert_eq!(filled.public_ipv6, Some(v6()));
	assert_eq!(
		text,
		"detected public_ipv6 = 2606:4700::1111 (not in the answers file)\n"
	);
}

#[test]
fn nothing_detected_leaves_the_addresses_empty_and_hints_at_nat() {
	let detector = Scripted::found(None, None);
	let mut filled = answers(None, None);
	let text = fill(&mut filled, &detector);
	assert_eq!((filled.public_ipv4, filled.public_ipv6), (None, None));
	assert_eq!(
		text,
		"no global IPv4 or IPv6 address on this host's interfaces (behind NAT the public one is not visible here; set it by hand if the server has one)\n"
	);
}

#[test]
fn a_failing_detector_counts_as_nothing_found() {
	let detector = Scripted::failing();
	let mut filled = answers(None, Some(v6()));
	let text = fill(&mut filled, &detector);
	assert_eq!(detector.calls.get(), 1);
	assert_eq!((filled.public_ipv4, filled.public_ipv6), (None, Some(v6())));
	assert_eq!(
		text,
		"no global IPv4 address on this host's interfaces (behind NAT the public one is not visible here; set it by hand if the server has one)\n"
	);
}

fn fill_declining(answers: &mut Answers, declined: Declined, detector: &dyn Detector) -> String {
	let mut out = Vec::new();
	fill_missing(answers, declined, detector, &mut out);
	String::from_utf8(out).expect("utf-8")
}

#[test]
fn an_explicit_none_is_kept_and_the_detector_is_not_called() {
	let declined = Declined { v4: true, v6: true };
	let mut filled = answers(None, None);
	let text = fill_declining(&mut filled, declined, &MustNotDetect);
	assert_eq!((filled.public_ipv4, filled.public_ipv6), (None, None));
	assert_eq!(text, "", "no notice and no NAT hint for a declined family");
}

#[test]
fn an_explicit_none_for_one_family_still_detects_the_other() {
	let declined = Declined {
		v4: true,
		v6: false,
	};
	let detector = Scripted::found(Some(v4()), Some(v6()));
	let mut filled = answers(None, None);
	let text = fill_declining(&mut filled, declined, &detector);
	assert_eq!(
		filled.public_ipv4, None,
		"\"none\" must win over the detected IPv4"
	);
	assert_eq!(filled.public_ipv6, Some(v6()));
	assert_eq!(
		text,
		"detected public_ipv6 = 2606:4700::1111 (not in the answers file)\n"
	);
}

#[test]
fn a_declined_family_gets_no_nat_hint() {
	let declined = Declined {
		v4: false,
		v6: true,
	};
	let detector = Scripted::found(None, Some(v6()));
	let mut filled = answers(None, None);
	let text = fill_declining(&mut filled, declined, &detector);
	assert_eq!(filled.public_ipv6, None);
	assert_eq!(
		text,
		"no global IPv4 address on this host's interfaces (behind NAT the public one is not visible here; set it by hand if the server has one)\n"
	);
}
