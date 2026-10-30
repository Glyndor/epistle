//! Regression cases from the independent clock review.

use super::{ProbeError, ntp_to_unix_seconds, validate_measurement};
use ntp_proto::{NtpPacket, NtpTimestamp, PollInterval};

#[test]
fn review_rejects_unusable_server_time() {
	for (first, stratum) in [(0x23, 2), (0xe4, 2), (0x24, 16), (0x24, 255)] {
		let mut wire = [0u8; 48];
		wire[0] = first;
		wire[1] = stratum;
		let (packet, _) = NtpPacket::deserialize(&wire, &ntp_proto::NoCipher).unwrap();
		assert!(
			matches!(validate_measurement(&packet), Err(ProbeError::BadReply(_))),
			"mode/leap byte {first:#x}, stratum {stratum}"
		);
	}
}

#[test]
fn review_rejects_every_kiss_including_unauthenticated_nts_nak() {
	let (request, _) = NtpPacket::nts_poll_message(&[1; 96], 0, PollInterval::default());
	let nak = NtpPacket::nts_nak_response(request);
	let mut storage = [0u8; 1024];
	let mut wire = std::io::Cursor::new(storage.as_mut_slice());
	nak.serialize(&mut wire, &ntp_proto::NoCipher, None)
		.unwrap();
	let length = wire.position() as usize;
	let (nak, _) = NtpPacket::deserialize(&wire.get_ref()[..length], &ntp_proto::NoCipher).unwrap();
	assert!(matches!(
		validate_measurement(&nak),
		Err(ProbeError::Kiss(_))
	));
	for code in [*b"DENY", *b"RATE", *b"RSTR", *b"NTSN", *b"????"] {
		let mut wire = [0u8; 48];
		wire[0] = 0x24;
		wire[12..16].copy_from_slice(&code);
		let (packet, _) = NtpPacket::deserialize(&wire, &ntp_proto::NoCipher).unwrap();
		assert!(
			matches!(validate_measurement(&packet), Err(ProbeError::Kiss(_))),
			"{code:?}"
		);
	}
}

#[test]
fn review_unfolds_the_2036_era_boundary() {
	let before = NtpTimestamp::from_seconds_nanos_since_ntp_era(u32::MAX, 500_000_000);
	let after = NtpTimestamp::from_seconds_nanos_since_ntp_era(1, 250_000_000);
	for unix in [1_761_091_200, 2_085_978_495, 2_085_978_497] {
		let reference = std::time::UNIX_EPOCH + std::time::Duration::from_secs(unix);
		assert_eq!(ntp_to_unix_seconds(before, reference), 2_085_978_495.5);
		assert_eq!(ntp_to_unix_seconds(after, reference), 2_085_978_497.25);
	}
}

#[test]
fn review_accepts_synchronized_server_metadata_at_both_stratum_bounds() {
	for leap in [0, 1, 2] {
		for stratum in [1, 15] {
			let mut wire = [0u8; 48];
			wire[0] = (leap << 6) | 0x24;
			wire[1] = stratum;
			let (packet, _) = NtpPacket::deserialize(&wire, &ntp_proto::NoCipher).unwrap();
			assert_eq!(validate_measurement(&packet), Ok(()));
		}
	}
}
