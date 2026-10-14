//! A dual-signing rotation killed at any step: both keys switch together
//! or neither does, at the crash and after the restart, and the next start
//! completes or rolls back both, leaving no TXT record and no key file that
//! nothing names. The configured RSA key and its records are never removed.

use super::steps::Step;
use super::tests_crash::{Start, Visibility};
use super::tests_rsa_lab::{RsaLab, crash_and_restart, skipped};

macro_rules! dual_completes {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = match RsaLab::new(Start::RotationDue) {
				Ok(lab) => lab,
				Err(reason) => return skipped(&reason),
			};
			let signer = crash_and_restart(&lab, $step, Visibility::AfterOneWait).await;
			lab.assert_settled(&signer, "ed100", Some("rsa100"), Some(("ed0", None))).await;
		}
	)*};
}

macro_rules! dual_rolls_back {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = match RsaLab::new(Start::RotationDue) {
				Ok(lab) => lab,
				Err(reason) => return skipped(&reason),
			};
			let signer = crash_and_restart(&lab, $step, Visibility::Never).await;
			lab.assert_settled(&signer, "ed0", None, None).await;
		}
	)*};
}

macro_rules! dual_retires {
	($($name:ident: $step:expr,)*) => {$(
		#[tokio::test]
		async fn $name() {
			let lab = match RsaLab::new(Start::RetireDue) {
				Ok(lab) => lab,
				Err(reason) => return skipped(&reason),
			};
			let signer = crash_and_restart(&lab, $step, Visibility::AfterOneWait).await;
			lab.assert_settled(&signer, "ed100", Some("rsa100"), None).await;
		}
	)*};
}

dual_completes! {
	dual_crash_after_journal_completes_both: Step::Journaled,
	dual_crash_after_ed25519_key_write_completes_both: Step::KeyWritten,
	dual_crash_after_rsa_key_write_completes_both: Step::RsaKeyWritten,
	dual_crash_after_first_ed25519_publish_completes_both: Step::Published(0),
	dual_crash_after_first_rsa_publish_completes_both: Step::RsaPublished(0),
	dual_crash_after_last_ed25519_publish_completes_both: Step::Published(1),
	dual_crash_after_last_rsa_publish_completes_both: Step::RsaPublished(1),
	dual_crash_during_dns_wait_completes_both: Step::Waiting,
	dual_crash_after_confirmation_completes_both: Step::Confirmed,
	dual_crash_after_commit_keeps_both: Step::Committed,
	dual_crash_after_signer_swap_keeps_both: Step::Swapped,
}

dual_rolls_back! {
	dual_crash_during_failing_dns_wait_rolls_back_both: Step::Waiting,
	dual_crash_after_marking_withdrawal_rolls_back_both: Step::Withdrawing,
	dual_crash_after_first_withdrawal_rolls_back_both: Step::WithdrawnRecord(0),
	dual_crash_after_last_withdrawal_rolls_back_both: Step::WithdrawnRecord(1),
	dual_crash_after_withdrawn_key_removal_rolls_back_both: Step::WithdrawnKey,
}

dual_retires! {
	dual_crash_after_first_retired_records_retires_both: Step::RetiredRecord(0),
	dual_crash_after_last_retired_records_retires_both: Step::RetiredRecord(1),
	dual_crash_after_retired_key_removal_retires_both: Step::RetiredKey,
	dual_crash_after_retired_state_save_retires_both: Step::RetiredState,
}
