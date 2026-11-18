//! What a policy refusal (an enhanced status of subject 7) tells the
//! operator. Most of them are about the sender's reputation, but a remote
//! that refuses to relay is saying the recipient's domain is not one it
//! hosts, which has nothing to do with reputation, and when that remote is
//! this very server the cause is its own configuration.

/// Why a remote refused a recipient on policy grounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
	/// The remote does not host the recipient's domain and will not relay.
	NotHosted,
	/// The remote is this server and does not host the recipient's domain.
	NotHostedHere,
	/// The remote does not want mail from this sender.
	Reputation,
}

impl Refusal {
	/// Read a permanent refusal: `remote` is the host that answered and
	/// `own_hostname` the name this server gives in EHLO.
	pub(super) fn of(reason: &str, remote: &str, own_hostname: &str) -> Self {
		let reason = reason.to_ascii_lowercase();
		let denies_relay = [
			"relaying denied",
			"relay access denied",
			"relay not permitted",
			"relaying not allowed",
			"unable to relay",
		]
		.iter()
		.any(|phrase| reason.contains(phrase));
		match denies_relay {
			true if remote
				.trim_end_matches('.')
				.eq_ignore_ascii_case(own_hostname) =>
			{
				Refusal::NotHostedHere
			}
			true => Refusal::NotHosted,
			false => Refusal::Reputation,
		}
	}

	/// The sentence the log carries.
	pub(super) fn advice(self) -> &'static str {
		match self {
			Refusal::NotHosted => {
				"remote refused to relay: the recipient domain is not one the receiver hosts, \
				 check the recipient address and the MX records of its domain"
			}
			Refusal::NotHostedHere => {
				"this server refused its own message: the recipient domain is not one it hosts, \
				 so the delivery went to a server that is this one; check the address the \
				 message was sent to and the MX records of its domain"
			}
			Refusal::Reputation => {
				"remote refused mail on policy grounds: check the sending \
				 reputation (IP and domain listings, SPF, DKIM, DMARC)"
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::Refusal;

	const OWN: &str = "mail.example.org";

	#[test]
	fn relaying_denied_by_another_server_is_a_hosting_problem() {
		let refusal = Refusal::of("550 5.7.1 relaying denied", "mx.example.net", OWN);
		assert_eq!(refusal, Refusal::NotHosted);
		assert!(!refusal.advice().contains("reputation"));
		assert!(refusal.advice().contains("not one the receiver hosts"));
	}

	#[test]
	fn relaying_denied_by_this_server_says_so() {
		let refusal = Refusal::of("550 5.7.1 Relaying Denied", "MAIL.example.org.", OWN);
		assert_eq!(refusal, Refusal::NotHostedHere);
		assert!(refusal.advice().contains("its own message"));
		assert!(!refusal.advice().contains("reputation"));
	}

	#[test]
	fn other_policy_refusals_keep_the_reputation_hint() {
		let refusal = Refusal::of("550 5.7.1 rejected by policy", "mx.example.net", OWN);
		assert_eq!(refusal, Refusal::Reputation);
		assert!(refusal.advice().contains("reputation"));
	}

	#[test]
	fn the_other_wordings_of_a_relay_refusal_are_recognised() {
		for text in [
			"554 5.7.1 Relay access denied",
			"550 5.7.1 Unable to relay for carol@example.net",
			"550 5.7.1 relay not permitted",
		] {
			assert_eq!(Refusal::of(text, "mx.example.net", OWN), Refusal::NotHosted);
		}
	}
}
