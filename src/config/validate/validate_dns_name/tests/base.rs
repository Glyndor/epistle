	use super::validate_dns_name;

	/// The file scanner already refuses some of these before the rule runs,
	/// so the rule is called directly: its message must not repeat a control
	/// or hidden character raw whichever caller reaches it.
	#[test]
	fn a_refusal_never_repeats_a_control_or_hidden_character_raw() {
		for value in [
			"ab\u{202e}cd",
			"mail\u{9b}.example.net",
			"mail\u{2028}x.example.net",
			"-\u{202e}x.example.org",
		] {
			for field in ["hostname", "domain"] {
				let message = validate_dns_name(field, value)
					.expect_err("refused")
					.to_string();
				assert!(
					message
						.chars()
						.all(|c| !(c.is_control()
							|| crate::util::validation::is_invisible_format(c))),
					"{field} {value:?} came back raw in {message:?}"
				);
			}
		}
	}
