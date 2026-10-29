	use super::*;

	fn rule(
		domain: Option<&str>,
		header: Option<(&str, &str)>,
		junk: bool,
		mailbox: Option<&str>,
	) -> Rule {
		Rule {
			sender_domain: domain.map(String::from),
			header: header.map(|(n, _)| n.to_string()),
			header_contains: header.map(|(_, v)| v.to_string()),
			junk,
			mailbox: mailbox.map(String::from),
		}
	}

	const MSG: &[u8] =
		b"From: a@news.example\r\nList-Id: <discuss.news.example>\r\nSubject: hi\r\n\r\nbody\r\n";

	#[test]
	fn matches_sender_domain_case_insensitively() {
		let rules = vec![rule(Some("News.Example"), None, false, Some("Lists"))];
		let hit = evaluate(&rules, MSG, Some("news.example")).expect("match");
		assert_eq!(hit.mailbox.as_deref(), Some("Lists"));
	}

	#[test]
	fn matches_header_substring() {
		let rules = vec![rule(None, Some(("List-Id", "discuss")), true, None)];
		let hit = evaluate(&rules, MSG, None).expect("match");
		assert!(hit.junk);
	}

	#[test]
	fn requires_all_conditions() {
		// Right header but wrong domain: no match.
		let rules = vec![rule(
			Some("other.example"),
			Some(("List-Id", "discuss")),
			false,
			Some("X"),
		)];
		assert!(evaluate(&rules, MSG, Some("news.example")).is_none());
	}

	#[test]
	fn first_match_wins() {
		let rules = vec![
			rule(Some("news.example"), None, false, Some("First")),
			rule(Some("news.example"), None, false, Some("Second")),
		];
		assert_eq!(
			evaluate(&rules, MSG, Some("news.example"))
				.unwrap()
				.mailbox
				.as_deref(),
			Some("First")
		);
	}

	#[test]
	fn missing_header_does_not_match() {
		let rules = vec![rule(None, Some(("X-Absent", "z")), true, None)];
		assert!(evaluate(&rules, MSG, None).is_none());
	}

	#[test]
	fn unconditional_rule_never_matches() {
		let rules = vec![rule(None, None, true, Some("All"))];
		assert!(evaluate(&rules, MSG, Some("news.example")).is_none());
	}
