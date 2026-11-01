//! Every retry delegates to the canonical answer validator.

use super::super::super::answers::{DnsAnswers, Mode};
use super::*;

#[test]
fn canonical_failures_remain_attached_to_the_question_that_can_fix_them() {
	let base: Answers = toml::from_str(&Answers::template()).unwrap();
	let mut cases = Vec::new();
	let mut add = |question: &str, expected: &str, change: fn(&mut Answers)| {
		let mut answers = base.clone();
		change(&mut answers);
		cases.push((question.to_string(), expected.to_string(), answers));
	};
	add("domains", "must not equal", |a| {
		a.domains = vec![a.hostname.clone()]
	});
	add("domains", "distinct", |a| {
		a.domains.push(a.domains[0].clone())
	});
	add("data_dir", "absolute", |a| a.data_dir = "relative".into());
	add("config_path", "usable file name", |a| {
		a.config_path = "/".into()
	});
	add("config_path", "must not overlap", |a| {
		a.config_path = a.data_dir.join("etc/mail.toml")
	});
	add("image", "pinned", |a| {
		a.image = Some("epistle:latest".into())
	});
	add("image", "whitespace-free", |a| {
		a.image = Some("bad image:dev".into())
	});
	add("DNS zone", "containing every", |a| {
		a.mode = Mode::Automatic;
		a.dns = Some(DnsAnswers {
			provider: "cloudflare".into(),
			zone: "elsewhere.org".into(),
			token_env: Some("EPISTLE_DNS_TOKEN".into()),
			..Default::default()
		});
	});
	for (question, expected, answers) in cases {
		let reason = check(&answers, &question).expect_err(&question);
		assert!(reason.contains(&expected), "{question}: {reason}");
	}
}
