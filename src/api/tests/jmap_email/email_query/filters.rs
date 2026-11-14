use super::*;

#[tokio::test]
async fn q01_in_mailbox_excludes_other_folders() {
	let f = Fixture::new();
	f.filtered(json!({"inMailbox": "INBOX"}), &[&f.middle, &f.old])
		.await;
	f.filtered(json!({"inMailbox": "Archive"}), &[&f.new]).await;
	f.filtered(json!({"inMailbox": "missing"}), &[]).await;
}

#[tokio::test]
async fn q02_text_searches_every_header_and_body_case_insensitively() {
	let f = Fixture::new();
	for term in ["sEnDeRnEeDlE", "tOnEeDlE", "SUBJECTNEEDLE"] {
		f.filtered(json!({"text": term}), &[&f.middle, &f.old])
			.await;
	}
	for term in ["COPYNEEDLE", "BlindNeedle", "bOdYnEeDlE"] {
		f.filtered(json!({"text": term}), &[&f.old]).await;
	}
	f.filtered(json!({"text": "absent"}), &[]).await;
}

#[tokio::test]
async fn q03_from_does_not_match_body_or_other_headers() {
	let f = Fixture::new();
	f.filtered(json!({"from": "SENDERNEEDLE"}), &[&f.old]).await;
	for term in ["ToNeedle", "SubjectNeedle", "BodyNeedle"] {
		f.filtered(json!({"from": term}), &[]).await;
	}
}

#[tokio::test]
async fn q04_to_does_not_match_body_or_other_headers() {
	let f = Fixture::new();
	f.filtered(json!({"to": "TONEEDLE"}), &[&f.old]).await;
	for term in ["SenderNeedle", "CopyNeedle", "BlindNeedle", "BodyNeedle"] {
		f.filtered(json!({"to": term}), &[]).await;
	}
}

#[tokio::test]
async fn q05_subject_does_not_match_body_or_other_headers() {
	let f = Fixture::new();
	f.filtered(json!({"subject": "SUBJECTNEEDLE"}), &[&f.old])
		.await;
	for term in ["SenderNeedle", "ToNeedle", "BodyNeedle"] {
		f.filtered(json!({"subject": term}), &[]).await;
	}
}

#[tokio::test]
async fn q06_before_excludes_the_exact_boundary_and_later_messages() {
	let f = Fixture::new();
	f.filtered(json!({"before": "2020-01-01T00:00:10Z"}), &[&f.old])
		.await;
	f.filtered(json!({"before": "2020-01-01T00:00:00Z"}), &[])
		.await;
}

#[tokio::test]
async fn q07_after_includes_the_exact_boundary_and_later_messages() {
	let f = Fixture::new();
	f.filtered(
		json!({"after": "2020-01-01T00:00:10Z"}),
		&[&f.new, &f.middle],
	)
	.await;
	f.filtered(json!({"after": "2020-01-01T00:00:21Z"}), &[])
		.await;
}

#[tokio::test]
async fn q08_has_keyword_matches_system_and_custom_keywords_without_prefixes() {
	let f = Fixture::new();
	for keyword in ["$seen", "project"] {
		f.filtered(json!({"hasKeyword": keyword}), &[&f.old]).await;
	}
	for keyword in ["$see", "pro", "project-extra"] {
		f.filtered(json!({"hasKeyword": keyword}), &[]).await;
	}
}

#[tokio::test]
async fn q09_not_keyword_excludes_only_the_exact_keyword() {
	let f = Fixture::new();
	for keyword in ["$seen", "project"] {
		f.filtered(json!({"notKeyword": keyword}), &[&f.new, &f.middle])
			.await;
	}
	f.filtered(json!({"notKeyword": "pro"}), &[&f.new, &f.middle, &f.old])
		.await;
}

#[tokio::test]
async fn q10_condition_properties_are_conjoined() {
	let f = Fixture::new();
	f.filtered(
		json!({"inMailbox": "INBOX", "hasKeyword": "$seen", "subject": "alpha"}),
		&[&f.old],
	)
	.await;
	f.filtered(json!({"inMailbox": "Archive", "hasKeyword": "$seen"}), &[])
		.await;
}

#[tokio::test]
async fn q11_empty_filters_search_all_account_mailboxes() {
	let f = Fixture::new();
	for filter in [
		Value::Null,
		json!({}),
		json!({"operator": "AND", "conditions": []}),
	] {
		f.filtered(filter, &[&f.new, &f.middle, &f.old]).await;
	}
}

#[tokio::test]
async fn q12_and_requires_every_child() {
	let f = Fixture::new();
	f.filtered(
		json!({"operator": "AND", "conditions": [
			{"inMailbox": "INBOX"}, {"hasKeyword": "$seen"}
		]}),
		&[&f.old],
	)
	.await;
	f.filtered(
		json!({"operator": "AND", "conditions": [
			{"inMailbox": "Archive"}, {"hasKeyword": "$seen"}
		]}),
		&[],
	)
	.await;
}

#[tokio::test]
async fn q13_or_requires_any_child() {
	let f = Fixture::new();
	f.filtered(
		json!({"operator": "OR", "conditions": [
			{"inMailbox": "Archive"}, {"hasKeyword": "$seen"}
		]}),
		&[&f.new, &f.old],
	)
	.await;
	f.filtered(json!({"operator": "OR", "conditions": []}), &[])
		.await;
}

#[tokio::test]
async fn q14_not_rejects_each_child_including_nested_conditions() {
	let f = Fixture::new();
	f.filtered(
		json!({"operator": "NOT", "conditions": [{"hasKeyword": "$seen"}]}),
		&[&f.new, &f.middle],
	)
	.await;
	f.filtered(
		json!({"operator": "NOT", "conditions": [
			{"hasKeyword": "$seen"},
			{"operator": "OR", "conditions": [{"inMailbox": "Archive"}, {"subject": "absent"}]}
		]}),
		&[&f.middle],
	)
	.await;
}

#[tokio::test]
async fn q15_nested_operators_preserve_their_boolean_meaning() {
	let f = Fixture::new();
	f.filtered(
		json!({"operator": "AND", "conditions": [
			{"operator": "OR", "conditions": [{"inMailbox": "INBOX"}, {"subject": "Other"}]},
			{"operator": "NOT", "conditions": [{"hasKeyword": "$seen"}]}
		]}),
		&[&f.new, &f.middle],
	)
	.await;
}

#[tokio::test]
async fn q23_all_text_terms_must_appear() {
	let f = Fixture::new();
	f.filtered(json!({"text": "omega alpha"}), &[&f.old]).await;
	f.filtered(json!({"text": "alpha absent"}), &[]).await;
}

#[tokio::test]
async fn q24_quoted_phrase_requires_contiguous_words_without_quotes() {
	let f = Fixture::new();
	f.filtered(json!({"subject": "\"alpha omega\""}), &[&f.old])
		.await;
	f.filtered(json!({"subject": "\"omega alpha\""}), &[]).await;
	f.filtered(json!({"subject": "\"SubjectNeedle omega\""}), &[])
		.await;
}

#[tokio::test]
async fn q25_apostrophe_in_a_word_is_literal() {
	let f = Fixture::new();
	f.filtered(json!({"subject": "O'Reilly"}), &[&f.old]).await;
}

#[tokio::test]
async fn q26_encoded_subject_and_from_are_decoded_before_matching() {
	let f = Fixture::new();
	let id = append(f.dir.path(), "INBOX", EPOCH + 30, &[],
		b"From: =?UTF-8?Q?Jos=C3=A9_P=C3=A9rez?= <jose@example.org>\r\nSubject: =?UTF-8?B?wqFIb2xhIQ==?=\r\n\r\nbody\r\n");
	for filter in [
		json!({"from": "JOSÉ PÉREZ"}),
		json!({"subject": "¡HOLA!"}),
		json!({"text": "¡hola!"}),
	] {
		f.filtered(filter, &[&id]).await;
	}
	f.filtered(json!({"subject": "wqFIb2xhIQ"}), &[]).await;
}
