//! An acknowledgement covers the day as the operator saw it, and nothing the
//! day is rewritten to afterwards.

use crate::evidence::ack::{Operator, acknowledge_at};
use crate::evidence::audit::tests::base::{DAY, Fixture};
use crate::evidence::chain::Chain;
use crate::evidence::day::Day;
use crate::evidence::record::{Entry, Record, sha256, to_hex};
use crate::evidence::test_support::{accepted, at};

fn operator() -> Operator {
	Operator::named("uid=0 sudo_user=admin host=mail")
}

/// Accept the first break, as of `hour` on the last day.
fn accept(fixture: &Fixture, hour: u64) {
	let first = fixture.verify().first_break.expect("a break");
	acknowledge_at(
		fixture.root(),
		&fixture.key,
		&first,
		"restored from backup",
		&operator(),
		at(DAY + 3, hour),
	)
	.expect("acknowledge");
}

fn edit(fixture: &Fixture, offset: i64, from: &str, to: &str) {
	let path = Chain::open(fixture.root())
		.expect("chain")
		.day_file(Day(DAY + offset));
	let text = std::fs::read_to_string(&path).expect("read");
	assert!(text.contains(from), "nothing to edit: {from}");
	std::fs::write(&path, text.replacen(from, to, 1)).expect("write");
}

#[test]
fn a_break_in_a_sealed_day_shows_twice_the_chain_and_then_the_seal() {
	let fixture = Fixture::new();
	edit(&fixture, 1, "Notice 1", "Notice X");
	// The chain break, then the seal that no longer matches the records.
	accept(&fixture, 13);
	accept(&fixture, 14);
	let report = fixture.verify();
	assert_eq!(report.first_break, None);
	assert_eq!(report.acknowledged.len(), 2);
}

#[test]
fn the_seal_of_an_acknowledged_day_is_still_checked() {
	let fixture = Fixture::new();
	edit(&fixture, 1, "Notice 1", "Notice X");
	accept(&fixture, 13);
	let next = fixture
		.verify()
		.first_break
		.expect("the seal is judged next");
	assert!(
		next.to_string().contains("Merkle root does not match"),
		"the seal was not looked at: {next}"
	);
}

#[test]
fn the_link_to_the_next_day_is_still_checked_after_an_acknowledgement() {
	let fixture = Fixture::new();
	edit(&fixture, 0, "Notice 0", "Notice X");
	accept(&fixture, 13);
	accept(&fixture, 14);
	assert_eq!(fixture.verify().first_break, None);
	// The day after is replaced by another that chains onto nothing.
	let chain = Chain::open(fixture.root()).expect("chain");
	let path = chain.day_file(Day(DAY + 1));
	let text = std::fs::read_to_string(&path).expect("read");
	let first = text.lines().next().expect("a line");
	let mut record = Record::parse_canonical(first.as_bytes()).expect("a record");
	record.prev = to_hex(&[0u8; 32]);
	let rewritten = String::from_utf8(record.to_line().expect("line")).expect("utf8");
	std::fs::write(&path, text.replacen(first, &rewritten, 1)).expect("write");
	let report = fixture.verify();
	let at_break = report.first_break.expect("the link to the next day");
	assert_eq!(at_break.day, Day(DAY + 1));
	assert!(
		at_break
			.to_string()
			.contains("does not follow the day before"),
		"{at_break}"
	);
}

/// Change line `number` of the last day with `change`, and chain every line
/// after it onto the new one again, as someone who holds the files can.
fn rewrite_and_rechain(fixture: &Fixture, number: usize, change: impl Fn(&mut Entry)) {
	let chain = Chain::open(fixture.root()).expect("chain");
	let path = chain.day_file(Day(DAY + 3));
	let text = std::fs::read_to_string(&path).expect("read");
	let mut out: Vec<u8> = Vec::new();
	let mut previous: Option<[u8; 32]> = None;
	for (index, line) in text.lines().enumerate() {
		let mut record = Record::parse_canonical(line.as_bytes()).expect("a record");
		if index + 1 == number {
			change(&mut record.entry);
		}
		if index + 1 > number {
			record.prev = to_hex(&previous.expect("a line before"));
		}
		let bytes = record.to_line().expect("line");
		previous = Some(sha256(&bytes));
		out.extend_from_slice(&bytes);
		out.push(b'\n');
	}
	std::fs::write(&path, out).expect("write");
	crate::evidence::head::write(
		fixture.root(),
		at(DAY + 3, 13),
		&previous.expect("a last line"),
	)
	.expect("head");
}

#[test]
fn lines_rewritten_after_an_acknowledgement_in_the_same_day_bring_the_break_back() {
	let fixture = Fixture::new();
	let chain = Chain::open(fixture.root()).expect("chain");
	for (n, hour) in [(7, 1), (8, 2), (9, 3)] {
		chain
			.append_at(at(DAY + 3, hour), accepted(n))
			.expect("record");
	}
	edit(&fixture, 3, "Notice 7", "Notice X");
	accept(&fixture, 13);
	let report = fixture.verify();
	assert_eq!(report.first_break, None, "{:?}", report.first_break);
	// The third record is rewritten and the lines after it chained again:
	// the text of the break is the same, the day is not.
	rewrite_and_rechain(&fixture, 3, |entry| {
		if let Entry::Accepted(accepted) = entry {
			accepted.subject = Some("rewritten".into());
		}
	});
	assert!(
		fixture.verify().first_break.is_some(),
		"a rewrite after the acknowledgement was covered by it"
	);
}
