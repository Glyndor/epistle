use super::*;

fn table() -> Table {
	// One bucket forces collisions and exercises linked-record removal.
	Table::new(tempfile::tempfile().unwrap(), 0).unwrap()
}

#[test]
fn collisions_keep_distinct_keys_and_each_identical_copy() {
	let mut table = table();
	let a = Key::MessageId(b"<a>".to_vec(), 1);
	let b = Key::MessageId(b"<b>".to_vec(), 1);
	let c = Key::Digest([7; 32], 1);
	for key in [&a, &b, &a, &c] {
		table.add(key).unwrap();
	}
	assert!(
		!table
			.claim(&Key::MessageId(b"<missing>".to_vec(), 1))
			.unwrap()
	);
	assert!(
		table.claim(&b).unwrap(),
		"remove the middle of a collision chain"
	);
	assert!(table.claim(&a).unwrap());
	assert!(table.claim(&c).unwrap(), "remove the head");
	assert!(table.claim(&a).unwrap(), "remove the tail");
	assert!(!table.claim(&a).unwrap());
	assert!(!table.claim(&b).unwrap());
	assert!(!table.claim(&Key::MessageId(b"<a>".to_vec(), 2)).unwrap());
}

#[test]
fn io_failures_are_errors_rather_than_missing_identities() {
	let mut table = table();
	let key = Key::Digest([9; 32], 1);
	table.add(&key).unwrap();
	table.file.set_len(8).unwrap();
	assert_eq!(
		table.claim(&key).unwrap_err().kind(),
		io::ErrorKind::UnexpectedEof
	);
	assert!(Table::new(tempfile::tempfile().unwrap(), u64::MAX).is_err());
}
