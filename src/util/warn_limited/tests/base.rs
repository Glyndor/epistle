use super::*;

#[test]
fn a_key_is_let_through_once_an_hour() {
	let mut seen = HashMap::new();
	let start = Instant::now();
	assert!(allow_at(&mut seen, "a", start));
	assert!(!allow_at(&mut seen, "a", start + Duration::from_secs(10)));
	assert!(!allow_at(&mut seen, "a", start + Duration::from_secs(3599)));
	assert!(allow_at(&mut seen, "a", start + Duration::from_secs(3601)));
	assert!(
		allow_at(&mut seen, "b", start),
		"another key has its own hour"
	);
}

#[test]
fn the_table_does_not_grow_without_bound() {
	let mut seen = HashMap::new();
	let start = Instant::now();
	for n in 0..(MAX_KEYS * 3) {
		assert!(allow_at(&mut seen, &format!("k{n}"), start));
		assert!(seen.len() <= MAX_KEYS);
	}
}
