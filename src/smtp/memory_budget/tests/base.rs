
use super::*;

#[test]
fn unlimited_admits_every_reservation() {
	let budget = MemoryBudget::unlimited();
	assert!(budget.try_reserve(1).is_ok());
	assert!(budget.try_reserve(usize::MAX as u64).is_ok());
}

#[test]
fn reservation_fails_when_over_cap() {
	let budget = MemoryBudget::with_cap(100);
	assert!(budget.try_reserve(60).is_ok());
	assert_eq!(budget.try_reserve(50), Err(50));
	assert_eq!(budget.used(), 60);
}

#[test]
fn release_frees_the_bytes_for_the_next_reservation() {
	let budget = MemoryBudget::with_cap(100);
	assert!(budget.try_reserve(60).is_ok());
	budget.release(60);
	assert!(budget.try_reserve(80).is_ok());
}

#[test]
fn a_reservation_hands_its_octets_back_when_dropped() {
	let budget = Arc::new(MemoryBudget::with_cap(100));
	let mut held = Reservation::none();
	assert!(held.try_grow(&budget, None, 30).is_ok());
	let mut chunk = Reservation::none();
	assert!(chunk.try_grow(&budget, None, 50).is_ok());
	held.absorb(chunk);
	assert_eq!((held.bytes(), budget.used()), (80, 80));
	assert_eq!(held.try_grow(&budget, None, 30), Err(30));
	assert_eq!(
		held.bytes(),
		80,
		"a refused claim leaves the held octets alone"
	);
	drop(held);
	assert_eq!(budget.used(), 0);
}

#[test]
fn release_saturates_on_over_release() {
	let budget = MemoryBudget::with_cap(100);
	assert!(budget.try_reserve(40).is_ok());
	budget.release(200);
	assert_eq!(budget.used(), 0);
}
