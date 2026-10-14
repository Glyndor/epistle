use super::*;

/// The root above `node` by walking parents: the obvious answer the
/// link-cut tree has to agree with.
fn walked_root(forest: &Forest, mut node: u32) -> u32 {
	while let Some(parent) = forest.parent(node) {
		node = parent;
	}
	node
}

#[test]
fn a_link_that_would_loop_is_refused() {
	let mut forest = Forest::new();
	let (a, b, c) = (forest.add(), forest.add(), forest.add());
	assert!(!forest.link(a, a), "a node cannot be its own parent");
	assert!(forest.link(b, a));
	assert!(forest.link(c, b));
	assert!(!forest.link(a, c), "a under its grandchild loops");
	assert_eq!(forest.parent(a), None);
	forest.cut(c);
	assert_eq!(forest.parent(c), None);
	assert!(forest.link(a, c), "after the cut c is no longer below a");
	assert_eq!(walked_root(&forest, b), c);
}

/// Random links and cuts over a small forest, checked step by step
/// against walking the parents. A fixed linear congruential sequence keeps
/// the run reproducible.
#[test]
fn agrees_with_walking_the_parents() {
	let mut forest = Forest::new();
	let nodes: Vec<u32> = (0..64).map(|_| forest.add()).collect();
	let mut state: u64 = 0x2545_f491_4f6c_dd1d;
	let mut next = |bound: usize| {
		state = state
			.wrapping_mul(6_364_136_223_846_793_005)
			.wrapping_add(1_442_695_040_888_963_407);
		((state >> 33) as usize) % bound
	};
	for _ in 0..20_000 {
		let child = nodes[next(nodes.len())];
		let parent = nodes[next(nodes.len())];
		if next(3) == 0 {
			forest.cut(child);
			assert_eq!(forest.parent(child), None);
			continue;
		}
		forest.cut(child);
		let loops = walked_root(&forest, parent) == child;
		assert_eq!(forest.link(child, parent), !loops);
		let expected = if loops { None } else { Some(parent) };
		assert_eq!(forest.parent(child), expected);
		let probe = nodes[next(nodes.len())];
		let up = probe + 1;
		assert_eq!(forest.splay.find_root(up) - 1, walked_root(&forest, probe));
	}
}
