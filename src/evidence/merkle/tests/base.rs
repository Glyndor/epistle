use super::*;

fn leaves(n: u64) -> Vec<[u8; 32]> {
	(0..n)
		.map(|i| leaf_hash(&sha256(&i.to_be_bytes())))
		.collect()
}

/// RFC 6962 MTH, written as the recursion the RFC states.
fn reference_root(leaves: &[[u8; 32]]) -> [u8; 32] {
	match leaves.len() {
		0 => empty_root(),
		1 => leaves[0],
		n => {
			let k = largest_power_of_two_below(n as u64) as usize;
			node_hash(&reference_root(&leaves[..k]), &reference_root(&leaves[k..]))
		}
	}
}

/// RFC 6962 PATH, as the recursion states it (bottom-up order).
fn reference_path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
	let n = leaves.len();
	if n <= 1 {
		return Vec::new();
	}
	let k = largest_power_of_two_below(n as u64) as usize;
	if m < k {
		let mut path = reference_path(m, &leaves[..k]);
		path.push(reference_root(&leaves[k..]));
		path
	} else {
		let mut path = reference_path(m - k, &leaves[k..]);
		path.push(reference_root(&leaves[..k]));
		path
	}
}

fn build(leaves: &[[u8; 32]], targets: &[u64]) -> ([u8; 32], BTreeMap<u64, Vec<[u8; 32]>>) {
	let mut builder = TreeBuilder::for_proofs(leaves.len() as u64, targets);
	for leaf in leaves {
		builder.push(*leaf);
	}
	builder.finish(targets)
}

#[test]
fn the_streaming_root_is_the_rfc_6962_root() {
	for n in 0..70u64 {
		let leaves = leaves(n);
		let (root, _) = build(&leaves, &[]);
		assert_eq!(root, reference_root(&leaves), "root of {n} leaves");
	}
}

#[test]
fn every_proof_is_the_rfc_6962_path_and_verifies() {
	for n in 1..40u64 {
		let leaves = leaves(n);
		let targets: Vec<u64> = (0..n).collect();
		let (root, proofs) = build(&leaves, &targets);
		for m in 0..n {
			let proof = &proofs[&m];
			assert_eq!(
				proof,
				&reference_path(m as usize, &leaves),
				"path of {m} in {n}"
			);
			assert!(
				verify_inclusion(m, n, &leaves[m as usize], proof, &root),
				"proof of {m} in {n} does not verify"
			);
		}
	}
}

#[test]
fn a_proof_does_not_verify_for_another_leaf_index_or_root() {
	let leaves = leaves(13);
	let (root, proofs) = build(&leaves, &[5]);
	let proof = &proofs[&5];
	assert!(verify_inclusion(5, 13, &leaves[5], proof, &root));
	assert!(!verify_inclusion(5, 13, &leaves[6], proof, &root));
	assert!(!verify_inclusion(4, 13, &leaves[5], proof, &root));
	// The size is not checked by the proof alone (5 sits in the same
	// subtrees of 13 and 14 leaves): the checkpoint signs the size with the
	// root, and a verifier takes both from there.
	assert!(!verify_inclusion(5, 13, &leaves[5], &proof[1..], &root));
	assert!(!verify_inclusion(13, 13, &leaves[5], proof, &root));
	let other = reference_root(&leaves[..12]);
	assert!(!verify_inclusion(5, 13, &leaves[5], proof, &other));
}

#[test]
fn leaves_and_nodes_are_hashed_apart() {
	let record = sha256(b"line");
	assert_ne!(
		leaf_hash(&record),
		sha256(&[&[1u8][..], &record[..]].concat())
	);
	assert_eq!(
		leaf_hash(&record),
		sha256(&[&[0u8][..], &record[..]].concat())
	);
}

#[test]
fn a_large_day_is_built_in_logarithmic_memory() {
	let mut builder = TreeBuilder::for_proofs(1_000_003, &[0, 500_000, 1_000_002]);
	let mut deepest = 0;
	for i in 0..1_000_003u64 {
		builder.push(leaf_hash(&sha256(&i.to_le_bytes())));
		deepest = deepest.max(builder.stack.len());
	}
	assert!(deepest <= 21, "stack grew to {deepest}");
	assert!(
		builder.found.len() <= 3 * 21,
		"kept {} hashes",
		builder.found.len()
	);
	let (root, proofs) = builder.finish(&[0, 500_000, 1_000_002]);
	for (index, proof) in proofs {
		let leaf = leaf_hash(&sha256(&index.to_le_bytes()));
		assert!(verify_inclusion(index, 1_000_003, &leaf, &proof, &root));
	}
}
