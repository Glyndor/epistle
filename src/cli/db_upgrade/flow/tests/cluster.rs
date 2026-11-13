//! Which directories of the old cluster a verified move may remove.

use crate::cli::db_upgrade::flow::leftovers::{Cluster, cluster};

#[test]
fn the_reported_directory_goes_with_its_emptied_major_directory() {
	assert_eq!(
		cluster(
			"/var/lib/postgresql/18/docker",
			"/var/lib/postgresql/19/docker"
		),
		Ok(Cluster {
			tree: "/var/lib/postgresql/18/docker".to_string(),
			parent: Some("/var/lib/postgresql/18".to_string()),
		})
	);
}

/// The layout before PostgreSQL 18 kept the cluster straight under the
/// volume, so there is no major directory around it to remove.
#[test]
fn a_cluster_straight_under_the_volume_goes_alone() {
	assert_eq!(
		cluster("/var/lib/postgresql/data", "/var/lib/postgresql/18/docker"),
		Ok(Cluster {
			tree: "/var/lib/postgresql/data".to_string(),
			parent: None,
		})
	);
}

#[test]
fn a_parent_the_new_cluster_lives_in_stays() {
	assert_eq!(
		cluster("/var/lib/postgresql/x/old", "/var/lib/postgresql/x/new"),
		Ok(Cluster {
			tree: "/var/lib/postgresql/x/old".to_string(),
			parent: None,
		})
	);
}

#[test]
fn overlapping_clusters_are_refused() {
	for (old, new) in [
		(
			"/var/lib/postgresql/18/docker",
			"/var/lib/postgresql/18/docker",
		),
		("/var/lib/postgresql/18", "/var/lib/postgresql/18/docker"),
		("/var/lib/postgresql/18/docker", "/var/lib/postgresql/18"),
	] {
		let error = cluster(old, new).expect_err(old);
		assert!(error.contains("overlaps"), "{old} {new}: {error}");
	}
}

/// A neighbour that only shares a prefix of the name does not overlap.
#[test]
fn a_shared_name_prefix_is_not_an_overlap() {
	assert!(cluster("/var/lib/postgresql/18", "/var/lib/postgresql/180/docker").is_ok());
}

#[test]
fn a_directory_outside_the_volume_or_not_plain_is_refused() {
	for old in [
		"/var/lib/postgresql",
		"/var/lib/postgresql/",
		"/var/lib/postgresqlx/18",
		"var/lib/postgresql/18",
		"/srv/postgres/18",
		"/var/lib/postgresql/../../etc",
		"/var/lib/postgresql/18/./docker",
		"/var/lib/postgresql//18",
		"/var/lib/postgresql/18/docker/",
		"/var/lib/postgresql/-rf",
		"/var/lib/postgresql/a b",
		"/var/lib/postgresql/18\n/etc",
	] {
		let error = cluster(old, "/var/lib/postgresql/19/docker").expect_err(old);
		assert!(
			error.contains("not a directory inside the epistle-pgdata volume"),
			"{old:?}: {error}"
		);
	}
}
