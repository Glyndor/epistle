//! Pin the shape of `.github/dependabot.yml`.
//!
//! The mail base digest has to be the same in `Containerfile` and
//! `deploy/images/Dockerfile`, and `the_container_image_runs_on_the_same_base_as_the_stack`
//! compares them. A Dependabot group only gathers one directory unless it
//! sets `group-by: dependency-name`, and the old `images` group also filtered
//! on minor and patch, which a digest bump with an unchanged tag does not
//! have. Result: two pull requests (#1563 and #1565) that each failed that
//! test. This file keeps the fix from rolling back and checks that every
//! place the repository keeps a manifest is watched by an entry.
//!
//! The ecosystems are discovered from the tree, not listed here, and the
//! test fails when it finds fewer manifests than exist today: an empty
//! "all covered" pass is the false positive this kind of guard is born with.

use std::fs;
use std::path::{Path, PathBuf};

use yaml_rust2::{Yaml, YamlLoader};

// debian/ holds the build's cargo-home (vendored crates ship their own Dockerfiles).
const SKIP: &[&str] = &[
	"target",
	".git",
	".claude",
	"node_modules",
	"debian",
	"vendor",
];

fn root() -> PathBuf {
	PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn updates() -> Vec<Yaml> {
	let text = fs::read_to_string(root().join(".github/dependabot.yml")).expect("read");
	let mut documents = YamlLoader::load_from_str(&text).expect("valid YAML");
	assert_eq!(documents.len(), 1);
	let document = documents.remove(0);
	assert_eq!(document["version"].as_i64(), Some(2));
	document["updates"].as_vec().expect("updates").clone()
}

fn entry<'a>(updates: &'a [Yaml], ecosystem: &str) -> &'a Yaml {
	let mut found = updates
		.iter()
		.filter(|u| u["package-ecosystem"].as_str() == Some(ecosystem));
	let one = found
		.next()
		.unwrap_or_else(|| panic!("no {ecosystem} entry"));
	assert!(found.next().is_none(), "two {ecosystem} entries");
	one
}

/// The directories an entry watches, from `directory` or `directories`.
fn directories(entry: &Yaml) -> Vec<String> {
	if let Some(dir) = entry["directory"].as_str() {
		return vec![dir.to_string()];
	}
	entry["directories"]
		.as_vec()
		.expect("directory or directories")
		.iter()
		.map(|d| d.as_str().expect("a string").to_string())
		.collect()
}

/// Repository-relative directories ("/" for the root) holding a file that
/// `matches` accepts.
fn dirs_with(matches: &dyn Fn(&str) -> bool) -> Vec<String> {
	fn walk(dir: &Path, base: &Path, matches: &dyn Fn(&str) -> bool, out: &mut Vec<String>) {
		for item in fs::read_dir(dir).expect("read_dir") {
			let path = item.expect("entry").path();
			let name = path.file_name().unwrap().to_string_lossy().to_string();
			if path.is_dir() {
				if !SKIP.contains(&name.as_str()) {
					walk(&path, base, matches, out);
				}
			} else if matches(&name) {
				let rel = dir
					.strip_prefix(base)
					.unwrap()
					.to_string_lossy()
					.to_string();
				let rel = if rel.is_empty() {
					"/".to_string()
				} else {
					format!("/{rel}")
				};
				if !out.contains(&rel) {
					out.push(rel);
				}
			}
		}
	}
	let mut out = Vec::new();
	walk(&root(), &root(), matches, &mut out);
	out.sort();
	out
}

fn assert_covered(found: &[String], entry: &Yaml, what: &str, floor: usize) {
	assert!(
		found.len() >= floor,
		"found {found:?}: fewer {what} than exist"
	);
	let watched = directories(entry);
	for dir in found {
		assert!(
			watched.contains(dir),
			"{what} in {dir} is not watched: {watched:?}"
		);
	}
}

#[test]
fn every_manifest_in_the_tree_is_watched_by_its_ecosystem() {
	let updates = updates();
	let docker = dirs_with(&|n| n.starts_with("Dockerfile") || n.starts_with("Containerfile"));
	assert_covered(&docker, entry(&updates, "docker"), "container files", 3);
	let cargo = dirs_with(&|n| n == "Cargo.toml");
	assert_covered(&cargo, entry(&updates, "cargo"), "Cargo manifests", 2);
	let pip = dirs_with(&|n| n.contains("requirements") && n.ends_with(".txt"));
	assert_covered(&pip, entry(&updates, "pip"), "Python requirement files", 1);
	assert_eq!(directories(entry(&updates, "github-actions")), ["/"]);
	assert!(root().join(".github/workflows").is_dir());
}

#[test]
fn every_entry_lands_on_develop_weekly_with_labels_and_a_limit() {
	for update in updates() {
		let name = update["package-ecosystem"].as_str().expect("ecosystem");
		assert_eq!(update["target-branch"].as_str(), Some("develop"), "{name}");
		assert_eq!(
			update["schedule"]["interval"].as_str(),
			Some("weekly"),
			"{name}"
		);
		assert!(
			update["labels"].as_vec().is_some_and(|l| !l.is_empty()),
			"{name}"
		);
		assert!(
			update["open-pull-requests-limit"].as_i64().is_some(),
			"{name}"
		);
	}
}

/// A pull request carries one value of each single-valued dimension the
/// repository labels by: `type:`, `prio:` and `effort:`. Two types on one
/// bump, or none of the others, is what the pull request template forbids.
#[test]
fn every_entry_carries_one_type_one_priority_and_one_effort() {
	for update in updates() {
		let name = update["package-ecosystem"].as_str().expect("ecosystem");
		let labels: Vec<&str> = update["labels"]
			.as_vec()
			.expect("labels")
			.iter()
			.map(|label| label.as_str().expect("a label is text"))
			.collect();
		for dimension in ["type:", "prio:", "effort:"] {
			let count = labels.iter().filter(|l| l.starts_with(dimension)).count();
			assert_eq!(
				count, 1,
				"{name}: {dimension} appears {count} times in {labels:?}"
			);
		}
	}
}

/// `*` matches any run of characters, as in Dependabot's `patterns`.
fn glob(pattern: &str, text: &str) -> bool {
	match pattern.split_once('*') {
		None => pattern == text,
		Some((head, tail)) => {
			text.starts_with(head)
				&& (0..=text.len() - head.len()).any(|skip| {
					text.is_char_boundary(head.len() + skip)
						&& glob(tail, &text[head.len() + skip..])
				})
		}
	}
}

#[test]
fn the_mail_base_moves_in_one_pull_request_across_both_directories() {
	let base = "gcr.io/distroless/static-debian13";
	for file in ["Containerfile", "deploy/images/Dockerfile"] {
		let text = fs::read_to_string(root().join(file)).expect("read");
		assert!(text.contains(base), "{file} no longer uses {base}");
	}
	let updates = updates();
	let docker = entry(&updates, "docker");
	let dirs = directories(docker);
	for dir in ["/", "/deploy/images"] {
		assert!(
			dirs.contains(&dir.to_string()),
			"{dir} left the docker entry"
		);
	}
	let Yaml::Hash(groups) = &docker["groups"] else {
		panic!("the docker entry has no groups");
	};
	// Dependabot names the dependency with or without the registry.
	let first = groups
		.iter()
		.find(|(_, group)| {
			let patterns = group["patterns"].as_vec().cloned().unwrap_or_default();
			[base, "distroless/static-debian13"].iter().all(|name| {
				patterns
					.iter()
					.any(|p| p.as_str().is_some_and(|p| glob(p, name)))
			})
		})
		.map(|(name, group)| (name.as_str().unwrap_or_default().to_string(), group))
		.expect("a group matches the mail base");
	assert_eq!(first.0, "distroless-base", "another group matches first");
	assert_eq!(first.1["group-by"].as_str(), Some("dependency-name"));
	assert!(
		first.1["update-types"].is_badvalue(),
		"a digest bump has no semver level, so update-types would leave it out"
	);
}

#[test]
fn the_glob_matches_like_a_dependabot_pattern() {
	assert!(glob("*", "anything"));
	assert!(glob("*distroless*", "gcr.io/distroless/static-debian13"));
	assert!(glob("a*c", "abbc"));
	assert!(!glob("a*c", "abbd"));
	assert!(!glob("*distroless*", "library/rust"));
}
