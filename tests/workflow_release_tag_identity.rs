//! A dispatch must release the tag it was asked for, and images-only must be
//! able to run.
//!
//! Two shapes were wrong in `release.yml`.
//!
//! `verify` reads `TAG` from the dispatch input but checked out the ref that
//! launched the workflow. On `workflow_dispatch` that is the dispatch commit,
//! so the version check, the changelog check and `cargo audit` all read a
//! tree nobody is going to build, while `build-deb`, `build` and `image-build`
//! checked out the tag. A rerun of an old tag whose version still matches on
//! the dispatch commit therefore audits the fixed lockfile and packages the
//! vulnerable one. The tag is now resolved once, in `verify`, and every build
//! checks out the commit that came out of it.
//!
//! The "no published release yet" gate ran for every dispatch, including
//! `images-only`, whose whole purpose is to finish the images of a release
//! that is already published. `verify` failed, and `image-build` needs `verify`
//! to succeed, so the option could never run. The gate now belongs to the full
//! release path, and images-only checks the opposite.

use std::fs;
use std::path::Path;

/// One step of a job: its active lines, without indentation or comments.
struct Step {
	lines: Vec<String>,
}

impl Step {
	/// The value of a key line, with the `key: ` prefix removed.
	fn key(&self, key: &str) -> Option<&str> {
		// A step's own first key carries the list dash (`- uses: ...`).
		let dashed = format!("- {key}: ");
		let plain = format!("{key}: ");
		self.lines.iter().find_map(|line| {
			line.strip_prefix(&dashed)
				.or_else(|| line.strip_prefix(&plain))
		})
	}

	fn uses(&self) -> Option<&str> {
		self.key("uses")
	}

	fn guard(&self) -> Option<&str> {
		self.key("if")
	}

	fn name(&self) -> &str {
		self.lines
			.first()
			.and_then(|line| line.strip_prefix("- name: "))
			.unwrap_or_else(|| self.uses().unwrap_or(""))
	}
}

fn workflow() -> String {
	let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
	fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The body of every job, keyed by job id.
fn jobs(text: &str) -> Vec<(String, String)> {
	let lines: Vec<&str> = text.lines().collect();
	let mut found: Vec<(String, String)> = Vec::new();
	for (index, line) in lines.iter().enumerate() {
		let trimmed = line.trim();
		if line.len() - trimmed.len() != 2 {
			continue;
		}
		let Some(id) = trimmed.strip_suffix(':') else {
			continue;
		};
		if id.is_empty() || !id.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
			continue;
		}
		let mut body = Vec::new();
		for next in &lines[index + 1..] {
			let indent = next.len() - next.trim_start().len();
			if next.trim().is_empty() {
				continue;
			}
			if indent <= 2 {
				break;
			}
			if next.trim_start().starts_with('#') {
				continue;
			}
			body.push(next.trim_start());
		}
		found.push((id.to_owned(), body.join("\n")));
	}
	found
}

/// The active lines of each step of a job body.
fn steps(job: &str) -> Vec<Step> {
	let mut found: Vec<Vec<String>> = Vec::new();
	for line in job.lines() {
		if line.starts_with("- ") {
			found.push(vec![line.to_owned()]);
			continue;
		}
		if let Some(current) = found.last_mut() {
			current.push(line.to_owned());
		}
	}
	found
		.into_iter()
		.map(|lines| Step {
			lines: lines
				.into_iter()
				.filter(|line| !line.starts_with('#'))
				.collect(),
		})
		.collect()
}

fn job<'a>(jobs: &'a [(String, String)], id: &str) -> &'a str {
	jobs.iter()
		.find(|(name, _)| name == id)
		.map(|(_, body)| body.as_str())
		.unwrap_or_else(|| panic!("release.yml has no `{id}` job"))
}

#[test]
fn verify_resolves_the_tag_once_and_every_build_checks_out_that_commit() {
	let text = workflow();
	let jobs = jobs(&text);

	let verify_steps = steps(job(&jobs, "verify"));
	let checkouts: Vec<&Step> = verify_steps
		.iter()
		.filter(|step| {
			step.uses()
				.is_some_and(|uses| uses.starts_with("actions/checkout"))
		})
		.collect();
	assert_eq!(
		checkouts.len(),
		1,
		"the verify job checks out once, with no `ref:` of its own it audited whatever the \
		 dispatch or push selected. Its steps were: {:?}",
		verify_steps.iter().map(Step::name).collect::<Vec<_>>()
	);
	let reference = checkouts[0].key("ref").unwrap_or_default();
	assert!(
		reference.contains("env.TAG"),
		"verify must check out the tag it was asked to release, not the ref that launched the \
		 workflow: on a dispatch those are two different trees. Its checkout reads ref: \
		 {reference:?}"
	);

	// The merge-base check also names `${TAG}^{commit}`; what makes a step
	// the resolver is that it turns that into a value other jobs read.
	let resolvers: Vec<&Step> = verify_steps
		.iter()
		.filter(|step| {
			let resolves = step
				.lines
				.iter()
				.any(|line| line.contains("${TAG}^{commit}"));
			let publishes = step.lines.iter().any(|line| line.contains("GITHUB_OUTPUT"));
			resolves && publishes
		})
		.collect();
	assert_eq!(
		resolvers.len(),
		1,
		"exactly one step resolves the tag to a commit, and every build job takes its output. \
		 The steps were: {:?}",
		verify_steps.iter().map(Step::name).collect::<Vec<_>>()
	);
	let resolver = resolvers[0];
	let id = resolver.key("id").unwrap_or_default();
	assert!(
		!id.is_empty(),
		"the resolving step needs an `id:` for its output to be reachable"
	);
	assert!(
		resolver.lines.iter().any(|line| line.contains("commit=")),
		"the resolving step must write the commit to $GITHUB_OUTPUT: {:?}",
		resolver.lines
	);
	let outputs = job(&jobs, "verify");
	assert!(
		outputs.contains(&format!("commit: ${{{{ steps.{id}.outputs.commit }}}}")),
		"the verify job must expose the resolved commit as an output, which is what the build \
		 jobs check out. The job body was:\n{outputs}"
	);

	for id in ["build-deb", "build", "image-build", "image-manifest"] {
		let build_steps = steps(job(&jobs, id));
		let checkout = build_steps
			.iter()
			.find(|step| {
				step.uses()
					.is_some_and(|uses| uses.starts_with("actions/checkout"))
			})
			.unwrap_or_else(|| panic!("the {id} job checks out nothing"));
		assert_eq!(
			checkout.key("ref"),
			Some("${{ needs.verify.outputs.commit }}"),
			"the {id} job must build the commit verify resolved. Checking out the tag name \
			 again leaves a window where the tag moved between the two checkouts, and \
			 checking out the dispatch expression would build the dispatch commit."
		);
		// The tag name still reaches these jobs as an env var, because the
		// artifact and image tags are named after it. What must not come back
		// is a checkout that resolves it into a ref of its own.
		assert!(
			build_steps.iter().all(|step| {
				step.key("ref")
					.is_none_or(|value| !value.contains("github.event_name"))
			}),
			"the {id} job must not resolve the release ref into a checkout of its own; the ref is \
			 resolved once, in verify."
		);
	}
}

#[test]
fn the_release_tag_is_validated_before_it_reaches_a_ref() {
	let steps = steps(job(&jobs(&workflow()), "verify"));
	let validation = steps
		.iter()
		.find(|step| step.lines.iter().any(|line| line.contains("case \"$TAG\"")))
		.unwrap_or_else(|| {
			panic!(
				"the dispatch tag is free text and every later step reads it as a ref, so verify \
				 must check its shape first. Its steps were: {:?}",
				steps.iter().map(Step::name).collect::<Vec<_>>()
			)
		});
	assert!(
		validation.lines.iter().any(|line| line.contains("v[0-9]*")),
		"the validation must state the shape a release tag has, or it accepts anything: {:?}",
		validation.lines
	);
}

#[test]
fn images_only_needs_a_published_release_instead_of_forbidding_one() {
	let steps = steps(job(&jobs(&workflow()), "verify"));
	let refusal = steps
		.iter()
		.find(|step| step.name().contains("no published release yet"))
		.unwrap_or_else(|| panic!("the gate against re-publishing an existing release is gone"));
	assert_eq!(
		refusal.guard(),
		Some("${{ !inputs.images-only }}"),
		"this gate refuses to touch a tag that already has a release, which is exactly what an \
		 images-only dispatch is for. It has to be skipped for images-only, or verify fails and \
		 image-build, which needs verify to succeed, never starts."
	);
	let required = steps
		.iter()
		.filter(|step| step.guard() == Some("${{ inputs.images-only }}"))
		.find(|step| {
			step.lines
				.iter()
				.any(|line| line.contains("gh release view"))
		})
		.unwrap_or_else(|| {
			panic!(
				"an images-only dispatch must check that the release it completes is published, \
				 otherwise it pushes images for a version no release carries. The steps were: {:?}",
				steps.iter().map(Step::name).collect::<Vec<_>>()
			)
		});
	assert!(
		required
			.lines
			.iter()
			.any(|line| line.contains("no release is published for")),
		"the images-only check must say what is wrong when the release is missing: {:?}",
		required.lines
	);
}
