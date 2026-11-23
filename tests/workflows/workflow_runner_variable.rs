//! Every Linux job in `.github/workflows/*.yml` reads its runner from the
//! `CI_RUNNER` repository variable, except the jobs that must stay on GitHub's
//! runners. One setting then moves the repository to a self-hosted runner and
//! deleting it moves the repository back.
//!
//! The accepted form is exactly
//! `${{ fromJSON(vars.CI_RUNNER || '"ubuntu-latest"') }}`. A literal
//! `ubuntu-latest` or `ubuntu-24.04` silently opts one job out of the switch,
//! and a privileged job on the variable hands its secrets to a pool that also
//! runs untrusted pull-request code.
//!
//! "Privileged" is decided from the job's content, never its name: a
//! `permissions:` (the job's own, else the workflow's) with a write scope, or
//! any `secrets.X` other than the default `GITHUB_TOKEN`, or a `secrets:`
//! passthrough. Those jobs must be listed in `PRIVILEGED` with the reason and
//! must not use the variable.
//!
//! Not checked: `runs-on: ${{ matrix.* }}`. `e2e.yml` and `reusable-rust-ci.yml`
//! (`extra-test-os`) name the OS they test on.

use std::fs;
use std::path::Path;
use yaml_rust2::{Yaml, YamlLoader};

const EXPRESSION: &str = "${{ fromJSON(vars.CI_RUNNER || '\"ubuntu-latest\"') }}";

/// Jobs that stay on GitHub's runners: `(workflow, job, why)`.
const PRIVILEGED: &[(&str, &str, &str)] = &[
	(
		"release.yml",
		"build-deb",
		"builds the .deb with id-token and attestations: write",
	),
	(
		"release.yml",
		"build",
		"builds the release binaries with id-token and attestations: write",
	),
	(
		"release.yml",
		"sign",
		"uses the GLYNDOR_RELEASE_ED25519_KEY secret",
	),
	(
		"release.yml",
		"publish",
		"creates the GitHub release with contents: write",
	),
	(
		"release.yml",
		"image-build",
		"pushes to GHCR with packages: write",
	),
	(
		"release.yml",
		"image-manifest",
		"publishes and attests the image with packages, id-token and attestations: write",
	),
	(
		"ci.yml",
		"cancel-others",
		"cancels the other runs of the commit with actions: write",
	),
	(
		"codeql.yml",
		"analyze",
		"uploads the results with security-events: write",
	),
	(
		"rust-audit.yml",
		"report",
		"opens and comments on issues with issues: write",
	),
	(
		"rust-audit.yml",
		"close",
		"closes issues with issues: write",
	),
];

/// Jobs with no secret or write scope that stay fixed anyway: `(workflow, job, why)`.
const FIXED: &[(&str, &str, &str)] = &[(
	"release.yml",
	"verify",
	"read-only gate of the release run that signs and publishes; the run stays on one kind of runner",
)];

const WRITE_SCOPES: &[&str] = &[
	"contents",
	"packages",
	"id-token",
	"attestations",
	"pull-requests",
	"issues",
	"actions",
	"security-events",
	"statuses",
	"checks",
	"deployments",
	"pages",
	"discussions",
];

fn key<'a>(y: &'a Yaml, k: &str) -> &'a Yaml {
	&y[k]
}

/// True when this `permissions:` value grants any write scope.
fn grants_write(perms: &Yaml) -> bool {
	match perms {
		Yaml::String(s) => s == "write-all",
		Yaml::Hash(h) => h.iter().any(|(k, v)| {
			k.as_str().is_some_and(|k| WRITE_SCOPES.contains(&k)) && v.as_str() == Some("write")
		}),
		_ => false,
	}
}

/// True when any string or key under `y` names a secret other than the default token.
fn uses_secret(y: &Yaml) -> bool {
	let named = |s: &str| {
		s.match_indices("secrets.").any(|(i, _)| {
			let rest = &s[i + 8..];
			let end = rest
				.find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
				.unwrap_or(rest.len());
			&rest[..end] != "GITHUB_TOKEN"
		})
	};
	match y {
		Yaml::String(s) => named(s),
		Yaml::Array(a) => a.iter().any(uses_secret),
		Yaml::Hash(h) => h.iter().any(|(k, v)| {
			k.as_str() == Some("secrets") && !v.is_badvalue()
				|| named(k.as_str().unwrap_or(""))
				|| uses_secret(v)
		}),
		_ => false,
	}
}

/// A job's privilege from its content: its permissions (job, else workflow) or its secrets.
fn privileged(workflow: &Yaml, job: &Yaml) -> bool {
	let perms = if job["permissions"].is_badvalue() {
		key(workflow, "permissions")
	} else {
		key(job, "permissions")
	};
	grants_write(perms) || uses_secret(job)
}

#[test]
fn linux_jobs_read_the_runner_variable() {
	let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
	let mut problems = Vec::new();
	let mut with_variable = 0usize;
	let mut seen_privileged: Vec<(String, String)> = Vec::new();
	for entry in fs::read_dir(&dir).expect("read .github/workflows") {
		let path = entry.expect("dir entry").path();
		if path.extension().is_none_or(|x| x != "yml") {
			continue;
		}
		let file = path.file_name().unwrap().to_string_lossy().into_owned();
		let text = fs::read_to_string(&path).expect("read workflow");
		let workflow = YamlLoader::load_from_str(&text)
			.unwrap_or_else(|e| panic!("{file}: {e}"))
			.remove(0);
		let Yaml::Hash(jobs) = &workflow["jobs"] else {
			panic!("{file}: no jobs");
		};
		for (name, job) in jobs {
			let name = name.as_str().expect("job id");
			let secret_or_write = privileged(&workflow, job);
			if job["uses"].as_str().is_some() {
				if secret_or_write {
					problems.push(format!(
						"{file}: job {name} calls a reusable workflow with secrets or write permissions; its runner cannot be fixed from here"
					));
				}
				continue;
			}
			let runs_on = job["runs-on"].as_str().unwrap_or("");
			let on_variable = runs_on == EXPRESSION;
			if on_variable {
				with_variable += 1;
			}
			let listed = PRIVILEGED.iter().any(|(f, j, _)| *f == file && *j == name);
			if secret_or_write {
				seen_privileged.push((file.clone(), name.to_string()));
				if !listed {
					problems.push(format!(
						"{file}: job {name} has secrets or write permissions; add it to PRIVILEGED and pin its runner"
					));
				}
				if runs_on.contains("CI_RUNNER") {
					problems.push(format!(
						"{file}: privileged job {name} reads CI_RUNNER; use a GitHub-hosted runner"
					));
				}
			} else if runs_on.starts_with("ubuntu-")
				&& !FIXED.iter().any(|(f, j, _)| *f == file && *j == name)
			{
				problems.push(format!(
					"{file}: job {name} runs-on {runs_on}; use {EXPRESSION}"
				));
			}
		}
	}
	for (f, j, _) in PRIVILEGED {
		if !seen_privileged.iter().any(|(sf, sj)| sf == f && sj == j) {
			problems.push(format!(
				"PRIVILEGED lists {f}:{j}, which has no secrets or write permissions any more"
			));
		}
	}
	assert!(problems.is_empty(), "{}", problems.join("\n"));
	assert!(
		with_variable >= 30,
		"expected at least 30 jobs on the CI_RUNNER expression, found {with_variable}"
	);
}
