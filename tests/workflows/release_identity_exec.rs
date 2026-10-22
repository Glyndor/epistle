use super::{Step, job, jobs, steps, workflow};
use std::{fs, path::Path, process::Command};

fn git(path: &Path, args: &[&str]) -> String {
	let out = Command::new("git")
		.current_dir(path)
		.args(args)
		.output()
		.unwrap();
	assert!(out.status.success(), "git {args:?}: {out:?}");
	String::from_utf8(out.stdout).unwrap().trim().to_owned()
}

fn shell(step: &Step) -> String {
	let start = step.lines.iter().position(|s| s == "run: |").unwrap();
	step.lines[start + 1..].join("\n")
}

#[test]
fn resolver_uses_the_tag_with_a_divergent_branch_and_rejects_a_branch_alone() {
	// The container that builds the package carries no git, and this test
	// builds a repository to run the resolver against. The jobs that run the
	// workspace tests have git, so it runs there; say so when it cannot run.
	if Command::new("git").arg("--version").output().is_err() {
		eprintln!("SKIPPED: git is not installed, the release resolver is not exercised");
		return;
	}
	let tree = tempfile::tempdir().unwrap();
	let repo = tree.path().join("repo.git");
	fs::create_dir(&repo).unwrap();
	git(&repo, &["init", "-b", "main"]);
	git(&repo, &["config", "user.email", "release@example.test"]);
	git(&repo, &["config", "user.name", "Release test"]);
	fs::write(repo.join("audited"), "tag tree").unwrap();
	git(&repo, &["add", "."]);
	git(&repo, &["commit", "-m", "tag tree"]);
	let tag_sha = git(&repo, &["rev-parse", "HEAD"]);
	git(&repo, &["tag", "-a", "v1.2.3", "-m", "release"]);
	fs::write(repo.join("audited"), "branch tree").unwrap();
	git(&repo, &["commit", "-am", "branch tree"]);
	git(&repo, &["branch", "v1.2.3"]);
	git(&repo, &["branch", "v1.2.4"]);

	let verify = steps(job(&jobs(&workflow()), "verify"));
	let resolve = verify
		.iter()
		.find(|s| s.key("id") == Some("resolve"))
		.unwrap();
	let script = shell(resolve);
	assert!(
		!script.contains("${{"),
		"inputs must arrive through the environment"
	);
	for (tag, present) in [("v1.2.4", false), ("v1.2.3", true)] {
		let output = tree.path().join(format!("output-{tag}"));
		let out = Command::new("bash")
			.args(["-c", &script])
			.current_dir(&repo)
			.env("TAG", tag)
			.env("GITHUB_OUTPUT", &output)
			.env("RUNNER_TEMP", tree.path())
			.env("GITHUB_SERVER_URL", tree.path())
			.env("GITHUB_REPOSITORY", "repo")
			.output()
			.unwrap();
		assert_eq!(out.status.success(), present, "{tag}: {out:?}");
		if present {
			let emitted = fs::read_to_string(&output).unwrap();
			assert_eq!(
				emitted.trim(),
				format!("commit={tag_sha}"),
				"resolve the tag, never HEAD"
			);
			git(&repo, &["checkout", "--detach", &tag_sha]);
			assert_eq!(
				fs::read_to_string(repo.join("audited")).unwrap(),
				"tag tree"
			);
			let guard = verify
				.iter()
				.find(|s| s.name() == "Check the verified checkout")
				.unwrap();
			let run_guard = || {
				Command::new("bash")
					.args(["-c", &shell(guard)])
					.current_dir(&repo)
					.env("RELEASE_COMMIT", &tag_sha)
					.output()
					.unwrap()
			};
			assert!(run_guard().status.success(), "the resolved tree must pass");
			git(&repo, &["checkout", "main"]);
			assert!(
				!run_guard().status.success(),
				"a different audited tree must fail"
			);
		}
	}
}
