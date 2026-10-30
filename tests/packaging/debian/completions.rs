use super::read;
use std::process::Command;

/// The commands `make` would run for `target` in debian/rules, with every
/// variable expanded, without running any of them.
fn recipe(target: &str) -> String {
	let output = Command::new("make")
		.args([
			"-n",
			"-s",
			"-f",
			"debian/rules",
			"DEB_HOST_ARCH=amd64",
			target,
		])
		.current_dir(env!("CARGO_MANIFEST_DIR"))
		.output()
		.expect("make must be available to read debian/rules");
	assert!(
		output.status.success(),
		"make -n {target} failed: {}",
		String::from_utf8_lossy(&output.stderr)
	);
	String::from_utf8(output.stdout).unwrap()
}

#[test]
fn package_build_generates_man_pages_and_completions_from_the_built_binary() {
	let build = recipe("override_dh_auto_build");
	let binary = "target/x86_64-unknown-linux-musl/release/epistle";
	for command in [
		format!("{binary} manpages target/generated/man"),
		format!("{binary} completions bash > target/generated/completions/epistle"),
		format!("{binary} completions zsh > target/generated/completions/_epistle"),
		format!("{binary} completions fish > target/generated/completions/epistle.fish"),
	] {
		assert!(
			build.lines().any(|line| line.trim() == command),
			"debian/rules must run `{command}` after the cargo build"
		);
	}
	let cargo = build
		.lines()
		.position(|line| line.starts_with("cargo build"));
	let manpages = build.lines().position(|line| line.contains(" manpages "));
	assert!(
		cargo.is_some() && cargo < manpages,
		"the pages must come from the binary this build produced, so after cargo build"
	);
}

#[test]
fn package_installs_completions_where_each_shell_looks_and_lists_the_man_pages() {
	let install = recipe("override_dh_auto_install");
	for (source, destination) in [
		(
			"target/generated/completions/epistle",
			"debian/epistle/usr/share/bash-completion/completions/epistle",
		),
		(
			"target/generated/completions/_epistle",
			"debian/epistle/usr/share/zsh/vendor-completions/_epistle",
		),
		(
			"target/generated/completions/epistle.fish",
			"debian/epistle/usr/share/fish/vendor_completions.d/epistle.fish",
		),
	] {
		let joined = install.replace("\\\n", " ");
		assert!(
			joined.lines().any(|line| {
				let words: Vec<_> = line.split_whitespace().collect();
				words.starts_with(&["install", "-D", "-m", "0644"])
					&& words.contains(&source)
					&& words.last() == Some(&destination)
			}),
			"debian/rules must install {source} as {destination}"
		);
	}
	let manpages = read("debian/epistle.manpages");
	assert_eq!(
		manpages.lines().collect::<Vec<_>>(),
		["target/generated/man/*.1"],
		"dh_installman must pick up every generated page and nothing else"
	);
}
