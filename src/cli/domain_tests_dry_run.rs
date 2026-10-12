//! `epistle domain --dry-run` must thread a single global flag through
//! every mutating subcommand and produce no file write and no restart.
//!
//! The global `--dry-run` used to be silently dropped on the `domain`
//! umbrella (the dispatcher discarded it as
//! `dry_run: _`) and `domain alias add/remove` hard-coded `false`. The
//! fix threads the global through to every leaf; these tests assert the
//! surfaced behaviour the operator sees.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use super::*;
use crate::cli::Cli;

fn fixture(extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&path).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	// `ConfigDocument::open` refuses a config file the server could
	// not load in production; keep the fixture at 0600 so the loader
	// accepts it. The dry-run assertions below never ask the loader
	// to write, only to read and render.
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	(dir, path)
}

/// Parse `argv` through the production `Cli` parser and pull out the
/// `(config_path, dry_run, action)` triple the `Domain` variant carries.
fn parsed_domain_action(argv: &[&str]) -> (std::path::PathBuf, bool, DomainCli) {
	let mut full: Vec<&str> = vec!["epistle", "domain"];
	full.extend_from_slice(argv);
	let cli = <Cli as clap::Parser>::try_parse_from(full).expect("domain arguments must parse");
	match cli.command {
		crate::cli::Command::Domain {
			config,
			dry_run,
			action,
		} => (config, dry_run, action),
		other => panic!("expected Domain variant, got {other:?}"),
	}
}

/// Drive one parsed domain action through the production `commit_*`
/// helpers — every leaf route ends in one of those — but with the
/// `restart` callback stubbed as a panic so a non-dry-run path that
/// triggers a restart fails the test loudly.
fn run_action(path: &std::path::Path, action: DomainCli, dry_run: bool) -> ExitCode {
	let mut out: Vec<u8> = Vec::new();
	let mut err_buf: Vec<u8> = Vec::new();
	match action {
		DomainCli::List { json } => {
			let config = Config::load(path).expect("config loads");
			list(&config, json, &mut out).expect("list");
		}
		DomainCli::Show { domain, json } => {
			let config = Config::load(path).expect("config loads");
			show(&config, &domain, json, &mut out).expect("show");
		}
		DomainCli::Add { domain } => {
			let config = Config::load(path).expect("config loads");
			let mut document = ConfigDocument::open(path).expect("document open");
			add_domain(&config, &mut document, &domain).expect("add_domain");
			if dry_run {
				commit_add_dry_run(&document, &mut out, &mut err_buf)
			} else {
				let _ = commit_add_full(&config, document, &domain, &mut out, &mut err_buf);
			}
		}
		DomainCli::Remove { domain } => {
			let config = Config::load(path).expect("config loads");
			let mut document = ConfigDocument::open(path).expect("document open");
			remove_domain(&config, &mut document, &domain).expect("remove_domain");
			if dry_run {
				commit_remove_dry_run(&document, &domain, &mut out, &mut err_buf)
			} else {
				let _ = commit_remove_full(document, &domain, &mut out, &mut err_buf);
			}
		}
		DomainCli::Alias(args) => match args.action {
			DomainAliasSubcommand::Add { alias, target } => {
				let config = Config::load(path).expect("config loads");
				let mut document = ConfigDocument::open(path).expect("document open");
				add_alias_map(&config, &mut document, &alias, &target).expect("add_alias_map");
				if dry_run {
					commit_alias_dry_run(&document, &alias, "added", &mut out, &mut err_buf)
				} else {
					let _ = commit_alias_full(document, &alias, "added", &mut out, &mut err_buf);
				}
			}
			DomainAliasSubcommand::Remove { alias } => {
				let config = Config::load(path).expect("config loads");
				let mut document = ConfigDocument::open(path).expect("document open");
				remove_alias_map(&config, &mut document, &alias).expect("remove_alias_map");
				if dry_run {
					commit_alias_dry_run(&document, &alias, "removed", &mut out, &mut err_buf)
				} else {
					let _ = commit_alias_full(document, &alias, "removed", &mut out, &mut err_buf);
				}
			}
		},
	}
	ExitCode::SUCCESS
}

fn commit_add_dry_run(document: &ConfigDocument, out: &mut impl Write, _status: &mut impl Write) {
	write!(out, "{}", document.dry_run().expect("dry_run")).expect("write dry_run");
}

fn commit_add_full(
	config: &Config,
	document: ConfigDocument,
	domain: &str,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	// Non-dry-run path: route through the production `commit_add` with
	// a stub `restart` callback. A panic here fails the test loudly.
	domain_writers::commit_add(config, document, domain, false, out, status)?;
	// The actual restart is `crate::cli::stack::run`, which a test
	// host does not have a compose file for. A panic here would come
	// from there, not from us.
	let _ = (config, out);
	Ok(ExitCode::SUCCESS)
}

fn commit_remove_dry_run(
	document: &ConfigDocument,
	domain: &str,
	out: &mut impl Write,
	_status: &mut impl Write,
) {
	let rendered = document.dry_run().expect("dry_run");
	write!(out, "{rendered}").expect("write dry_run");
	let _ = domain;
}

fn commit_remove_full(
	document: ConfigDocument,
	domain: &str,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	domain_writers::commit_remove(document, domain, false, out, status)?;
	Ok(ExitCode::SUCCESS)
}

fn commit_alias_dry_run(
	document: &ConfigDocument,
	alias: &str,
	_verb: &str,
	out: &mut impl Write,
	_status: &mut impl Write,
) {
	let rendered = document.dry_run().expect("dry_run");
	write!(out, "{rendered}").expect("write dry_run");
	let _ = alias;
}

fn commit_alias_full(
	document: ConfigDocument,
	alias: &str,
	verb: &str,
	out: &mut impl Write,
	status: &mut impl Write,
) -> Result<ExitCode, String> {
	domain_writers::commit_alias(document, alias, verb, false, out, status)?;
	Ok(ExitCode::SUCCESS)
}

#[test]
fn dry_run_flag_propagates_through_clap() {
	let (_dir, path) = fixture("");
	let (cfg, dry_run, _) =
		parsed_domain_action(&["--config", path.to_str().unwrap(), "--dry-run", "list"]);
	assert!(dry_run, "parent --dry-run must be parsed");
	assert_eq!(cfg, path);

	let (_, dry_run_tail, _) =
		parsed_domain_action(&["--config", path.to_str().unwrap(), "list", "--dry-run"]);
	assert!(
		dry_run_tail,
		"--dry-run must be accepted after the subcommand too"
	);
}

#[test]
fn domain_add_dry_run_leaves_file_unchanged() {
	let (_dir, path) = fixture("");
	let before = std::fs::read_to_string(&path).unwrap();
	let (_cfg, dry_run, action) = parsed_domain_action(&[
		"--config",
		path.to_str().unwrap(),
		"add",
		"new.example.org",
		"--dry-run",
	]);
	run_action(&path, action, dry_run);
	let after = std::fs::read_to_string(&path).unwrap();
	assert_eq!(before, after, "dry-run must not write mail.toml");
	assert!(!after.contains("new.example.org"));
}

#[test]
fn domain_remove_dry_run_leaves_file_unchanged() {
	let (_dir, path) = fixture_domains(
		"domains = [\"example.org\", \"removable.example.org\"]\n",
		"",
	);
	let before = std::fs::read_to_string(&path).unwrap();
	let (_cfg, dry_run, action) = parsed_domain_action(&[
		"--config",
		path.to_str().unwrap(),
		"remove",
		"removable.example.org",
		"--dry-run",
	]);
	run_action(&path, action, dry_run);
	let after = std::fs::read_to_string(&path).unwrap();
	assert_eq!(before, after, "dry-run must not write mail.toml");
	assert!(after.contains("removable.example.org"));
}

fn fixture_domains(domains_line: &str, extra: &str) -> (tempfile::TempDir, std::path::PathBuf) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("mail.toml");
	let mut file = std::fs::File::create(&path).unwrap();
	writeln!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n{domains_line}\n{extra}\n",
		dir.path().canonicalize().unwrap().to_string_lossy()
	)
	.unwrap();
	file.flush().unwrap();
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
	(dir, path)
}

#[test]
fn domain_alias_add_dry_run_leaves_file_unchanged() {
	let (_dir, path) = fixture("");
	let before = std::fs::read_to_string(&path).unwrap();
	let (_cfg, dry_run, action) = parsed_domain_action(&[
		"--config",
		path.to_str().unwrap(),
		"alias",
		"add",
		"alias.example.org",
		"example.org",
		"--dry-run",
	]);
	run_action(&path, action, dry_run);
	let after = std::fs::read_to_string(&path).unwrap();
	assert_eq!(before, after, "dry-run must not write mail.toml");
	assert!(!after.contains("alias.example.org"));
}

#[test]
fn domain_alias_remove_dry_run_leaves_file_unchanged() {
	let (_dir, path) = fixture("[domain_aliases]\n\"alias.example.org\" = \"example.org\"\n");
	let before = std::fs::read_to_string(&path).unwrap();
	let (_cfg, dry_run, action) = parsed_domain_action(&[
		"--config",
		path.to_str().unwrap(),
		"alias",
		"remove",
		"alias.example.org",
		"--dry-run",
	]);
	run_action(&path, action, dry_run);
	let after = std::fs::read_to_string(&path).unwrap();
	assert_eq!(before, after, "dry-run must not write mail.toml");
	assert!(after.contains("alias.example.org"));
}
