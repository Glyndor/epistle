//! Which operator-named paths a root command stages for the service account.
//!
//! Every argument that names a file or directory on a command that
//! re-executes as the service account is listed here: either in [`STAGED`],
//! with what the command does with the path, or in [`NOT_STAGED`], with why
//! the account must use the path where it is. A test walks the whole parser
//! and fails on a path argument found in neither table.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use clap::CommandFactory;

/// The largest file staged for a reader: Mox's configuration parser caps a
/// file at 16 MiB, the largest cap among the readers listed here, so a
/// bigger file is not one the command would read whole anyway.
pub(crate) const FILE_LIMIT: u64 = 16 * 1024 * 1024;

/// A Mox configuration directory: two configuration files of at most 16 MiB
/// each and the DKIM keys beside them (64 KiB each at most).
pub(crate) const CONFIG_DIR_LIMIT: u64 = 64 * 1024 * 1024;

/// A message file to inspect: what the server accepts by default, the
/// largest message `epistle attachments check` reads from root without a
/// larger `max_message_size` in the configuration.
pub(crate) const MESSAGE_LIMIT: u64 = crate::smtp::session::MAX_MESSAGE_SIZE as u64;

/// A Maildir to import. The copy sits on the data disk the running server
/// writes mail to until the import ends, and the import then writes the same
/// mail again, so a staged Maildir costs twice its size in free space. Past
/// 4 GiB that is a cost the operator should choose, by making the Maildir
/// readable by the account, not one a root run takes on by itself.
pub(crate) const MAILDIR_LIMIT: u64 = 4 * 1024 * 1024 * 1024;

/// What the delegated command does with a path, and so how it is staged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
	/// A file the command reads, copied when it is at most `limit` bytes.
	/// `secret` repeats the command's warning about a file other users can
	/// read, which the private copy would otherwise hide.
	ReadFile { limit: u64, secret: bool },
	/// A directory the command reads, copied with everything in it.
	ReadDir { limit: u64 },
	/// A directory the command reads, or a file in one; either way the
	/// whole directory is copied, because the command reads its neighbours.
	ReadDirOfFile { limit: u64 },
	/// A new file the command writes. It holds secrets, so it lands at the
	/// requested path mode 0600 and owned by root.
	WriteFile,
	/// A directory tree the command writes; it must be missing or empty.
	WriteDir,
}

/// One staged argument: the subcommand path, the argument id (the field
/// name clap derives it from) and what is done with it.
pub(crate) struct Staged {
	pub(crate) command: &'static [&'static str],
	pub(crate) arg: &'static str,
	pub(crate) kind: Kind,
}

/// Arguments staged before a root run re-executes as the service account.
pub(crate) const STAGED: &[Staged] = &[
	Staged {
		command: &["migrate", "imap"],
		arg: "password_file",
		kind: Kind::ReadFile {
			limit: FILE_LIMIT,
			secret: true,
		},
	},
	Staged {
		command: &["migrate", "imap"],
		arg: "ca_file",
		kind: Kind::ReadFile {
			limit: FILE_LIMIT,
			secret: false,
		},
	},
	Staged {
		command: &["migrate", "mox"],
		arg: "from",
		kind: Kind::ReadDirOfFile {
			limit: CONFIG_DIR_LIMIT,
		},
	},
	Staged {
		command: &["migrate", "mox"],
		arg: "passwords_out",
		kind: Kind::WriteFile,
	},
	Staged {
		command: &["migrate", "stalwart"],
		arg: "from",
		kind: Kind::ReadFile {
			limit: FILE_LIMIT,
			secret: false,
		},
	},
	Staged {
		command: &["migrate", "stalwart"],
		arg: "passwords_out",
		kind: Kind::WriteFile,
	},
	Staged {
		command: &["import"],
		arg: "maildir",
		kind: Kind::ReadDir {
			limit: MAILDIR_LIMIT,
		},
	},
	Staged {
		command: &["export"],
		arg: "maildir",
		kind: Kind::WriteDir,
	},
	Staged {
		command: &["attachments", "check"],
		arg: "file",
		kind: Kind::ReadFile {
			limit: MESSAGE_LIMIT,
			secret: false,
		},
	},
	Staged {
		command: &["init"],
		arg: "answers",
		kind: Kind::ReadFile {
			limit: FILE_LIMIT,
			secret: false,
		},
	},
];

/// Path arguments of delegated commands that are deliberately not staged
/// (read by the coverage test, which is what keeps this list honest):
/// the subcommand path (`None` for every command), the argument id, and why
/// the account uses the path where it is.
#[cfg(test)]
pub(crate) const NOT_STAGED: &[(Option<&[&str]>, &str, &str)] = &[
	(
		None,
		"config",
		"the service's own configuration: the account reads it, and the \
		 editing commands rewrite it, in place",
	),
	(Some(&["dns", "provider", "set"]), "token_file", REFERENCE),
	(
		Some(&["dns", "provider", "set"]),
		"credentials_file",
		REFERENCE,
	),
	(
		Some(&["storage", "blobs", "set", "s3"]),
		"secret_file",
		REFERENCE,
	),
];

/// Why a credential file named for the configuration is not staged.
#[cfg(test)]
const REFERENCE: &str = "recorded in mail.toml for the server to read at run time, so the \
	account must be able to read it where it is";

/// One occurrence of a staged argument on the command line.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Found {
	/// Index of the token holding the value, in the arguments without the
	/// program name.
	pub(crate) token: usize,
	/// `--flag=` when the value shares its token with the flag.
	pub(crate) prefix: Option<OsString>,
	/// The path as the operator typed it.
	pub(crate) value: PathBuf,
	pub(crate) kind: Kind,
}

/// Every staged argument of `table` present in `args` (the command line
/// without the program name). A command line clap cannot make sense of
/// stages nothing; the delegated run reports it.
pub(crate) fn find(args: &[OsString], table: &[Staged]) -> Vec<Found> {
	let root = crate::cli::Cli::command();
	let argv = std::iter::once(OsString::from("epistle")).chain(args.iter().cloned());
	let Ok(matches) = root.clone().ignore_errors(true).try_get_matches_from(argv) else {
		return Vec::new();
	};
	let mut path = Vec::new();
	let mut level = &matches;
	let mut command = &root;
	while let Some((name, sub)) = level.subcommand() {
		let Some(next) = command.find_subcommand(name) else {
			return Vec::new();
		};
		path.push(name);
		level = sub;
		command = next;
	}
	let mut found = Vec::new();
	for entry in table
		.iter()
		.filter(|entry| entry.command == path.as_slice())
	{
		let long = command
			.get_arguments()
			.find(|arg| arg.get_id() == entry.arg)
			.and_then(clap::Arg::get_long);
		if let Some(long) = long {
			scan(args, long, entry.kind, &mut found);
		} else {
			positional(args, &root, level, entry, &mut found);
		}
	}
	found.sort_by_key(|found| found.token);
	found
}

/// The most tokens of one value tried as the place of a positional; a line
/// repeating one text more often than this stages nothing and the run
/// reports the unreadable file.
const MAX_PROBES: usize = 64;

/// Push the values of the positional argument `entry` names, each at the
/// token clap read it from. Matching the text is not enough, the same text
/// can also be the value of another flag. So each token with that text is
/// replaced by a marker no operator typed and the line parsed again: the
/// token that changes the positional is the one.
fn positional(
	args: &[OsString],
	root: &clap::Command,
	matches: &clap::ArgMatches,
	entry: &Staged,
	found: &mut Vec<Found>,
) {
	let Ok(Some(values)) = matches.try_get_raw(entry.arg) else {
		return;
	};
	for value in values {
		let marker = OsString::from("\u{1}epistle-positional-probe");
		let probe = |index: usize| {
			let mut line = args.to_vec();
			line[index] = marker.clone();
			let argv = std::iter::once(OsString::from("epistle")).chain(line);
			let parsed = root.clone().ignore_errors(true).try_get_matches_from(argv);
			let mut level = parsed.as_ref().ok()?;
			while let Some((_, sub)) = level.subcommand() {
				level = sub;
			}
			let mut raw = level.try_get_raw(entry.arg).ok()??;
			Some(raw.any(|seen| seen == marker))
		};
		let token = (0..args.len())
			.filter(|index| args[*index] == value)
			.filter(|index| !found.iter().any(|f| f.token == *index))
			.take(MAX_PROBES)
			.find(|index| probe(*index) == Some(true));
		if let Some(token) = token {
			found.push(Found {
				token,
				prefix: None,
				value: PathBuf::from(value),
				kind: entry.kind,
			});
		}
	}
}

/// Push every `--long VALUE` and `--long=VALUE` before a `--` terminator.
fn scan(args: &[OsString], long: &str, kind: Kind, found: &mut Vec<Found>) {
	let flag = format!("--{long}");
	let joined = format!("--{long}=");
	let mut index = 0;
	while index < args.len() {
		let token = args[index].as_bytes();
		if token == b"--" {
			break;
		}
		if token == flag.as_bytes() {
			if let Some(value) = args.get(index + 1) {
				found.push(Found {
					token: index + 1,
					prefix: None,
					value: PathBuf::from(value),
					kind,
				});
			}
			index += 2;
			continue;
		}
		if let Some(value) = token.strip_prefix(joined.as_bytes()) {
			found.push(Found {
				token: index,
				prefix: Some(OsString::from(&joined)),
				value: PathBuf::from(OsStr::from_bytes(value)),
				kind,
			});
		}
		index += 1;
	}
}

#[cfg(test)]
#[path = "table_tests.rs"]
mod tests;
