use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
	epistle::cli::Cli::parse().run()
}
