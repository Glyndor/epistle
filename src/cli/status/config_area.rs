//! The `config` check: the configuration file loads, as `config-check` does.

use super::Ctx;
use super::report::AreaReport;

/// Report whether the configuration loaded.
pub(super) async fn check(ctx: &Ctx) -> AreaReport {
	match &ctx.config {
		Ok(_) => AreaReport::ok(format!("{} loads", ctx.path.display())),
		Err(error) => AreaReport::fail(error.clone()),
	}
}
