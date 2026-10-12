//! IMAP QUOTA: GETQUOTAROOT, GETQUOTA (RFC 9208).

use super::mailbox;
use super::{Output, Session};

impl Session {
	pub(super) fn get_quota_root(&self, tag: &str, mailbox_name: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !mailbox::exists(&self.data_dir, &account, mailbox_name) {
			return Output::text(format!("{tag} NO no such mailbox\r\n"));
		}
		let quota = self.quota_line(&account);
		Output::text(format!(
			"* QUOTAROOT {} \"\"\r\n{quota}{tag} OK GETQUOTAROOT completed\r\n",
			self.mailbox_astring(mailbox_name)
		))
	}

	/// GETQUOTA: report the quota for a root (only the empty root exists).
	pub(super) fn get_quota(&self, tag: &str, root: &str) -> Output {
		let Some(account) = self.account().map(str::to_string) else {
			return Output::text(format!("{tag} NO not authenticated\r\n"));
		};
		if !root.is_empty() {
			return Output::text(format!("{tag} NO unknown quota root\r\n"));
		}
		let quota = self.quota_line(&account);
		Output::text(format!("{quota}{tag} OK GETQUOTA completed\r\n"))
	}

	/// The `* QUOTA` line for an account: STORAGE used/limit in 1024-octet
	/// units, or no resource at all when the account has no limit.
	fn quota_line(&self, account: &str) -> String {
		let Some(limit) = self.effective_quota() else {
			return "* QUOTA \"\" ()\r\n".to_string();
		};
		let used_kib = mailbox::account_usage(&self.data_dir, account, &self.crypto).div_ceil(1024);
		let limit_kib = limit.div_ceil(1024);
		format!("* QUOTA \"\" (STORAGE {used_kib} {limit_kib})\r\n")
	}
}
