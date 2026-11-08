//! The hand-written `Debug` for [`Config`].
//!
//! The rendering redacts the SRS secret (`***` in place of its value): the
//! struct is printed and logged, and the secret must not travel with it.

use super::Config;

impl std::fmt::Debug for Config {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Config")
			.field("hostname", &self.hostname)
			.field("public_ipv4", &self.public_ipv4)
			.field("public_ipv6", &self.public_ipv6)
			.field("data_dir", &self.data_dir)
			.field("domains", &self.domains)
			.field("domain_aliases", &self.domain_aliases)
			.field("disabled_domains", &self.disabled_domains)
			.field("dnsbl_zones", &self.dnsbl_zones)
			.field("dnsbl_domain_zones", &self.dnsbl_domain_zones)
			.field("dnsbl_url_zones", &self.dnsbl_url_zones)
			.field(
				"first_time_sender_delay_secs",
				&self.first_time_sender_delay_secs,
			)
			.field("greylist_delay_secs", &self.greylist_delay_secs)
			.field("srs_secret", &self.srs_secret.as_ref().map(|_| "***"))
			.field("srs_domain", &self.srs_domain)
			.field("quota_bytes", &self.quota_bytes)
			.field("queue_give_up_secs", &self.queue_give_up_secs)
			.field("queue_retry_base_secs", &self.queue_retry_base_secs)
			.field("queue_retry_cap_secs", &self.queue_retry_cap_secs)
			.field("queue_delay_warning_secs", &self.queue_delay_warning_secs)
			.field("rules", &self.rules)
			.field("scanner_hook_url", &self.scanner_hook_url)
			.field("antispam", &self.antispam)
			.field("attachments", &self.attachments)
			.field("antispam_llm", &self.antispam_llm)
			.field("subjectpass", &self.subjectpass)
			.field("listeners", &self.listeners)
			.field("accounts", &self.accounts)
			.field("tls", &self.tls)
			.field("mta_sts", &self.mta_sts)
			.field("dkim", &self.dkim)
			.field("api", &self.api)
			.field("database", &self.database)
			.field("log_format", &self.log_format)
			.field("acme", &self.acme)
			.field("dns", &self.dns)
			.field("domain_quotas", &self.domain_quotas)
			.field("default_feedback_id", &self.default_feedback_id)
			.field("default_list_unsubscribe", &self.default_list_unsubscribe)
			.field("bulk_recipients", &self.bulk_recipients)
			.field("default_list_id", &self.default_list_id)
			.field("system_auto_submitted", &self.system_auto_submitted)
			.field("x_epistle_header", &self.x_epistle_header)
			.field("organization_header", &self.organization_header)
			.field("domain_organization", &self.domain_organization)
			.field(
				"submission_rate_limit_per_min",
				&self.submission_rate_limit_per_min,
			)
			.field("new_recipients_per_day", &self.new_recipients_per_day)
			.field("domain_submission_limits", &self.domain_submission_limits)
			.field(
				"inbound_rate_limit_per_ip_per_min",
				&self.inbound_rate_limit_per_ip_per_min,
			)
			.field(
				"inbound_rate_limit_per_sender_per_min",
				&self.inbound_rate_limit_per_sender_per_min,
			)
			.field(
				"max_connections_per_listener",
				&self.max_connections_per_listener,
			)
			.field("max_connections_per_ip", &self.max_connections_per_ip)
			.field("max_recipients", &self.max_recipients)
			.field("message_memory_budget", &self.message_memory_budget)
			.field("min_data_rate", &self.min_data_rate)
			.field("data_rate_grace", &self.data_rate_grace)
			.field("junk_command_limit", &self.junk_command_limit)
			.field("max_session_time", &self.max_session_time)
			.field("preauth_timeout", &self.preauth_timeout)
			.field(
				"max_mailbox_connections_per_ip",
				&self.max_mailbox_connections_per_ip,
			)
			.field(
				"max_connections_per_account",
				&self.max_connections_per_account,
			)
			.field(
				"max_connections_per_account_per_ip",
				&self.max_connections_per_account_per_ip,
			)
			.field(
				"max_connections_per_account_total",
				&self.max_connections_per_account_total,
			)
			.field("max_http_connections", &self.max_http_connections)
			.field(
				"max_http_connections_per_ip",
				&self.max_http_connections_per_ip,
			)
			.field("transport", &self.transport)
			.field("otel", &self.otel)
			.field("alias", &self.alias)
			.field("arc", &self.arc)
			.field("oauth", &self.oauth)
			.field("ldap", &self.ldap)
			.field("webhook", &self.webhook)
			.field("tenants", &self.tenants)
			.field("privileges", &self.privileges)
			.field("storage", &self.storage)
			.field("queue", &self.queue)
			.field("auth", &self.auth)
			.field("alerts", &self.alerts)
			.field("hold_outbound", &self.hold_outbound)
			.field("clock_external", &self.clock_external)
			.finish()
	}
}
