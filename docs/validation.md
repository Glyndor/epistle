# Input validation rules

Every value an operator or a client types is checked by a rule. This page lists
each rule, the one place in the code that defines it, the entry points that call
that definition, and why the rule exists. The tests that keep the entry points in
agreement are listed at the end.

A rule is one of three kinds:

- **Safety**: it keeps a value from reaching a file name, a log line, a terminal
  or a protocol frame as something other than itself.
- **Standard**: an RFC fixes the shape or the limit.
- **Habit**: the project chose it so names stay short and plain. A habit can be
  relaxed without breaking a standard, and a change to one needs an owner
  decision.

## Rules

| Rule | Definition | Kind | Entry points |
|---|---|---|---|
| Local part of an address | `util::validation` (`ATEXT`, `is_atext`, `MAX_LOCAL_PART`), read by `smtp::address::Address::parse` | Standard (RFC 5321 section 4.1.2, RFC 6531), plus Safety for controls and U+2028/U+2029 | SMTP `MAIL FROM` and `RCPT TO`, IMAP and SMTP sign-in names, `epistle account`, `alias`, `domain`, `suppression`, `[[accounts]]`, `[[alias]]` and `forward` in `mail.toml`, SCIM `userName` and `emails`, API v1 `send`, JMAP `Email/set` addresses |
| Whole address | `util::validation::MAX_ADDRESS`, `Address::parse` | Standard (RFC 5321 section 4.5.3.1) | Same as above |
| Domain name | `domain::normalize` (A-label, lowercase, at least one dot, `MAX_DOMAIN`, `MAX_LABEL`, confusable check) | Standard (RFC 1035, RFC 5890) plus Safety (look-alike scripts) | `domains`, `domain_alias`, tenants and ACME names in `mail.toml`, `epistle domain` and `dns`, `epistle init` (answers file, guided and assistant), DNS provider zones, the address parser |
| Host name | The domain rule. `mail.toml` trims, lowercases and drops trailing dots first, and wants the ASCII form on disk | Standard | `hostname` in `mail.toml`, `epistle init` |
| Account name | `util::account_rule` (lowercase ASCII letters, digits, hyphen; not starting with a hyphen; 64 characters) | Safety (it is a directory name) | `epistle account add`, `[[accounts]]` in `mail.toml`, the management API `POST /accounts`, SCIM `POST /Users`, `epistle init` (derived from the address) |
| Account directory component | `util::path_component::AccountName` (plain path component, wider than the account rule because SQL and LDAP rows may name accounts `J_Smith`) | Safety | Every module that builds a path under `<data_dir>/accounts/`, including external directory rows |
| Credential label | `util::label_rule` (1 to 64 characters, no control or invisible formatting character, no space at either end) | Habit, plus Safety for what reaches a terminal or a log | `epistle app-password create` and `rename`, `epistle api-key create`. No HTTP route creates either |
| Masked address label | `directory_store::masked` (must hold a letter or a digit; it is slugified into the address) | Habit | `epistle masked`, API v1 masked addresses |
| Sieve script name | `managesieve::store::is_valid_name` (`MAX_NAME_BYTES`, NFC, no slash, backslash, control or bidirectional character) | Safety plus Standard (RFC 5804, RFC 5198) | ManageSieve, JMAP `SieveScript` |
| Mailbox name | `util::mailbox_path::valid_folder` (`DELIMITER`, `MAX_DEPTH`, `MAX_DISK_NAME_LEN`) | Safety (it becomes a directory) plus Standard (RFC 3501 modified UTF-7 on the wire) | IMAP `CREATE`, `RENAME`, `SUBSCRIBE`, JMAP `Mailbox/set`, API v1 mailboxes |
| Display name | `directory_store::display_name::validate` | Safety (header and log injection) | `epistle account`, `epistle init`, `[[accounts]]`, the store, API v1 `send` |
| Password | `password::Policy` | Safety | `epistle account`, the management API, SCIM, `epistle init` |
| Network range | `cidr::Cidr::parse` (an address or a block; a zero prefix is refused where it would trust or ban everyone) | Standard (RFC 4632, RFC 4291) | API key and app password `--ip-cidr`, `trusted_proxies`, `epistle ban`, the per-IP limits |
| Memory size | `util::validation::is_memory_size_shape` and `parse_memory_size` (a whole number of `k`, `m` or `g`) | Habit (the compose file spelling) | `epistle stack resources`, `[resources]` in the init answers, the SMTP memory budget |
| Data directory | `Config::validate_data_dir` (absolute) for `mail.toml`; `epistle init` adds a refusal of `$`, control and invisible characters and a `..` above the root | Safety (compose interpolates `$`; terminals print the path) | `data_dir` in `mail.toml`, `epistle init` |
| Sizes of messages, attachments, scripts and queues | `docs/limits.md` and the catalog in `cli::limits_catalog` | Standard where an RFC sets the floor, Habit otherwise | SMTP, IMAP, JMAP, API, ManageSieve |

## Differences kept on purpose

The tests below name each of these as a cell, so a new difference turns the build
red instead of going unnoticed.

- `mail.toml` accepts `Mail.Example.NET.` and ` mail.example.net ` for `hostname`
  because it tidies the value before it checks it. `epistle init` and the domain
  rule refuse both. Only the tidied value is stored.
- `mail.toml` refuses a non-ASCII host name and says which A-label to write.
  `epistle init` accepts the U-label and stores the A-label.
- `epistle init` refuses a data directory with `$`, a control character or a
  `..` above the root. `mail.toml` only needs an absolute path.
- An account name typed with capitals is converted to lowercase by the store and
  refused by the rule when read as typed (owner decision of 2026-10-12).
- The directory component rule is wider than the account rule on purpose.

## What a refusal says

A refusal that reaches a person names the value, the rule it breaks, and a value
that would be accepted:

```
account name "torre.control": '.' is not allowed in an account name, which has
lowercase letters, digits and hyphens only; use a hyphen; for example "torre-control"
```

The value is cut to a short length and printed with escapes, so a control
character in it cannot move the cursor of the terminal that shows it, and a long
value cannot flood a log. A secret is never part of a refusal: passwords and keys
are not echoed, and the credential label rules apply to a label, which is not a
secret.

A protocol reply (ManageSieve `NO`) states the rule and an example but not the
value, because the client already holds it.

## Tests

- `tests/validation_matrix.rs` and `tests/validation_matrix/` drive each rule
  through every entry point from a table of boundary cases and fail when two
  entry points disagree: accounts, addresses, domains, single labels, Sieve
  names, passwords, display names, CIDR, mailbox names, memory sizes, credential
  labels (`labels.rs`), host names (`hostname.rs`) and data directories
  (`data_dir.rs`).
- Each definition has unit tests beside it (`util/label_rule_tests.rs`,
  `util/account_rule_tests.rs`, `cidr_tests.rs`, `util/validation/mod_tests.rs`).
