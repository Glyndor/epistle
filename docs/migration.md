# Migrating to epistle

Moving a mail service has two halves: the configuration (domains, accounts,
aliases, DKIM keys) and the mail itself. epistle imports the first from Mox or
Stalwart, and copies the second from any IMAP server, again and again until the
old server is switched off.

| Source | Configuration | Mail |
|---|---|---|
| Mox | `epistle migrate mox --from DIR` | `epistle migrate imap` per account |
| Stalwart up to 0.15 | `epistle migrate stalwart --from FILE` | `epistle migrate imap` per account |
| Stalwart 0.16 and later | by hand (settings live in its database) | `epistle migrate imap` per account |
| Any other IMAP server | by hand (`epistle domain add`, `epistle account add`) | `epistle migrate imap` per account |

## The order that keeps mail flowing

1. **Import the configuration.** Run the import with `--dry-run` first: it
   prints what would be created and changes nothing.
2. **Copy the mail** of every account with `epistle migrate imap`. This can take
   hours for large mailboxes and can be interrupted and run again.
3. **Cut DNS over.** Point MX at epistle and publish what `epistle dns-records`
   prints. DKIM records do not change when the import kept your selectors.
4. **Copy again.** Once the old server stops receiving mail, run the same
   `epistle migrate imap` commands once more. Each copies only what arrived
   since the last run.
5. **Hand out passwords and enable the accounts** (see below).

## From Mox

```sh
epistle migrate mox --from /home/mox/config --dry-run
epistle migrate mox --from /home/mox/config --passwords-out /root/mox-passwords.txt
```

`--from` is the directory holding `mox.conf` and `domains.conf`. The reader
follows the configuration format of Mox v0.0.17. It imports:

- every domain, written in Unicode in Mox and stored here in its ASCII form;
- every account with its addresses, its full name, and a `@domain` destination
  as the domain's catch-all;
- every alias, with its members;
- the DKIM keys of the selectors listed under `Sign`, with the same selectors.

Mox's DMARC and TLS report addresses, MTA-STS policy, routes, rulesets and web
handlers are not imported; the output lists the ones it found.

## From Stalwart

```sh
epistle migrate stalwart --from /opt/stalwart/etc/config.toml --dry-run
epistle migrate stalwart --from /opt/stalwart/etc/config.toml --password-reset
```

The reader follows Stalwart v0.15.5, the last release configured by a TOML
file. It imports the DKIM signatures (`[signature.*]`, with the key inline or as
`%{file:PATH}%`) and, when `storage.directory` names a `memory` directory, its
principals: individuals become accounts, groups and `email-list` addresses
become aliases. Accounts in an `internal` (RocksDB), SQL or LDAP directory are
not read; create them with `epistle account add` and copy their mail with
`migrate imap`.

From Stalwart 0.16 the configuration file only points at the database, and the
import refuses it with the same directions. Settings changed in Stalwart's web
admin live in its database in every version and are not imported.

## What both imports do

- **Nothing is overwritten.** An existing domain, account or alias stops the
  import. `--merge` keeps those as they are and adds the rest.
- **Passwords cannot be carried over**: the old server keeps its own hashes.
  Every imported account is created disabled for login. With
  `--passwords-out FILE` each gets a random temporary password, written to that
  new file (mode 0600); with `--password-reset` nobody knows it and you set one
  with `epistle account password NAME`. Then `epistle account enable NAME`.
- **DKIM keys** are saved under `data_dir/dkim-migrated/<domain>/` (mode 0600)
  and never printed. Every imported domain keeps signing with the key it had,
  under the same selector, so its published records stay valid. Without a
  `[dkim]` block the first imported domain's keys become the default, which
  also signs any domain added later; every other domain with different keys
  gets a `[[dkim.domain]]` entry (see the configuration reference). An existing
  `[dkim]` default is kept, and each imported domain gets its own entry. A
  domain that had only an RSA key signs with the default, and the import says
  so: publish the default's record (`epistle dns-records`) for it before the
  cutover.
- Names the account store cannot hold (an account called `Mail Admin`, say) are
  reported and skipped, never renamed.

## Copying mail over IMAP

```sh
epistle migrate imap --account alice --host mail.old.example \
    --user alice@example.com --password-file /root/alice.pw
```

The local account must exist. The remote password comes from `--password-file`
(its first line; keep it mode 0600) or stdin, never from the command line.

- **Connection.** TLS on port 993 by default. `--starttls` uses port 143 and
  refuses a server that does not offer STARTTLS. `--ca-file PEM` trusts a private
  CA or a self-signed server. `--insecure-skip-verify` (encrypted but not
  authenticated) and `--insecure-plaintext` exist for servers on a trusted
  network and print a warning every time.
- **Folders.** Every folder is copied, with the remote hierarchy separator
  turned into `/`. Special-use folders land in the local `Sent`, `Drafts`,
  `Trash`, `Junk` and `Archive`. Virtual folders such as Gmail's All Mail are
  skipped unless named exactly in `--folders`. `--folders` takes patterns with
  `*`; a leading `!` excludes: `--folders '*' --folders '!Trash'`. A name that
  cannot be stored locally is reported and skipped.
- **Messages.** Flags and the received date (INTERNALDATE) are kept. Messages
  marked `\Deleted` on the old server are not copied, and nor are messages over
  the local size limit (25 MiB); the summary counts both.
- **Resuming.** Progress is kept per local account, remote user and host, and
  remote folder, in `data_dir/migrate/<account>/`. A run copies only messages
  newer than the last one copied. If the old server renumbers a folder (its
  UIDVALIDITY changes), the folder is read again and each message is checked
  against the mailbox by Message-ID and size, so nothing is stored twice. Keep
  `--host` and `--user` the same between runs: they name the progress files.
- **Limits.** The run stops with an error when the next message would exceed
  the account's quota; raise it and run again to continue.
- **Output.** One line per folder with messages, bytes and rate; `--dry-run`
  lists each folder and how many messages it would copy; `--json` prints the
  summary as one object.

A broken or hostile server cannot make the copy hold unbounded data: lines,
literals, the bytes held for one batch, the number of responses and every wait
are capped, and a message larger than the server declared is refused.
