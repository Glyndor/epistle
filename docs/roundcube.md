# Roundcube with epistle

For this setup, I use IMAP for mailboxes and authenticated SMTP for sending.
The HTTP API is for administration and integrations; it is not
the backend to configure in Roundcube. The available services are described in
[configuration](configuration.md#listeners), and the API's purpose is described
in [its configuration section](configuration.md#api).

**Verification status: not verified.** The epistle behaviour below
is backed by the linked source and documentation. A complete Roundcube
installation, a particular Roundcube/PHP version, and a browser login and send
have not been verified here. The PHP examples are proposed settings, not a
record of a tested installation. epistle's protocol tests do not establish
Roundcube compatibility.

## Prepare the mail services

Start with the [epistle installation](../README.md#install) and an existing
account. Check the enabled listeners and the account before changing the
webmail configuration:

```sh
sudo epistle service list
sudo epistle account show alice
sudo epistle config-check
sudo epistle status
```

These commands and their output are documented in the [CLI reference](cli.md).
Replace `alice` with the account name. Account names and mail addresses are
different identifiers; account names cannot contain dots. Accounts can restrict
sign-in by protocol, so the account must allow both `imap` and `smtp`. See
[accounts](cli.md#accounts).

Use these backend ports, or the custom ports reported by `service list`:

| Purpose | epistle listener | Default port | Transport |
|---|---|---|---|
| Read and manage mail | `imaps` | 993 | TLS from connection start |
| Submit outgoing mail | `submissions` | 465 | TLS from connection start |
| Alternative submission | `submission` | 587 | STARTTLS before authentication |

Port 25 is the inbound SMTP service for other mail servers. I use a submission
listener for webmail. IMAPS and implicit-TLS submission require TLS material;
SMTP authentication is refused before TLS even on loopback. Sources:
[listeners](configuration.md#listeners), [service commands](cli.md#service-listeners),
[transport security](security.md#transport), and
[`src/smtp/session/auth_dispatch.rs`](../src/smtp/session/auth_dispatch.rs).

For a same-host installation, a listener can be published on `127.0.0.1`.
For a separate webmail host, use the mail hostname and a reachable listener.
The bind address belongs to the namespace where epistle runs: a host's loopback
address is not the loopback address inside a separate container. With the
epistle stack, the service command manages the host publication separately
from the container bind. Check [service listeners](cli.md#service-listeners)
and [private interfaces](configuration.md#a-listener-on-a-private-interface).
Roundcube container networking and name resolution are **not verified** here.

## Certificates

I keep TLS on the mail connection as well as on the browser connection.
epistle accepts an operator-managed PEM chain and key through `[tls]`, or
certificates managed through `[acme]`. Its `init` certificate is self-signed
and intended for the first setup. Sources: [TLS configuration](configuration.md#tls),
[ACME](configuration.md#acme), and [the initial certificate](cli.md#why-a-self-signed-cert).

For the proposed Roundcube settings below, use a name covered by the mail
certificate and a chain trusted by the PHP runtime. If the connection travels
over loopback, keep that certificate name as the TLS peer name rather than
assuming a certificate for `mail.example.org` also covers `127.0.0.1`.
The PHP trust store, hostname resolution and Roundcube TLS option syntax are
**not verified** in this repository. Keep certificate and peer-name checks
enabled when validating the installation.

The HTTPS reverse proxy's browser certificate and the certificate epistle
serves on 993/465/587 are separate connections. epistle's ACME service manages
the mail certificates, not the web application's HTTPS certificate. See
[ACME configuration](configuration.md#acme). The web server, PHP packages,
Roundcube database setup and HTTPS virtual host are **not verified** here;
this repository contains no Roundcube installation recipe for them.

## SMTP authentication

I choose SCRAM-SHA-256 when the client supports the complete SMTP exchange.
It proves knowledge of the password without sending the password itself.
epistle enables SCRAM by default. The SMTP server sends the server-final
signature (`v=...`, base64 encoded on the wire) in a **334 challenge**. The
client verifies it and replies with an empty line; only then does epistle
return `235 2.7.0 authentication successful`. This is implemented in
[`src/smtp/session/scram.rs`](../src/smtp/session/scram.rs), in
`scram_client_final` and `scram_server_final`, and covered by
[`src/smtp/session/tests/mods/tests_scram_final.rs`](../src/smtp/session/tests/mods/tests_scram_final.rs).
Those tests have not been run for this guide.

Do not work around an old client assumption that the server-final belongs on
the `235` response. If the installed Roundcube SMTP client cannot complete the
final `334`, explicitly select PLAIN or LOGIN with `smtp_auth_type`, over TLS.
epistle keeps both mechanisms available with SCRAM enabled, so this does not
require turning SCRAM off for every client. Sources:
[authentication](security.md#authentication) and
[`[auth] scram`](configuration.md#auth). Support for the `smtp_auth_type`
values in a particular Roundcube release is **not verified** here.

Credentials matter too. SCRAM needs an account verifier. Static accounts have
no verifier; a successful PLAIN or LOGIN sign-in upgrades an older verifier.
SCRAM also cannot carry an account's TOTP code, so an account with TOTP uses
PLAIN or LOGIN with the code appended instead. See
[authentication](security.md#authentication). The browser workflow for TOTP
and Roundcube's handling of app passwords are **not verified** here; do not
assume a working password login proves SCRAM will work with every credential.

## Proposed Roundcube backend settings

**No verificado:** this repository does not define Roundcube's PHP configuration
keys, their release compatibility, `%u`/`%p` expansion, or the TLS URL prefixes.
Check these against the installed Roundcube release before applying them.
This example deliberately covers only the mail backend, not the application's
database or session configuration.

```php
$config["imap_host"] = "ssl://mail.example.org:993";
$config["smtp_host"] = "ssl://mail.example.org:465";
$config["smtp_user"] = "%u";
$config["smtp_pass"] = "%p";
$config["smtp_auth_type"] = "SCRAM-SHA-256";
```

If SMTP SCRAM is unsupported by that client, the proposed explicit alternative
is:

```php
$config["smtp_auth_type"] = "PLAIN";
```

To use STARTTLS submission instead of implicit TLS, the proposed replacement
is:

```php
$config["smtp_host"] = "tls://mail.example.org:587";
```

These alternatives remain **not verified** on the Roundcube side. The epistle
port and authentication behaviour they target is documented above. In the
loopback case, arrange for the configured certificate name to reach the local
mail listener from the PHP process; verify the actual route rather than
changing the URL to an IP and disabling certificate checks.

## Folder subscriptions and Sent copies

Folder existence and subscription are different. epistle implements `LIST`,
`LSUB` and subscribed listings, with `/` as its hierarchy delimiter. Compare
the mailbox list with the subscription list if a client shows only INBOX.
Sources: [IMAP folders](configuration.md#imap-mailbox-names-and-folders) and
[`src/imap/subscriptions.rs`](../src/imap/subscriptions.rs).
The exact Roundcube folder-subscription screen is **not verified** here.

`epistle migrate imap` now subscribes the folders it puts in the account,
including an already existing folder it copies into. It does not require a
separate manual subscription pass for those folders. See
[IMAP migration](migration.md#copying-mail-over-imap),
[`src/migrate/imap/copy.rs`](../src/migrate/imap/copy.rs), and
[`src/migrate/imap/tests/subscribe.rs`](../src/migrate/imap/tests/subscribe.rs).
This does not establish the subscription state of folders from unrelated
imports or older runs.

epistle saves submitted messages to `Sent` by default, with account and
app-password overrides. If testing reveals duplicate Sent messages, check
whether the client also saves a copy before changing either setting. The
server controls are in [accounts](cli.md#accounts); Roundcube's Sent-copy
defaults and the appropriate client setting are **not verified** here.

## Reverse proxies, shared IPs and bans

IMAP and SMTP use the peer address of the connection Roundcube opens. They do
not obtain the browser's address from an HTTP header. See
[`src/imap/server/mod.rs`](../src/imap/server/mod.rs) (`set_peer_ip`) and
[`src/smtp/server/run.rs`](../src/smtp/server/run.rs) (`set_peer_ip`).
Consequently, users connecting through one webmail backend share the source
address epistle sees. A ban on that address can affect other webmail users.

`[api] trusted_proxies` controls HTTP client attribution for epistle's API,
including OAuth password bans. It defaults to `[]`. Only a trusted TCP peer
may supply `X-Forwarded-For`; epistle validates the chain and selects the first
untrusted address from right to left. Missing or malformed headers fall back
to the peer. Invalid CIDRs and universal `/0` prefixes are refused. Changes
require a restart. See [trusted proxies](configuration.md#api).

Configure that list only when a controlled reverse proxy actually forwards
HTTP requests to epistle. Adding the proxy in front of Roundcube to this list
does not restore browser IP attribution on Roundcube's IMAP/SMTP connections.
Roundcube's own handling of forwarded headers is **not verified** here.

I inspect the ban subjects before lifting one:

```sh
sudo epistle ban list
```

With `[database]`, the CLI can remove an IP, pair or account ban and clear that
subject's failure counter. Without it, the running server's in-memory bans
cannot be managed by the CLI. Allow-listing the webmail address exempts its
clients from shared authentication bans and failure counting, so it also
removes that defence for guesses made through webmail. The SMTP connection's
three-failure limit still applies. See [authentication bans](cli.md#authentication-bans).

## Attachments and message size

`max_message_size` defaults to 26,214,400 bytes (25 MiB). It caps the complete
SMTP message, not just a selected attachment, and is advertised in EHLO
`SIZE`. Headers and the encoded MIME body must fit together. An oversized
message gets `552 5.3.4 message exceeds maximum size`. The message-memory
budget must also accommodate the configured message size. See
[configuration](configuration.md#top-level-keys) and [limits](limits.md#adjustable-limits).

PHP's `upload_max_filesize` and `post_max_size`, the HTTP proxy's body limit,
and Roundcube's upload/message settings are **not verified** here. Check each
layer in the actual installation and leave room below the SMTP cap for the
encoded message. No attachment size is certified by this guide.

Size is not the only gate: authenticated SMTP submissions are inspected when
attachment policy and `scan_authenticated` enable it. A forbidden attachment
can be refused even below the size cap, and an unavailable scanner can defer
submission. See [attachment policy](attachments.md#the-policy) and
[scanner configuration](configuration.md#antispam-clamd-scanner-and-bayesian-thresholds).

## Troubleshooting

These are epistle responses or diagnostic checks. Roundcube's corresponding
UI wording is **not verified**.

| Symptom | Cause or check | Source |
|---|---|---|
| Cannot connect to IMAP or SMTP | Check enabled listener, port and host/container bind. A loopback listener is not reachable from another host. | [Listeners](cli.md#service-listeners) |
| Certificate verification fails | Check the configured mail name, chain and trust store; `init` starts with a self-signed pair. PHP's exact failure is not verified. | [Initial certificate](cli.md#why-a-self-signed-cert) |
| `538 5.7.11 encryption required for auth` | SMTP AUTH was attempted before TLS. Use implicit TLS on 465 or STARTTLS on 587. | [`auth_dispatch.rs`](../src/smtp/session/auth_dispatch.rs) |
| `504 5.5.4 mechanism not supported` | The selected mechanism is unknown or unavailable. In particular, `[auth] scram = false` makes SCRAM unavailable. | [`auth_dispatch.rs`](../src/smtp/session/auth_dispatch.rs), [Auth configuration](configuration.md#auth) |
| SCRAM ends at `334`, or `501 5.5.2 invalid authentication response` | The server-final requires an empty-line acknowledgement. A nonempty response is refused. Check client support or explicitly select PLAIN/LOGIN over TLS. | [`scram.rs`](../src/smtp/session/scram.rs) |
| `535 5.7.8 authentication credentials invalid` | Check password, protocol permissions, disabled account/domain, TOTP and ban subjects. A ban deliberately looks like bad credentials. | [Authentication](security.md#authentication), [`auth_dispatch.rs`](../src/smtp/session/auth_dispatch.rs) |
| Folders exist but are absent from a subscribed listing | Compare subscriptions with `LIST`; migration now subscribes the folders it copies. | [Migration](migration.md#copying-mail-over-imap) |
| `552 5.3.4 message exceeds maximum size` | The complete submitted message exceeded `max_message_size`. | [Size cap](configuration.md#top-level-keys) |
| `452 4.3.1 insufficient system resources; try again later` | The shared message-memory budget is exhausted. | [Memory budget](configuration.md#top-level-keys) |
| `550 5.7.1` attachment refusal, or `451 4.7.1 content scan unavailable, try again later` | Attachment policy refused the content, or inspection could not run. | [Attachments](attachments.md#the-policy) |
| IMAP `NO [OVERQUOTA]` when saving a message | The mailbox quota prevents the append. | [Quota](configuration.md#top-level-keys) |

## Verify the installation

The following acceptance checks are **not verified** until run with the
actual installation. Record the epistle, Roundcube and PHP versions, backend
address, ports and selected SMTP mechanism with the results:

1. Sign in from the browser with certificate verification enabled.
2. Open INBOX and a migrated nested folder; compare folder subscriptions.
3. Send a small message to a local account and a remote mailbox. Check receipt
   and the Sent folder for a single copy.
4. Send attachments below the intended limit, then try a message above it.
   Distinguish an HTTP upload refusal from an SMTP size or policy refusal.
5. In an isolated test setup, check a failed login and its ban subject. Confirm
   the address epistle sees before enabling webmail for multiple users.

Until those checks have results, this page documents the server contract and
a proposed client configuration, not a verified Roundcube deployment.
