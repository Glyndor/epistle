# DNS setup

DNS is the hardest part of self-hosting mail. This guide lists every record to
publish for a domain. The examples use:

- domain **`example.org`**
- mail hostname **`mail.example.org`** (the one name the server HELOs with)
- public IP **`203.0.113.10`** (and `2001:db8::10` for IPv6)

Several values are generated for you — `epistle dkim-keygen` (DKIM),
`epistle srv-records` (SRV), `epistle autoconfig` / `epistle autodiscover` (client setup).
After publishing, verify with `epistle config-check` and an external checker.

## Records at a glance

| Record | Name | Type | Value |
|---|---|---|---|
| Host | `mail.example.org` | A / AAAA | `203.0.113.10` / `2001:db8::10` |
| Mail exchanger | `example.org` | MX | `10 mail.example.org.` |
| SPF | `example.org` | TXT | `v=spf1 mx -all` |
| DKIM | `<selector>._domainkey.example.org` | TXT | from `epistle dkim-keygen` |
| DMARC | `_dmarc.example.org` | TXT | `v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org` |
| MTA-STS | `_mta-sts.example.org` | TXT | `v=STSv1; id=20260101000000` |
| TLS-RPT | `_smtp._tls.example.org` | TXT | `v=TLSRPTv1; rua=mailto:tlsrpt@example.org` |
| Reverse DNS (PTR) | the IP | PTR | `mail.example.org` (set at the IP's host) |
| Client autoconfig | `autoconfig.example.org` | A/CNAME | the host |
| Client autodiscover | `autodiscover.example.org` | A/CNAME | the host |

Plus the **SRV** records printed by `epistle srv-records`.

## The essential four

These decide whether your mail is delivered at all.

### MX + host record
`MX` points the domain at the mail host; the host needs its own `A`/`AAAA`.
Multiple domains can share one mail host (and one PTR) — only the MX differs.

### Reverse DNS (PTR) — set this, it is often forgotten
One `PTR` per **IP**, pointing to the mail hostname (`mail.example.org`), and it
must match the name the server HELOs with. Receivers check HELO ↔ PTR ↔ IP. PTR
is set at the **IP owner (your VPS/host)**, not through your DNS provider, so it
cannot be automated by a DNS-provider integration — set it by hand.

`epistle verify-dns` checks the PTR for every address the hostname is supposed
to answer on (the configured `public_ipv4` / `public_ipv6`, or whatever the
hostname resolves to when neither is set). The three failure lines mean three
different things and point at three different fixes:

- `MISS PTR <ip>: no reverse record; ask the provider of this IP to point it
  at <hostname>`: the IP owner has not set a PTR. Talk to the VPS / host
  provider; they control this side of the DNS, not your zone file.
- `MISS PTR <ip>: points at <name>, not <hostname>`: the PTR exists but
  names something else (typically an old host from before a migration). Fix
  the PTR at the IP owner.
- `MISS PTR <ip>: <hostname> does not resolve back to <ip>`: the PTR points
  at the right name but the name's A/AAAA does not include this IP. Forward
  and reverse are out of sync; receivers that do forward-confirmation would
  still treat this as a mismatch.

### SPF
Authorizes your IP to send for the domain. `v=spf1 mx -all` authorizes whatever
the MX points at; or pin the IP: `v=spf1 ip4:203.0.113.10 -all`. `-all` (hard
fail) is recommended once you are sure every sender is listed.

Exactly one SPF record at the apex. Two `v=spf1` TXT records at the same
name are a `permerror` for every receiver (RFC 7208 §4.5), so a
migrated domain whose old provider left a record behind stops
delivering until the duplicate is removed. `epistle status` and
`epistle verify-dns` flag duplicates by name, count, and the
`keep one` instruction; the upsert through a configured provider
collapses them.

### DKIM

Sign outbound mail. Generate the key and record:

```sh
epistle dkim-keygen --out /etc/glyndor/epistle/dkim/ed1.pem
```

The default is an Ed25519 key (44-byte `p=`, always fits in one TXT
string). For receivers without Ed25519 support, add an RSA selector:

```sh
epistle dkim-keygen --rsa --out /etc/glyndor/epistle/dkim/rsa1.pem
```

`--rsa` delegates to `openssl genpkey` and the binary must be on `PATH`
(the Debian package installs it). `--bits` defaults to 2048 and accepts
2048 or 4096 only.

Publish the printed TXT at `<selector>._domainkey.example.org`, and
configure `[dkim] selector` / `key_file`. Add `rsa_selector` /
`rsa_key_file` for the dual-signing path (required from version 0.10;
a startup warning is logged before that whenever the pair is missing).
A single message is then signed with both keys (RFC 8463); receivers
that understand Ed25519 use that signature, the rest fall back to RSA.

Multiple selectors at different names are normal (the Ed25519 + RSA
pair), but two at the same selector name is the same configuration
mistake the SPF, DMARC, and MTA-STS lanes flag and collapse; a
DKIM rotator's old and new keys sit at different selector names,
never at the same one.

#### Long TXT values split at 255 octets

RFC 1035 §3.3.14 caps each character-string at 255 octets, and RSA-2048
`p=` is around 410 bytes (RSA-4096 around 755). When
`epistle dns-records` prints the RSA selector's record, it splits the
value at the boundary and quotes each part, so the operator can paste
the line into a zone file directly:

```
rsasel._domainkey.example.org 3600 IN TXT ("v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
                                     "MIIBCgKCAQEA...")
```

Some DNS providers prefer the value as one long string and split it
themselves on submit; `epistle dns-records` always emits the split form,
which the same providers accept too. Receivers reassemble the strings
the way every resolver does (RFC 1035 §3.3.14, §7), so the split is
transparent on the wire.

## Reporting and policy

### DMARC
Ties SPF and DKIM together and tells receivers what to do on failure. Start at
`p=none` to monitor, then move to `p=quarantine` and `p=reject`:

```
v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org; adkim=s; aspf=s
```

Exactly one DMARC record at `_dmarc.<domain>`. Two of them make
receivers ignore the policy (RFC 7489 §6.6.3); the same duplicate
detection and collapse the SPF lane gets.

The server produces aggregate (RUA) reports for domains you host. Inbound
DMARC aggregate reports from receivers are ingested automatically: the
deliverer recognises `postmaster@<domain>` as a report target, the JSONL
store under `data_dir/reports/dmarc/YYYYMMDD/` keeps one parsed report per
line, the alert engine can watch `dmarc_report_rows_failing`, and
`epistle reports --config F [--days N]` summarises what receivers saw.

### Locking the zone against spoofing

`epistle dns lockdown [<domain>] [--yes] [--json] [--undo] [--dmarc reject]`
(and the `dns` flag `--dry-run`) makes sure nobody can send mail as the
domain or a name under it from somewhere else. It reads the zone through
the `[dns]` provider, prints the plan (`--json` prints the same plan as
JSON), asks, and publishes:

- DMARC at `_dmarc.<domain>`, one step stricter per run: `none`, then
  `quarantine`, then `reject`. `sp=` follows `p=`, `np=reject`
  (DMARCbis, names that do not exist) is set at once, `pct` is dropped,
  and every other tag (`rua`, `ruf`, `adkim`, `aspf`, `fo`, `ri`) stays as
  written. `--dmarc reject` goes straight to `reject`. A DMARC record
  that cannot be read, a second one, or a CNAME at `_dmarc` is left alone
  and reported.
- `v=spf1 -all` (sends no mail) and `MX 0 .` (RFC 7505, accepts no mail)
  at every name with an A, AAAA or CNAME, except: names epistle serves
  (each hosted domain, the mail hostname, `autoconfig`, `autodiscover`,
  `mta-sts`), service names (`_dmarc`, `_domainkey` and DKIM selectors,
  `_mta-sts`, `_smtp._tls`), MX targets, CNAMEs (no record may sit next
  to a CNAME, RFC 1034 section 3.6.2), and names with an SPF or MX of
  their own. Each is listed as left as is, with the reason.
- `*.<domain>` `v=spf1 -all`, only when the zone has no wildcard. It
  covers names that do not exist; a wildcard never applies to a name
  with records of its own.

Before a step up, the plan lists the senders that failed DMARC in the
aggregate reports epistle received for the domain in the last 30 days
(`data_dir/reports/dmarc/`), or says there are none. Authorise the ones
that are yours first.

Every record published goes into `<data_dir>/dns-lockdown/<domain>.json`
as soon as the provider accepts it, so a failure halfway leaves the
journal with exactly what went out. A second run with nothing to do
prints `nothing to change`. `--undo` removes only journal records that
are still in the zone as published, puts back the DMARC record the first
run replaced, and reports anything changed since; nothing outside the
journal is touched. Without a provider, the command prints the DMARC
and wildcard records to add by hand.

### MTA-STS
Requires inbound senders to use verified TLS. Two parts:

1. TXT at `_mta-sts.example.org`: `v=STSv1; id=<changes when the policy changes>`.
2. A policy file served over HTTPS at
   `https://mta-sts.example.org/.well-known/mta-sts.txt` (your web/proxy serves
   this — the mail server does not):

   ```
   version: STSv1
   mode: enforce
   mx: mail.example.org
   max_age: 604800
   ```

One MTA-STS discovery TXT at `_mta-sts.<domain>`; the policy file
itself lives over HTTPS, but two discovery records break the lookup
(RFC 8461 §3.1).

### TLS-RPT
Receives reports about TLS delivery problems: TXT at `_smtp._tls.example.org`
with `v=TLSRPTv1; rua=mailto:tlsrpt@example.org`. One TLS-RPT TXT per
domain; a duplicate is the same configuration mistake the SPF and
DMARC lanes flag and collapse. The server ingests inbound
TLS-RPT reports the same way it ingests DMARC: `tlsrpt@<domain>` is the
envelope target, the JSONL store lives at
`data_dir/reports/tlsrpt/YYYYMMDD/`, the alert engine can watch
`tlsrpt_failed_sessions`, and `epistle reports` prints per-domain summaries.

### DANE (optional, needs DNSSEC)
If the zone is DNSSEC-signed, publish a `TLSA` record for `mail.example.org:25`
so senders authenticate your TLS certificate without relying on a public CA.

## Client autodiscovery

So users configure a client from just their address and password:

- Publish the **SRV** records from `epistle srv-records` (submission, IMAP(S),
  POP3S, ManageSieve, and the autodiscover SRV).
- Point `autoconfig.example.org` and `autodiscover.example.org` at the host and
  add an `autoconfigs` listener (port 443). It serves the documents over HTTPS
  with the server certificate, so no TLS proxy is needed; the certificate must
  cover both names (add them to `[acme] domains`). Keep the plain `autoconfig`
  listener only if a proxy already terminates TLS for those names.
- Apple devices have no autodiscovery of their own: send users to
  `https://autoconfig.example.org/mobileconfig?email=<address>` (or hand them
  the file from `epistle mobileconfig`). The profile carries no password.

## Publishing records through epistle

If `[dns]` is configured (see [`configuration.md`](configuration.md) §`[dns]`),
epistle writes records itself — the operator does not have to add them by
hand. The supported providers are `bunny`, `cloudflare`, `desec`,
`digitalocean`, `dnsimple`, `gcloud`, `godaddy`, `namecheap`, `ovh`,
`porkbun`, `route53`, `rfc2136` (TSIG-authenticated dynamic update against a
local nameserver), `spaceship`, and `manual` (records printed for the
operator).
RFC 2136 talks UPDATE directly to BIND/Knot/NSD over TCP, authenticating
with TSIG — useful when the zone is hosted on the same host as epistle
and a full DNS-as-a-service API is overkill.

### Record descriptions

Where a provider's record API has a free-text description, epistle sets it to
`Epistle v<version>` on every record it creates or updates, so the provider's
panel shows which records epistle wrote and with which release. The text is a
label, not an ownership key: records are still matched by type, name and (for
TXT) value. It is rewritten on each write, so a record touched by a newer
release shows the newer version.

| Provider | Description | Field | Limit (documented) |
|---|---|---|---|
| Cloudflare | yes | `comment` | 100 characters (Free), 500 (paid); no line breaks |
| Bunny DNS | yes | `Comment` | none documented |
| Porkbun | yes | `notes` | none documented |
| deSEC, DigitalOcean, DNSimple, GoDaddy, Google Cloud DNS, Namecheap, OVH, RFC 2136, Route 53, Spaceship | no description field | none | none |

Cloudflare also gets a tag `epistle:<hostname>` (the server's `hostname`), so a
zone shared by several servers shows which one wrote each record. epistle
replaces only its own `epistle:` tag and keeps any other tag you set on the
record. Tags need a paid Cloudflare plan: if a write is refused on a Free zone,
epistle retries it once without tags, stops sending them until the next
restart, and logs a single warning. The record `id` is assigned by Cloudflare
and cannot be set.

Cloudflare's proxy (the orange cloud) forwards only HTTP(S), so a mail
name behind it is unreachable on ports 25, 465, 587 and 993. With the
Cloudflare provider, `epistle status` fails for each proxied A, AAAA or
CNAME at the mail hostname, an MX target of a hosted domain, or a
domain's `autoconfig`, `autodiscover` and `mta-sts` host:

```
mail.example.org is proxied by Cloudflare (orange cloud): mail clients and other servers cannot reach port 25/465/587/993 through the proxy; set it to DNS only
```

Every A, AAAA and CNAME epistle publishes through Cloudflare is sent
with `proxied: false`. Other providers have no proxy and no such check.

### TXT values

Each provider API wants a TXT value in its own form, so epistle encodes it per
provider and reads it back to the plain text before comparing. A value is the
same record whatever its quoting or 255-octet splitting, so publishing the same
DKIM key twice changes nothing and never doubles its quotes. A value you pass
already wrapped in quotes is read without them.

| Provider | epistle sends | Over 255 octets | Read back as |
|---|---|---|---|
| Cloudflare, deSEC, DNSimple, Google Cloud DNS | quoted, `"` and `\` escaped | split by epistle into quoted strings | quoted strings |
| Route 53 | quoted, octal escapes | split by epistle into quoted strings | quoted strings |
| RFC 2136 | DNS wire format | split by epistle into character-strings | not listed |
| Bunny, DigitalOcean, GoDaddy, Namecheap, OVH, Porkbun, Spaceship | plain text | one string, the provider splits it | plain text (OVH: quoted strings) |

Bunny, DigitalOcean, GoDaddy, Namecheap, OVH, Porkbun and Spaceship do not
document TXT quoting. epistle sends the plain text there, which is also what
other clients of those APIs send. Those clients will not send a TXT value
containing `"` to Namecheap or OVH, or one containing `\` to OVH or
DigitalOcean, so such a value may be refused there. The records epistle
publishes never contain either character.

## BIMI (optional)

To show your brand logo in supporting inboxes you need DMARC at enforce
(`p=quarantine` or `p=reject`), an SVG Tiny PS logo hosted over HTTPS, and a
`default._bimi.example.org` TXT record (Gmail additionally requires a paid VMC).
