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

Plus the **SRV** records printed by `epistle srv-records`. `epistle
dns-records` prints one SRV locator per service your listeners enable: a
service you turned off gets no locator, so a client that follows a
published record always reaches a port the server answers on. The
`autoconfig` and `autodiscover` names follow the same rule: they are
published only when a listener serves the client setup documents, and the
JMAP locator only when the configuration carries the API that serves it.

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
epistle dkim-keygen --out /etc/epistle/dkim/ed1.pem
```

The default is an Ed25519 key (44-byte `p=`, always fits in one TXT
string). For receivers without Ed25519 support, add an RSA selector:

```sh
epistle dkim-keygen --rsa --out /etc/epistle/dkim/rsa1.pem
```

`--rsa` makes the key in process, so nothing has to be on `PATH`.
`--bits` defaults to 2048 and accepts 2048 or 4096 only.

Publish the printed TXT at `<selector>._domainkey.example.org`, and
configure `[dkim] selector` / `key_file`. Add `rsa_selector` /
`rsa_key_file` for the dual-signing path (required from version 0.10;
a startup warning is logged before that whenever the pair is missing).
A single message is then signed with both keys (RFC 8463); receivers
that understand Ed25519 use that signature, the rest fall back to RSA.

Give each hosted domain a key of its own. A key that signs several
domains lets whoever holds it sign as every one of them until all of
them are replaced, and the receivers rate the signing domain (`d=`), not
the key, so sharing one buys no reputation. A domain's own key goes in a
`[[dkim.domain]]` entry (see [configuration](configuration.md#dkimdomain))
and is published at `<selector>._domainkey.<that domain>`. Two domains
that name one key, or whose key files hold the same public key, are
refused; several domains on the `[dkim]` key still work and are reported
by `config-check`, `status` and `dkim show`.

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
  `quarantine`, then `reject`. `sp=` follows `p=` (a stricter `sp=`
  already there stays), `np=reject`
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
- A name is planned only when each of its labels is made of ASCII letters,
  digits, hyphens and underscores (the first may be `*`) and the name has at
  most 253 characters, 63 per label: a record is written back under the name
  that was read. Any other name is listed as left as is, with the reason.
- Delegations are left alone. A name below the zone apex that has NS
  records belongs to other nameservers, and so does everything under it:
  records written there would be hidden by the delegation or refused by
  the provider. The plan skips the name and every name under it, and
  lists it once as `sub.example.org is delegated to other nameservers;
  left as is`. A domain that is itself delegated (or sits inside a
  delegation) gets no DMARC rewrite, no names and no wildcard. The NS
  records at the zone apex name the servers of the zone itself and are
  not a delegation. The lockdown reads the whole zone first: a provider
  that cannot list it (`route53`, `rfc2136`) makes the command stop
  before it writes anything.

Before a step up, the plan lists the senders that failed DMARC in the
aggregate reports epistle received for the domain in the last 30 days
(`data_dir/reports/dmarc/`), or says there are none. Authorise the ones
that are yours first.

Every record published goes into `<data_dir>/dns-lockdown/<domain>.json`
as soon as the provider accepts it, so a failure halfway leaves the
journal with exactly what went out. A second run with nothing to do
prints `nothing to change`. `--undo` removes only journal records that
are still in the zone as published, puts back the DMARC record the
lockdown replaced (your last version of it, if you edited it between
runs), and reports anything changed since; nothing outside the
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

With a `[dns]` provider, epistle refreshes that record after every certificate
change (ACME renewal or a replaced `[tls]` pair):

- **Retry.** A refresh the provider refuses is not forgotten. It is kept in
  `data_dir/dns-tlsa/state.json` and retried every minute tick with a growing
  wait (one minute, doubling, at most one hour) until it succeeds, always for
  the certificate that is in service at that moment. `epistle status` shows it
  as a `tlsa-pending` item with the reason and the value to publish by hand.
- **Ownership.** Only TLSA values this instance published (or the association
  of the certificate it just replaced) are replaced. A record of somebody else
  at `_25._tcp.<hostname>`, such as the certificate of a second SMTP node, is
  never removed. A provider that applies guarded changes keeps those records
  and leaves the previous value next to the new one until the next rotation. A
  provider that can only replace the whole set does not write while foreign
  records are there: the refresh stays pending and `status` names them.
  Replacing everything needs you to remove them or publish by hand.
- **Zone.** The zone the credential sees is not assumed to serve the name. If
  the zone lists an NS delegation at or above `_25._tcp.<hostname>` the write
  is refused. Providers that cannot list their zone (`route53`, `rfc2136`)
  cannot be checked and keep writing into the zone you configured.

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

A record is published in the zone that holds its name. A provider that
names its zones looks a zone up by its exact name, so epistle asks it
which zone holds the name — the longest zone below it — and writes the
record there. A mail hostname under the zone apex (`mail.example.org`
inside `example.org`) is published in `example.org`, and the dns-01
challenge of an ACME order for such a hostname is published in the same
zone and withdrawn from it.

With several `[[dns]]` entries (see [`configuration.md`](configuration.md)
§`[dns]`) the zone also picks the credential: every write goes to the entry
whose zone contains the name, never to another one, and a name outside all of
them is left to you as in manual mode. A signing domain in any configured zone is
rotated, in its own zone.

A zone the provider does not hold is not a zone it could not answer
about: the search goes on to the parent only in the first case. When the
provider fails — a timeout, a refused token, a reply that does not parse
— the search stops and the record is not written anywhere: publishing it
in the parent zone would put it in a zone the operator did not ask for.

### Checking provider credentials

Run `epistle dns provider check [--json]` to inspect the configured credential
(each credential, with several `[[dns]]` entries, labelled with its zone).
This command only reports findings. It never changes records or settings,
restarts the server, or prevents another command from running. Findings use
`verified`, `not verifiable with this provider` (`not_verifiable` in JSON),
or `failure` with a cause. JSON carries the same facts as text. The command
exits successfully after printing its report, even when a finding fails.

Cloudflare checks user-token activity and expiration, lists visible zones,
and reads a record page in each visible zone needed by a hosted domain,
the mail hostname, `autoconfig`, `autodiscover`, or `mta-sts`. It names extra
zones and own names for which no visible zone matches. A visible zone is an
API visibility result, not proof of DNS delegation. Expiration within seven
days is reported explicitly. An omitted expiration date stays unknown.
Cloudflare inspection accepts at most 16384 own names and 100000 visible
zones. Zone matching uses a name index and yields to the operation deadline.

When token policies are readable, Cloudflare also reports DNS Write grants
for visible required zones and whether DNS access extends beyond them.
The write finding describes the token policy, without attempting a write;
it cannot establish restrictions inherited from the account owner's role.
A wildcard policy is broader even when the account currently has one zone.
Permission groups are recognized by their stable identifiers, not their display
names. Unrecognized groups and account-specific nested resources stay unknown.
The [token details endpoint](https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/get/)
requires API Tokens Read or Write. A token without that extra permission
can still report activity, expiration, zones and record reading. Do not add
token-management permissions merely to make every finding verifiable.

For Bunny, deSEC, DigitalOcean, DNSimple, Google Cloud DNS, GoDaddy,
Namecheap, OVH, Porkbun and Spaceship, the existing zone listing can verify
record reading in the configured zone. It does not enumerate every zone
accessible to the credential. Other findings stay unknown. Route 53,
RFC 2136 and manual mode currently expose no inspection metadata.
Read-only operations at Porkbun and Namecheap use POST; Google may exchange
a service-account assertion for an access token. None writes DNS records.
Tokens, token identifiers and remote error bodies are never printed. Zone names
containing the full token or its first or last eight characters are redacted,
including case variants. Configuration errors omit source excerpts and values;
TOML errors retain a numeric byte position when the parser supplies one.

### Creating credentials with the least access

Create a separate credential for epistle and restrict it to the zone it
manages wherever the provider offers that restriction. Grant only the
operations below for record automation. The table describes endpoints used
by the implementations in `src/dns/providers/`, including writes needed by
publishing and cleanup, not writes performed by `provider check`.
For every provider other than Cloudflare, the exact permission names,
credential creation steps, available zone restrictions and expiration
controls must be checked in that provider's documentation. A local
`ScopedSecret` restriction does not restrict the credential at the provider.

| Provider | Access to request when creating the credential |
|---|---|
| Cloudflare | Create a custom API token with Zone DNS Edit and Zone Read, restricted to the required zones. Publishing uses `GET /zones`, and GET, POST, PUT and DELETE on `/zones/{id}/dns_records[/{id}]`. Inspection adds GET `/user/tokens/verify` and, if permitted, `/user/tokens/{id}`. See [token creation](https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/). |
| Bunny | Use a key that can GET `/dnszone?search=...` and `/dnszone/{id}`, PUT `/dnszone/{id}/records`, and POST or DELETE `/dnszone/{id}/records/{record_id}`. Verify whether a DNS-only, zone-limited key is available. |
| deSEC | Use a token limited to reading and updating `/domains/{zone}/rrsets/` with GET and PUT. Deletion uses an empty record set. Verify the provider's token policy controls. |
| DigitalOcean | Use a token for GET and POST `/v2/domains/{zone}/records`, and PUT and DELETE `/v2/domains/{zone}/records/{id}`. Verify domain restrictions and permission names. |
| DNSimple | Use a token for GET and POST `/v2/{account}/zones/{zone}/records`, and PATCH and DELETE `/v2/{account}/zones/{zone}/records/{id}`. Verify account and zone restriction options. |
| Google Cloud DNS | Use a dedicated service account that can list `/dns/v1/projects/{project}/managedZones`, GET `/{zone}/rrsets`, and POST `/{zone}/changes` under that collection. The implementation requests OAuth scope `ndev.clouddns.readwrite` through `/token`. Verify the smallest IAM permission set and resource bindings. |
| GoDaddy | Use an API key and secret for GET `/v1/domains/{zone}/records[/type/name]`, PUT `/v1/domains/{zone}/records/{type}/{name}`, and DELETE at the same record path. Verify production API eligibility and zone restriction options. |
| Namecheap | Enable only the account access needed for `namecheap.domains.dns.getHosts` and `namecheap.domains.dns.setHosts` through form POST `/xml.response`. Supply the permitted egress IPv4 address. Verify key restrictions in the provider documentation; `setHosts` replaces the zone's host list. |
| OVH | Create application and consumer credentials for GET `/domain/zone/{zone}/record[/{id}]`, POST on `/record` and `/refresh`, and PUT and DELETE on `/record/{id}`. Verify access-rule syntax for those paths. |
| Porkbun | Use an API key and secret for POST `/api/json/v3/dns/retrieve/{zone}`, `/dns/create/{zone}`, `/dns/edit/{zone}/{id}`, and `/dns/delete/{zone}/{id}` under the same API base. Verify domain API access and key restrictions. |
| Route 53 | Use credentials for `ListResourceRecordSets` (GET `/2013-04-01/hostedzone/{id}/rrset`) and `ChangeResourceRecordSets` (POST at that path). Restrict to the hosted zone where IAM permits it; verify the IAM action and resource syntax. |
| RFC 2136 | Create a TSIG key on the authoritative nameserver with an update policy limited to the zone and record names/types epistle publishes. There is no HTTP endpoint or token inspection. Verify update-policy syntax in the nameserver documentation. |
| Spaceship | Use an API key and secret for GET, PUT and DELETE `/api/v1/dns/records/{zone}`. Verify DNS-only permissions and domain restrictions in the API manager documentation. |
| Manual | No token is needed; records are published by hand. |

### What a listing returns

`epistle dns lockdown`, `epistle dns provider test` and the DKIM clean-up
list the zone through the provider. Every provider returns each record with
its own type: NS, HTTPS, SVCB and CAA are kept as such, and a type epistle
has no use for (NAPTR, SSHFP, the SOA, Namecheap's URL redirects, Bunny's
redirect and script records) is kept under its type name. None of them is
read as a TXT, so a TXT check never sees an NS target, and none of them is
ever written or deleted by epistle. A type name that is not made of letters,
digits and hyphens (at most 32) is shown as `UNKNOWN`.

The value is kept with the type: an MX is `<preference> <exchange>` and a
CAA is `<flags> <tag> "<value>"`, even where the provider's API keeps those
parts in fields of their own (Bunny, DigitalOcean, DNSimple, Porkbun,
Spaceship). The field layouts come from the providers' published API
references, not from captures of the real services. Bunny's MX is read from
`Priority` and `Value` together, and `Priority` is joined to `Value` only when
`Value` does not already start with the preference.

A listing is never a part of the zone presented as the whole. It fails
instead when it would need more than 1000 pages or return more than 100000
records; when its pages do not add up to the total it gives (an empty page
before the total, a total below what was read, a total that changes or more
pages than it allows: Spaceship, Cloudflare, DNSimple, DigitalOcean, and OVH
when an id it listed has no record); when a full page does not say whether
more follow (Cloudflare, DNSimple, Spaceship); when a response body is larger
than 16 MiB (256 KiB for Namecheap, whose answer is the whole zone); and when
the bodies of the operation add up to more than 64 MiB. An rrset with no
record counts as one record. A delegation that fell off the end of a listing
would be written over. deSEC lists past 500 rrsets page by page, through the
`Link` header it sends; a `Link` that names a next page nobody can read is an
error.

Every call to a provider times out at 30 seconds (10 to connect), body
included, and a whole operation (a listing across its pages, a publish with
the reads it makes first) at 120 seconds. That holds for RFC 2136 too: 10
seconds to connect, 30 for the exchange. A provider is never followed to
another host: a redirect is an error. The error of a failed call carries no
URL, and what the provider answered is shown with control characters
escaped.

`route53` and `rfc2136` cannot list a zone at all, so a command that has to
read it stops with an error before it writes anything.

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
`default._bimi.example.org` TXT record (Gmail additionally requires a
certificate, a VMC or a CMC).

The record and the logo are the whole of the DNS side. epistle writes no BIMI
header and reads none, so publishing the record changes nothing about the mail
it sends until a receiver has a reason to look.

What each receiver asks for on top of the record:

- **Gmail** takes a Verified Mark Certificate (VMC) or a Common Mark
  Certificate (CMC) from a CA that supports BIMI (Entrust, DigiCert, GlobalSign
  or Sectigo), and its DMARC policy has to be at `p=quarantine` or `p=reject`
  with `pct=100`. Either certificate brings the logo; the checkmark next to the
  sender is the mark of a VMC, which names the organization and the DNS name in
  its subject, so it has to be issued for the exact domain that publishes the
  record. See
  [Set up BIMI](https://knowledge.workspace.google.com/admin/security/set-up-bimi).
- **Yahoo** asks for no certificate, but eligibility also depends on the
  sender sending bulk mail and having enough reputation and engagement. A valid
  SVG and a DMARC policy at `p=quarantine` or `p=reject` do not by themselves
  guarantee that the logo is shown. A VMC in the record is used to decide the
  overall eligibility, it is not needed for the logo. See
  [BIMI](https://senders.yahooinc.com/bimi/).
- **Apple Mail and Fastmail** need neither the VMC nor the certificate.
- **The logo** must be an SVG Tiny Portable/Secure (SVG P/S) file served over
  HTTPS with a valid certificate, small enough for the receiver's limit, with
  no scripting and no external references. Gmail caches it for about a day, so
  a fixed URL that changes in place is not noticed quickly.
- **The DMARC policy** has to be at enforce for every receiver that shows the
  mark. `p=none` collects the data but displays no logo anywhere.
- **`rua=` is not enough on its own**: the receiver needs a DMARC report
  aggregate stream to exist, which is what `rua=` is for, but the record and
  the mark are read independently of it.

The domain the record lives on is the one that must pass DMARC, and the logo
belongs to that domain. A logo served from another domain can be recorded in
the `l=` tag, and Gmail accepts a cross-domain `l=` only when the certificate
covers both names.

epistle does not generate or publish the record: `default._bimi` is a TXT
record you add, and `epistle dns` does not manage BIMI records.

## DNS provider token storage

I keep the provider token in an owner-only file outside `data_dir`, beside the
storage and OAuth keys. To move the current inline or environment token:

```sh
epistle dns provider set desec --zone example.org --store-token --config /etc/epistle/mail.toml
```

Use your provider and zone, and repeat its other required settings, such as
`--account-id` for DNSimple. `--store-token` reads the current token without
printing it, writes `<data_dir>/../secrets/dns_provider_token` with mode `0600`,
and replaces `dns.token` and `dns.token_env` with `dns.token_file`. With
`--token-env NAME` or `--token-file /absolute/path`, it imports that source
instead. A different existing destination is refused.

For a generated stack, the command removes the old token environment entry and
the read-only mount of a token file the configuration no longer names, adds the
mount of the new source only to `mail`, and recreates `mail`. A container that
keeps the mount of a credential you took away still has that credential, so the
mount leaves with the setting that named it. Without a stack, restart the server
yourself. Remove the old environment variable from your shell, service
configuration, answers file and Compose overrides too. Keep the secret
separately from data backups.

`--token-file /absolute/path` names a file you already keep: the command does
not move it, and the generated stack mounts that path read-only into `mail`, so
the container reads the same file the host does. A path the stack does not
mount is a path the container does not have, and the provider never builds.

`--dry-run` previews the redacted configuration change and the change to the
generated Compose file, and writes neither the token nor the Compose file. The
redaction walks the TOML tree, so a credential is hidden whole: a token written
as a multiline string does not reach the terminal, a log or the JSON output
with the lines it continues on.

Existing inline and environment sources keep working. `epistle status` reports
a warning with migration instructions, without displaying the token. A file
accessible to group or other users is rejected with an instruction to restrict
it to `0600`. For a new `init`, use `dns.token_file` in the answers file to name
the secret; `init` mounts that file read-only only into `mail` at the same path.
