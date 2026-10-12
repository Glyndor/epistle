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

The server produces aggregate (RUA) reports for domains you host. Inbound
DMARC aggregate reports from receivers are ingested automatically: the
deliverer recognises `postmaster@<domain>` as a report target, the JSONL
store under `data_dir/reports/dmarc/YYYYMMDD/` keeps one parsed report per
line, the alert engine can watch `dmarc_report_rows_failing`, and
`epistle reports --config F [--days N]` summarises what receivers saw.

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

### TLS-RPT
Receives reports about TLS delivery problems: TXT at `_smtp._tls.example.org`
with `v=TLSRPTv1; rua=mailto:tlsrpt@example.org`. The server ingests inbound
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

## BIMI (optional)

To show your brand logo in supporting inboxes you need DMARC at enforce
(`p=quarantine` or `p=reject`), an SVG Tiny PS logo hosted over HTTPS, and a
`default._bimi.example.org` TXT record (Gmail additionally requires a paid VMC).
