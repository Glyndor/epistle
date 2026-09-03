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
| DMARC | `_dmarc.example.org` | TXT | `v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org` |
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
configure `[dkim] selector` / `key_file`. Add the optional
`rsa_selector` / `rsa_key_file` for the dual-signing path. A single
message is then signed with both keys (RFC 8463); receivers that
understand Ed25519 use that signature, the rest fall back to RSA.

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
v=DMARC1; p=quarantine; rua=mailto:dmarc@example.org; adkim=s; aspf=s
```

The server produces aggregate (RUA) reports for domains you host.

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
with `v=TLSRPTv1; rua=mailto:tlsrpt@example.org`.

### DANE (optional, needs DNSSEC)
If the zone is DNSSEC-signed, publish a `TLSA` record for `mail.example.org:25`
so senders authenticate your TLS certificate without relying on a public CA.

## Client autodiscovery

So users configure a client from just their address and password:

- Publish the **SRV** records from `epistle srv-records` (submission, IMAP(S),
  POP3S, ManageSieve, and the autodiscover SRV).
- Point `autoconfig.example.org` and `autodiscover.example.org` at the host, and
  serve the documents from `epistle autoconfig` / `epistle autodiscover` there.
- Hand users the Apple profile from `epistle mobileconfig` for iOS/macOS.

## Publishing records through epistle

If `[dns]` is configured (see [`configuration.md`](configuration.md) §`[dns]`),
epistle writes records itself — the operator does not have to add them by
hand. The supported providers are `cloudflare`, `desec`, `namecheap`,
`route53`, `rfc2136` (TSIG-authenticated dynamic update against a local
nameserver), `spaceship`, and `manual` (records printed for the operator).
RFC 2136 talks UPDATE directly to BIND/Knot/NSD over TCP, authenticating
with TSIG — useful when the zone is hosted on the same host as epistle
and a full DNS-as-a-service API is overkill.

## BIMI (optional)

To show your brand logo in supporting inboxes you need DMARC at enforce
(`p=quarantine` or `p=reject`), an SVG Tiny PS logo hosted over HTTPS, and a
`default._bimi.example.org` TXT record (Gmail additionally requires a paid VMC).
