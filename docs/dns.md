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
epistle dkim-keygen --out /etc/epistle/dkim/ed1.pem
```

Publish the printed TXT at `ed1._domainkey.example.org`, and configure
`[dkim] selector = "ed1"` / `key_file`. Add a second RSA selector
(`rsa_selector`/`rsa_key_file`) for receivers without Ed25519 support.

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

## BIMI (optional)

To show your brand logo in supporting inboxes you need DMARC at enforce
(`p=quarantine` or `p=reject`), an SVG Tiny PS logo hosted over HTTPS, and a
`default._bimi.example.org` TXT record (Gmail additionally requires a paid VMC).
