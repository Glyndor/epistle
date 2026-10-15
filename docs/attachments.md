# Attachments

epistle looks at what every attachment really is, not what its name or its
declared type says, and applies the `[attachments]` policy to what it finds.
It never opens or runs an attachment: the risk is the recipient's client.
ClamAV still matters, see [below](#clamav-is-still-recommended).

To see what the policy would do with a message, without delivering it:

```sh
epistle attachments check suspicious.eml
```

## What is detected

Every finding is a stable reason code. Only codes reach the
`X-Epistle-Attachment-Warning` header and the logs, never a file name.

| Code | What it means |
|------|---------------|
| `dangerous-extension` | A name ends in an extension that runs or mounts on a double click (`exe`, `js`, `lnk`, `iso`, ... and `block_extensions`). |
| `double-extension` | A decoy extension sits before a dangerous one: `factura.pdf.exe`. |
| `bidi-name` | A name carries bidirectional or invisible formatting characters (`invoice<RLO>fdp.exe` shows as `invoiceexe.pdf`). |
| `executable-content` | The bytes are a program or a script (PE, ELF, Mach-O, shortcut, script), whatever the name says. |
| `disk-image` | The bytes are an ISO 9660 image. |
| `type-mismatch` | A name or declared type claims an image or a PDF and the bytes are something else, or a text part is really a binary. |
| `html-attachment` | An HTML page sent as an attachment, the usual fake login form. |
| `active-image` | An SVG by any reading: name, declared type or content. SVG can carry script. |
| `appended-payload` | A PNG, JPEG, GIF or WebP with a program, a script or a zip after its end or inside a metadata block. |
| `ambiguous-image` | An image whose structure cannot be followed to its end, or an SVG that cannot be read cleanly. |
| `dangerous-archive-entry` | A zip holds an entry with a dangerous extension or formatting characters in its name. |
| `nested-archive` | A zip holds another archive, whose content is not listed. |
| `encrypted-archive` | A zip or an Office file has encrypted content no scanner can read. |
| `unreadable-archive` | RAR and 7z (never listed), or a zip that cannot be read completely. |
| `ambiguous-archive` | Two extractors would unpack different files from this zip. |
| `macro` | An Office document carries a VBA project (OOXML or OLE2). |
| `ambiguous-mime` | Two mail clients could read the MIME structure, a header or an encoding differently. |
| `scan-limit` | A cap was hit (depth, parts, header size, decoded bytes, archive entries or time) and the rest was not inspected. |

Names are read the way clients and extractors read them: RFC 2231 and RFC
2047 decoding, Unicode NFKC folding with full-width dots and slashes, the
name cut at a NUL, trailing dots and spaces dropped, and zip names also as
code page 437. A finding from any reading stands. Nothing that could not be
read completely is called clean.

## The policy

```toml
[attachments]
mode = "quarantine"           # off | flag | quarantine | reject
macros = "quarantine"         # allow | flag | quarantine
encrypted_archives = "flag"   # allow | flag | quarantine
block_extensions = ["docm"]
allow_extensions = ["svg"]
```

- `flag` adds `X-Epistle-Attachment-Warning: <codes>` and delivers.
- `quarantine` delivers to the Rejects mailbox with the header.
- `reject` refuses during SMTP with `550 5.7.1 attachment type not accepted`;
  no bounce is sent.
- `macros` and `encrypted_archives` decide those two findings, never above
  `mode`. `scan-limit`, `ambiguous-mime`, `unreadable-archive` and
  `nested-archive` are flagged at least and quarantined at most: an odd
  message is not proof of a disguise, so they never reject on their own.
- An inspection that cannot run (too many at once, past its deadline)
  answers `451 4.7.1 content scan unavailable, try again later`.

Mail this server's accounts submit (SMTP after AUTH, `/api/v1/send`, JMAP)
is inspected when `mode` is `quarantine` or `reject` and
`scan_authenticated` in `[antispam]` is on (the default). A finding that would
quarantine or reject refuses the submission: `550 5.7.1` on SMTP, `422
attachment_refused` on the API, `forbiddenToSend` on JMAP. Nothing is
queued and nothing is saved to Sent.

The warning header is removed from every inbound message and every
submission before the server adds its own, so neither a remote sender nor a
local account can forge it.

`epistle attachments policy show|set|unset` edits the section, see
[cli.md](cli.md#attachments-epistle-attachments).

### Defaults

| | New install (`epistle init`) | Existing install, keys absent |
|---|---|---|
| `mode` | `quarantine` | `flag` |
| `macros` | `quarantine` | `flag` |
| `encrypted_archives` | `flag` | `flag` |
| `[antispam] clamd_on_error` | `defer` (with ClamAV) | `accept` |

Re-running `epistle init` on an existing configuration never adds these
keys, so an upgrade only adds a header until the operator decides.

## What `allow_extensions` can and cannot do

An allowed extension cancels a verdict that rests on that name, and only
when every reading of every name of the part ends in it. It never cancels:

- what the bytes say: `executable-content`, `disk-image`, `type-mismatch`,
  `appended-payload`, `macro`;
- a double extension (`a.svg.exe`), or a part whose names disagree;
- an entry inside an archive;
- an always-dangerous extension, which the configuration refuses in
  `allow_extensions`:

| Family | Extensions |
|--------|------------|
| Programs | `exe`, `scr`, `com`, `pif`, `cpl` |
| Command and script hosts | `bat`, `cmd`, `js`, `jse`, `vbs`, `vbe`, `wsf`, `wsh`, `ps1`, `ps1xml`, `psc1`, `jar` |
| HTML applications and compiled help | `hta`, `chm` |
| Installers, snap-ins, registry | `msi`, `msp`, `mst`, `msc`, `reg` |
| Shortcuts and deployments | `lnk`, `scf`, `url`, `website`, `appref-ms`, `application`, `gadget` |
| Disk images | `iso` |

`block_extensions` adds extensions to the dangerous list. An extension
cannot be in both lists.

## ClamAV is still recommended

This inspection finds files dressed up as something else. It does not know
malware: a real PDF with an exploit inside, or a macro document when
`macros = "allow"`, passes it. Keep ClamAV for known malware
(`[antispam] clamd_socket`), and set `clamd_on_error = "defer"` so a clamd
outage defers mail instead of letting it through unscanned. See
[configuration.md](configuration.md#antispam-clamd-scanner-and-bayesian-thresholds).

## Residual risks

- **Double-byte OEM code pages.** A zip entry name without the UTF-8 flag is
  read as UTF-8 and as code page 437. An extractor on a Japanese, Chinese or
  Korean Windows reads the same bytes with a double-byte code page (932,
  936, 949, 950) and may show a different name. A name crafted for that
  reading can show an extension the inspection did not see.
- **A signature by chance in image metadata.** `appended-payload` looks for
  4-byte signatures (`\x7fELF`, `PK\x03\x04`, and `MZ` with a valid PE
  header) in every image block that is not pixel data. Those bytes can
  appear by chance in a large EXIF, ICC or maker-note block, and the image
  is then treated as dangerous although it carries nothing: quarantined
  under `mode = "quarantine"`, refused under `reject`. `epistle attachments
  check` on the saved message shows the reason.
