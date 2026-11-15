# Outbound provider rejections

Use `epistle delivery show ID` to read the replies for a spool ID from
`epistle delivery list`. Recognized provider failures append `; cause: `
and a fixed sentence to the delivery log's `reply` field. The SMTP code
stays at the start; remote prose is shortened as needed so the complete
field stays within 200 UTF-8 bytes. The spool and bounce DSN retain the
remote diagnostic separately. JSON listings and CSV exports include the
same annotated reply.

The basic SMTP code decides temporary versus permanent failure, and a
matching enhanced status identifies the provider cause. Different wording
or language after the enhanced code does not change the result. Unknown
codes retain their generic failure class and log reply.

| Status / marker | Fixed delivery-log cause | Decision |
|---|---|---|
| `5.7.515` (Outlook) | The sending domain does not meet the receiver's authentication requirements; run epistle verify-dns. | Bounce this message; never suppress the recipient. |
| `5.7.26` (Gmail) | The receiver rejected an unauthenticated message; run epistle verify-dns. | Bounce this message; never suppress the recipient. |
| `4.7.28` (Gmail) | The receiver limited the sending rate; run epistle check queue. | Retry after the provider pause. |
| `5.7.1` naming an IP or a list | The receiver rejected the sending IP or a blocklist entry; run epistle check dns. | Bounce this message; never suppress the recipient. Other `5.7.1` replies remain generic policy rejections. |
| Temporary `4xx` containing the exact `TSS04` marker (Yahoo) | Yahoo temporarily throttled the sender (TSS04); run epistle check queue. | Retry after the provider pause, including replies without enhanced status. A permanent reply or another marker does not select this cause. |

`epistle verify-dns` checks the sending domain's published authentication
records. `epistle check dns` checks expected DNS records and identity; it
does not query every provider's private reputation system or remove IPs
from lists. Follow the receiver's listing instructions when it names one.
`epistle check queue` shows whether outbound mail is draining.

## Provider pauses

In `[queue]`, `provider_pause_secs = 600` sets the default ten-minute
minimum. Each provider rate-limit reply waits for at least this value,
or the current ordinary backoff step if longer. Change the value and
restart the server to apply it; see [queue configuration](../configuration.md#queue).
A provider rate limit stops this attempt before another MX is tried.

The recipient domain and answering MX are held as usual. Gmail/Google
Workspace and Yahoo/AOL receiver groups also share the hold across their
other MX hosts and hosted domains. Groups come from MX hostname suffixes,
using the same mapping as [IP warm-up](warmup.md), independently of whether
warm-up is enabled. Unknown MX hosts retain destination-level holds.
Pending recipient states persist the pause, so restarting does not shorten
it. `epistle queue destinations` lists the underlying destination holds;
`epistle queue release-destination` explicitly releases one.

After the pause, a throttled receiver group admits at most one connection
at a time while pending rate-limit replies remain in the spool. Connections
already running when a rate limit arrives finish normally; further ones
wait for them to drain. Once a scan finds no pending rate-limit replies for
the group, the ordinary concurrency settings apply again.

## Bare 553 replies

A `553` without an enhanced status bounces the message. It suppresses the
recipient only when the text explicitly identifies a nonexistent mailbox
or says that the mailbox is not allowed for this/that user. An ambiguous
`mailbox name not allowed`, a sender error, or a policy-looking reply does
not suppress. Enhanced statuses still take precedence: `553 5.1.1` identifies
a bad recipient, whereas `553 5.7.26` is a sending authentication problem.
