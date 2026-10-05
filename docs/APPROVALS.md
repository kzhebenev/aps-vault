# Read approval (two-person rule)

Some secrets should not be readable by one person alone — a root password, a signing key, the
recovery credentials of a customer. Since 0.12 a secret can be flagged **requires approval**:
a person opens its card, asks for approval, and a second person — the **approver** — confirms
from a link. The approver has a password of their own, never sees the value, and does not
need an account: the link plus the password is all. Machines (service tokens) are not
involved — a service that holds the folder's token reads the secret as before.

## Flow

1. Settings → *Read approval* → appoint an approver (your master password + the approver's
   password, ≥12 characters, different from the master password). Hand the approver password
   to the second person.
2. Flag a secret in its editor (*Requires a second person's approval*). Its value disappears
   from the card, the history, exports and share links.
3. Reading: the card shows *Request approval* with a reason field. The request lives 15 minutes.
4. The approver receives the link (see *Notifying the approver*), opens `/approve/<token>`, sees
   the secret's name, the requester's address, the time and the reason, enters the approver
   password and chooses *Approve* or *Deny*. Wrong passwords count toward the same lock-out
   budget as the master password.
5. On approval the requester's card loads the value; the approval is bound to the requesting
   session and lasts 10 minutes. Everything is in the audit log: `approval:requested`,
   `approval:approved` / `approval:denied` (actor `approver`, with both addresses),
   `approval:approver_set`, `approval:approver_cleared`.

Removing the approver closes all flagged secrets for people (HTTP 409) until the flag is
cleared or a new approver is appointed.

## Notifying the approver

The link is delivered by an HTTP request of your choosing, so nothing in the product depends on
a particular messenger. Without a notifier the requester sees the link and passes it on
(the approver password still protects the decision).

```bash
VAULT_APPROVAL_NOTIFY_URL=https://…            # where to POST
VAULT_APPROVAL_NOTIFY_HEADERS="X-API-Key: …; Authorization: Bearer …"   # optional, "K: V; K2: V2"
VAULT_APPROVAL_NOTIFY_BODY='{"text": "{text}"}' # template; placeholders are JSON-escaped
VAULT_APPROVAL_NOTIFY_METHOD=POST
```

Placeholders: `{text}` (a ready sentence with the link), `{url}`, `{secret}` (`folder/name`),
`{reason}`, `{requester_ip}`. Private-network targets are refused unless
`VAULT_WEBHOOK_ALLOW_PRIVATE=1` (same SSRF guard as webhooks).

Examples:

| Receiver | URL | Body |
|---|---|---|
| Telegram Bot API | `https://api.telegram.org/bot<token>/sendMessage` | `{"chat_id": "<id>", "text": "{text}"}` |
| Slack incoming webhook | `https://hooks.slack.com/services/…` | `{"text": "{text}"}` |
| ntfy | `https://ntfy.sh/<topic>` | `{text}` (set `Content-Type` as you like via headers) |
| Mattermost / Rocket.Chat | incoming webhook URL | `{"text": "{text}"}` |
| A company gateway (ours) | `http://bots:8062/api/v1/notify` | `{"service": "aps-vault", "level": "crit", "text": "{text}"}` with `X-API-Key` |

The regular webhooks (`approval:requested`, `approval:approved`, `approval:denied`) fire too,
with ids only — the approve link goes exclusively to the notifier.

## Why not a second account

APS Vault has one administrator and many machines on purpose. An approver is deliberately
the smallest possible second party: a password and a link, no profile, no session, no folder
access. For real multi-user sharing with roles the right tools are Passbolt or Bitwarden.
