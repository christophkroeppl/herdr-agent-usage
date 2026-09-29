# Kilo Code contract

What this plugin reads from Kilo Code, and what it deliberately does not.

## Tested baseline

| | |
| --- | --- |
| Kilo CLI | 7.8.1 (Linux x86_64) |
| Session store | `~/.local/share/kilo/kilo.db`, SQLite, opened `mode=ro` |
| Credential store | `~/.local/share/kilo/auth.json` |
| Model catalog | `~/.cache/kilo/models.json` |
| Herdr integration | `herdr integration install kilo`, reporting `agent_session.kind=id` with a `ses_…` id |

Kilo is an OpenCode fork and kept the same on-disk shapes under its own
directories. Every path here is Kilo's own; nothing resolves into OpenCode's
store, so a machine with both CLIs installed keeps the two apart.

## Context

Read from the `part` rows of type `step-finish` for the session herdr reports.
That row carries the prompt-cache occupancy for one model step:

```
context tokens = tokens.input + tokens.cache.read + tokens.cache.write
```

Output and reasoning tokens are excluded because the next step's input already
contains them — counting them here would double-count the window. This is the
same rule the OpenCode provider applies, and the same row Kilo's own "Token
Usage" panel reads.

The provider and model ids come from the `message` row that owns the step,
because only 88 of Kilo's 9140 step rows carry their own model block. The
context window comes from `~/.cache/kilo/models.json` at
`kilo.models[modelID].limit.context`.

A step whose every counter is zero is a free-model step. It yields no usage at
all, because reading it as a 0-token context would present as an untouched
window.

### Not used

- `session.model` is populated on only some sessions; it is read for pane
  activity and cost labels, never for attribution.
- `session_context_epoch` exists in the schema but is empty in 7.8.1, so it is
  not a usable source.
- `session_message` and `session_input` (the v2 tables) are empty in 7.8.1. All
  data lives in the v1 `message`/`part` pair, which is what is read.

## Quota

One window, monthly. Kilo publishes no 5h or 7h bucket for the Kilo Gateway and
no rate limit at all — no response carries one, and none is inferred.

Source: `GET https://api.kilo.ai/api/trpc/kiloPass.getState`, the tRPC procedure
Kilo's own CLI calls for the "Kilo Pass" line in its account panel, authenticated
with the OAuth device login in `auth.json`.

| Field | Used as |
| --- | --- |
| `subscription.currentPeriodBaseCreditsUsd` | allowance |
| `subscription.currentPeriodBonusCreditsUsd` | allowance, added to the base |
| `subscription.currentPeriodUsageUsd` | spend |
| `subscription.nextBillingAt` / `nextRenewalAt` | reset time |
| `subscription.status` | must be `active`, `past_due`, or `trialing` — the CLI's own set |

Bonus credits are added to the allowance rather than reported separately: they
are granted into the same period and expire with it, so they are allowance, not
a top-up outside the window.

Both halves of the ratio are required. A missing spend would read as an
untouched period, which presents as a full allowance.

### Without a subscription

Most accounts have no Kilo Pass and pay from a shared credit balance. Kilo
reports that balance (`GET /api/profile/balance`) with **no limit attached**, so
there is no honest percentage to draw and none is drawn: the pane shows the
balance as a note and no bar. The credit pool's own percentage would degenerate
to a constant 100% on a drained account and would read as "quota exhausted",
which would be false.

`subscription: null` and a status outside the live set both degrade to that
state rather than to an error the user has to read.

### Deliberately not collected

- **Rate limits.** Kilo publishes none, in any header or field. Any RPM/TPM
  figure would be invented.
- **Lifetime spend.** `/api/user` reports `microdollars_used` and
  `total_microdollars_acquired`, and `usageAnalytics.getSummary` reports a
  different lifetime `costMicrodollars` for the same account. The two are not
  reconcilable from any published field, so neither is presented as "spend".
- **The local `/kilocode/provider-usage` route.** Kilo's running server exposes
  it and it needs no credential, but the port is ephemeral and the account's
  `codingPlans.listSubscriptions` is empty, so it returns no items here. Not
  worth a port scan.
- **`KILO_API_URL`.** Not honoured: an override would send the login to a host
  this plugin cannot vouch for.

## Identity

Attribution is by the login, not the harness. Kilo drives OpenCode Go, Anthropic,
OpenRouter and others from one CLI, so the backend recorded on the session
decides:

| Session backend | Credential in Kilo's `auth.json` | Result |
| --- | --- | --- |
| `kilo` | `{"type":"oauth"}` gateway login | the Kilo Pass window |
| `kilo` | `{"type":"api"}` gateway key, or none | no window; keeps prior state |
| `opencode-go` | any | routed to the OpenCode collector as "OpenCode Go" |
| anything else | API key | pay-as-you-go, labelled with the backend |

A gateway API key bills the same account but cannot name it, so it is never the
attribution for a reading.

Herdr captures `agent_session` at launch and never refreshes it, so a cleared or
resumed session reports an id that no longer exists. Resolution falls back to
the pane's cwd only after the reported id has failed, and only when the cwd is
non-empty — the directory match is a `LIKE`, so an empty prefix would match every
session in the store.

## Credentials

The gateway access token is read for one HTTP request and never persisted. The
cached entry stores only the resolved limits plus a hash of the token, so a
stale cache file cannot leak a login and a second account's entry is refused
rather than displayed. The refresh token is never read, and no API key value is
ever copied out of the store.
