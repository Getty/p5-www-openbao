# WWW-OpenBao House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

HTTP client for the OpenBao / HashiCorp Vault API. Its selling point is that it is small. Read
first: one file holds the whole client; read `_request` and its callers before adding a method
beside them.

## Agent team

| Task | Agent |
|---|---|
| Implement / refactor / debug behavior-relevant code | `www-openbao-worker` (default) |
| Write/extend tests | `www-openbao-test-writer` |
| Write/maintain POD and README | `www-openbao-doc-writer` |
| Commits, `Changes`, card → done, pre-release audit | `www-openbao-release-manager` |
| Read-only research, audit, gap analysis | `www-openbao-worker` ("read-only, change nothing") |

Behavior-relevant = runtime behaviour, the public API (`WWW::OpenBao` attributes and methods),
the `_request` seam, the croak/undef error contract, the dependency set, tests. Prose in
`README.md` and `Changes` notes are not.

## Hazards — the short form (mechanism and background: skill `www-openbao-core`)

- **Consumers.** Downstream applications wrap this client. A change to the croak/undef contract
  or to what `delete_secret` deletes lands in their error handling, not in ours — ticket
  them, never edit those repos from this one.
- **The suite is offline by construction and must stay that way.** No live OpenBao, no k8s,
  not even localhost. `_http` is lazy precisely so it can be stubbed. A test that needs a
  running server is a release blocker, not a coverage win.
- **`delete_secret` is the irreversible one.** It hits `metadata/`, removing the key and
  every version. Anything that touches it — code, POD, or a test's expectations — is
  handling a data-loss path; treat it accordingly.
- **Plain `prove -l t/` is non-recursive** — always `prove -lr t`, so subdir tests are never
  silently skipped (the suite is flat today, keep `-r` anyway).

## Perl and API specifics — reference, don't restate

Module loading, Moo patterns, dependency pinning, `[@Author::GETTY]` release metadata and POD
directives live in skills `getty-perl-core`, `getty-perl-moo`, `perl-release-dist-ini` and
`getty-perl-release-author-getty`. Repo conventions are in `www-openbao-core`; the
OpenBao/Vault HTTP API itself is in `openbao-general`. All force-loaded for `www-openbao-*`
agents.
