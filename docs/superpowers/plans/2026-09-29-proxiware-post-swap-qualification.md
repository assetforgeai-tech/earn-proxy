# Proxiware Post-Swap Qualification

## Goal

After an automatic Proxiware swap, synchronize official inventory, refresh dashboard evidence, qualify the replacement in the existing bounded batch, and continue swapping only for a conclusive live `risk` result.

## Invariants

- Replacement cooldown remains at least 60 seconds.
- Qualification concurrency remains the configured batch ceiling.
- `Allow` stops replacement; only live `Risk` may queue the next swap.
- `Pending`, `dead`, `inconclusive`, duplicate, stale, or unverified rows never mutate the provider.
- Auto-swap, browser mutation, and distribution remain fail-closed by default.

## Handoff

1. `mark_provider_applied` queues a read-only sync, including a follow-up behind a running sync.
2. Successful sync schedules immediate dashboard observation for subscriptions waiting on reconciliation.
3. Dashboard reconciliation marks the replacement `active`, `qualification='pending'`, and sets `replacement_ready_at` / `qualification_next_check_at`.
4. Qualification claims only due active replacements and keeps the configured batch limit.
5. Auto-swap workers poll durable handoff state every five seconds without probing when no work is due.

## Verification

- Focused Proxiware tests cover reconciliation, cooldown, batch claims, wake races, and guarded repeat-swap behavior.
- Run full `pytest`, `ruff check app tests scripts`, `ruff format --check app tests scripts`, `compileall`, and isolated-venv `pip check` before release.
- Do not enable auto-swap or deploy without a separately approved production canary.
