# Traffic finding to patch

Goal: Turn suspicious traffic into a safe fix without killing checker.

## Steps

1. Open stream and identify service, endpoint, method, source team and tick.
2. Run lookback for attacker-controlled IDs, tokens or filenames.
3. Create finding and attach raw stream references, not screenshots only.
4. Draft patch task and snapshot current service.
5. Patch root cause in code; avoid broad deny rules first.
6. Run checker-like tests and suspicious replay.
7. Deploy with rollback_on_failed_healthcheck.
8. Watch traffic for continued FLAG_OUTBOUND on the same service.

## Safety gates

- Scope must be configured.
- Checker-like replay must pass before blocking/deploying.
- Own team must be excluded from attack jobs.
- Secrets and full flags stay redacted in shared views.
