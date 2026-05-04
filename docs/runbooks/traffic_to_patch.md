# Traffic finding to patch

1. Open the suspicious stream in Packmate/Tulip/Pkappa2/Shovel.
2. Identify service, source team, endpoint, method, payload and tick.
3. Run lookback for attacker-controlled IDs, filenames or tokens.
4. Create an OPAD finding and attach stream references.
5. Patch root cause first. Use filter rules only as emergency mitigation.
6. Run checker-like replay and suspicious replay.
7. Deploy with snapshot and rollback enabled.
8. Verify no more `FLAG_OUTBOUND` findings for that service.
