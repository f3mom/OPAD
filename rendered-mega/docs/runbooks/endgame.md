# Endgame stabilization

Goal: Avoid last-minute SLA loss and submit accepted flags reliably.

## Steps

1. Freeze risky patches unless there is an active leak.
2. Keep only high-yield exploits active; pause duplicate-heavy jobs.
3. Tighten submit queue TTL and retry windows.
4. Verify disk/capture retention and stop nonessential pcaps if disk is low.
5. Export audit, exploit stats and findings after the game.

## Safety gates

- Scope must be configured.
- Checker-like replay must pass before blocking/deploying.
- Own team must be excluded from attack jobs.
- Secrets and full flags stay redacted in shared views.
