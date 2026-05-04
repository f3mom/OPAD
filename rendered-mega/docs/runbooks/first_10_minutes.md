# First 10 minutes of A/D

Goal: Establish visibility and avoid losing SLA before deep reversing starts.

## Steps

1. Confirm scope, own team exclusion and target generation.
2. Run all service healthchecks and create baseline snapshots.
3. Start capture broker on game interface with management ports excluded.
4. Sync services and flag patterns to Packmate/traffic provider.
5. Create FLAG_INBOUND and FLAG_OUTBOUND patterns from Flag Engine.
6. Run checker-like tests and mark known good traffic for replay.
7. Run harmless connectivity probes against targets inside scope only.
8. Enable submitter dry-run and verdict parser test with organizer sample if available.

## Safety gates

- Scope must be configured.
- Checker-like replay must pass before blocking/deploying.
- Own team must be excluded from attack jobs.
- Secrets and full flags stay redacted in shared views.
