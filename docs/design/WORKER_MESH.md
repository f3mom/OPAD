# Worker Mesh

OPAD Mega plans a Neo/CookieFarm-style worker mesh:

- Controller stores scope, services, exploits and queue policy.
- Workers authenticate with bearer API tokens.
- Each worker receives a shard of teams/services.
- Workers refuse jobs outside assigned shard and configured CIDRs.
- Results contain stdout/stderr, extracted flags, timings and errors.
- Submitter queue handles TTL, dedup, fake-flag protection and verdicts.

The starter package renders manifests; real distributed execution should be deployed only inside the authorized CTF network.
