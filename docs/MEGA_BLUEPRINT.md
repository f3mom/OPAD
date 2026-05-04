# OPAD Mega Blueprint

OPAD Mega is an authorized Attack-Defense CTF cockpit. It is designed around the real A/D loop:

```text
observe traffic -> understand leak -> patch/filter safely -> replay checker -> deploy -> verify
write exploit -> run in scope -> extract flags -> submit with TTL/rate limits -> measure results
```

## Mega modules

- First-run setup wizard and scope guard.
- Target manager with own-team exclusion and CIDR validation.
- Service registry for HTTP/TCP/UDP/binary/gRPC/WebSocket services.
- Flag Engine: multiple regexes/plugins, `31 chars + =` preset, TTL, dedup, fake-flag protection and redaction.
- Submitter queue: HTTP JSON/form, TCP, command and plugin protocols.
- Exploit orchestration: versioning, sharding, worker manifest, canary/NOP tests and budgets.
- Defense agent: snapshots, logs, restart, patch, rollback and capture bootstrap.
- Checker lab: smoke, stateful put/get, HAR/PCAP replay and gate summaries.
- Traffic intelligence: Packmate, Tulip, Pkappa2, Shovel/Suricata, Caronte, Zeek/Arkime plans and native findings.
- Capture broker: tcpdump/pcap-broker fanout to many traffic tools.
- Defense filters: ctf_proxy, YAMPA, NGINX, iptables/nftables and Suricata rule drafts with checker-gated apply.
- Observability: Prometheus, Grafana, Loki and alert rule templates.
- CI/CD: GitHub Actions, GitLab CI and pre-commit renderers.
- IaC: Docker Compose, Ansible, Terraform, Kubernetes and Helm templates.
- RBAC, secrets, audit and safe-by-default action gates.

## Safety invariants

1. Exploit jobs must be scoped to configured target CIDRs and target list.
2. Own team is excluded by default.
3. Full flags and secrets are redacted in shared views.
4. Defense rules are rendered and staged before apply.
5. Checker-like replay must pass before patch deploy or proxy/firewall apply.
6. Traffic capture must use the game interface and exclude management ports.
7. OPAD does not add stealth, persistence or out-of-scope automation.

## Useful APIs

```text
GET  /api/mega/capabilities
GET  /api/mega/tool-matrix
GET  /api/mega/stack/docker-compose.yml?profile=mega
GET  /api/mega/farm/plan?workers=4
GET  /api/mega/worker/manifest?worker_id=worker-1
GET  /api/mega/checker/replay-plan
POST /api/mega/checker/gate-summary
GET  /api/mega/playbooks
GET  /api/mega/playbooks/traffic_to_patch.md
GET  /api/mega/observability/bundle
GET  /api/mega/iac/bundle
POST /api/mega/export/render-all
```
