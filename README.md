# OPAD — OP Attack&Defense

OPAD is a web cockpit for authorized Attack-Defense CTFs/labs. It combines setup wizard, target/service registry, flag extraction, submit queue, exploit orchestration, defense agent flows, safe patching, traffic-intelligence integrations, proxy rule generation, RBAC, audit logs, and plugin hooks.

## What is inside this v1 package

- First-run web setup wizard with scope guard and allowed CIDR enforcement.
- Game/tick config, target generator, service registry, and checker-like healthchecks.
- Flag Engine with `31 chars + =` preset, custom regexes, Python extractor plugins, deduplication, TTL metadata, and fake-flag-protection fields.
- Submitter adapters: HTTP JSON, HTTP form, TCP, command, Python plugin.
- Exploit runner that refuses targets outside configured CIDRs and excludes own team by default.
- Defense Agent starter for service logs/restarts/snapshots.
- Patch pipeline plans, snapshots, checker-gated deploy/rollback design.
- Traffic layer:
  - Native analyzer.
  - Packmate provider: services, patterns, streams, lookback best-effort API client.
  - Tulip provider: `/query`, `/flow`, `/to_python_request`, `/to_pwn` integration.
  - Pkappa2 provider: `/upload/<pcap>` and stream query adapters.
  - Shovel provider: Suricata rule generation and flow adapters.
  - pcap-broker capture plan generator.
- Defense filter layer:
  - ctf_proxy filter renderer.
  - YAMPA plugin renderer.
  - NGINX and iptables draft renderers.
  - Apply gate: checker replay + suspicious sample replay + service health + explicit env gate.
- RBAC:
  - admin / defense / attack / traffic / viewer roles.
  - Bootstrap admin flow.
  - PBKDF2 password hashing.
  - HMAC signed sessions.
  - API tokens stored as hashes.
  - Audit log.
- Secrets store with env-ref support and optional Fernet encryption when `cryptography` is installed.
- Production docs and examples.

## Run locally

```bash
cd OPAD
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export OPAD_DATA_DIR="$PWD/data"
export OPAD_SECRET_KEY="change-this-long-random-freaking-freak-secret"
export PYTHONPATH="$PWD/backend:$PWD/sdk"
uvicorn opad.main:app --reload --host 0.0.0.0 --port 1337
```

Open:

```text
http://localhost:1337
```

## Docker

```bash
cd OPAD
docker compose up --build
```

## RBAC bootstrap

When RBAC is enabled and no users exist, open:

```text
/login
```

Create the first admin. API tokens can be created from `/security` or with:

```bash
curl -X POST http://localhost:1337/api/rbac/tokens \
  -H 'Content-Type: application/json' \
  --cookie 'opad_session=<session-cookie>' \
  -d '{"name":"ci-runner","role":"attack"}'
```

## Safety model

OPAD is safe-by-default for CTF/lab use:

1. Exploit runner requires configured targets and CIDR scope.
2. Own team is excluded by default.
3. Defense rules are rendered as drafts first.
4. Rule apply requires checker replay and suspicious replay gates.
5. Actual rule file writing requires both `confirm=true` and `OPAD_ENABLE_DANGEROUS_APPLY=true`.
6. Traffic capture plans exclude management ports by default.
7. Secrets and flags are redacted in the UI.

## Key endpoints

```text
GET  /api/production/readiness
GET  /api/traffic/providers/status
POST /api/traffic/{provider}/sync-services
POST /api/traffic/{provider}/sync-patterns
POST /api/traffic/{provider}/streams/import
POST /api/traffic/{provider}/lookback
POST /api/tulip/to-python
POST /api/pkappa2/upload
GET  /api/capture/pcap-broker-plan-v2
POST /api/defense/rules/render
POST /api/defense/rules/gate
POST /api/defense/rules/apply
GET  /api/rbac/me
POST /api/rbac/bootstrap
POST /api/rbac/tokens
```

## Project layout

```text
backend/opad/
  main.py                  Web app + original OPAD core
  production.py            RBAC + integrations + production endpoints
  core/security.py         RBAC/session/token/password helpers
  core/secrets.py          Secret storage helpers
  core/automation.py       Event bus / hook plan
  integrations/traffic.py  Packmate/Tulip/Pkappa2/Shovel clients
  integrations/proxy.py    ctf_proxy/YAMPA/apply-gate logic
  integrations/capture.py  pcap-broker plans
agent/                     Defense agent starter
sdk/                       Exploit SDK starter
examples/                  Example config, plugins, checks, exploits
```

## Notes on external APIs

A/D traffic tools often expose different deployment-specific endpoints. OPAD therefore implements concrete clients for documented endpoints where stable, and configurable path maps for deployments that expose Packmate-like write APIs differently. When a provider cannot write directly, OPAD returns the exact payload/config/rules to apply.

## OPAD Mega Pack additions

This ZIP includes the Mega extension layer:

- `/mega` web page with capability/readiness overview.
- `/api/mega/capabilities` and `/api/mega/tool-matrix` for the full A/D feature map.
- `/api/mega/stack/docker-compose.yml?profile=mega` to render a mega deployment skeleton.
- `/api/mega/farm/plan?workers=4` for Neo/CookieFarm-style worker sharding.
- `/api/mega/worker/manifest` for authenticated worker bootstrap plans.
- `/api/mega/checker/replay-plan` for checker-aware patch/filter gates.
- `/api/mega/playbooks/*` for live-game runbooks.
- `/api/mega/observability/bundle` for Prometheus/Grafana templates.
- `/api/mega/iac/bundle` for Ansible/Terraform/Kubernetes/Helm templates.
- `/api/mega/export/render-all` to render all safe templates at once.

Generated artifacts are also included under `rendered-mega/`, plus `docker-compose.mega.yml`, `.env.mega.example`, `.github/workflows/opad-ci.yml`, `.gitlab-ci.yml`, `deploy/`, and new docs under `docs/MEGA_BLUEPRINT.md`, `docs/TOOL_MATRIX.md`, and `docs/runbooks/`.

The external traffic-tool image names in `docker-compose.mega.yml` are intentionally configurable via environment variables. Build or pin images from the upstream projects you trust, then set `PACKMATE_IMAGE`, `TULIP_IMAGE`, `PKAPPA2_IMAGE`, `SHOVEL_IMAGE`, `CARONTE_IMAGE`, `PCAP_BROKER_IMAGE`, `CTF_PROXY_IMAGE`, and `YAMPA_IMAGE`.


## OPAD Ultra

The Ultra pack adds a full web cockpit at `/ultra`. It includes pages and API actions for targets, services, flags, submitter queue, exploit runner, defense agent, patching, checker replay, traffic intelligence, capture fanout, defense filters, monitoring, automation, notifications, RBAC, secrets, incidents, backups, DevOps/IaC, plugins, lab and reports.

After starting OPAD, complete `/setup`, then open `/ultra` and run **Run web self-test**.


## OPAD Ultra Web Interface

Open `http://localhost:1337/ops` after setup. This page is the all-in-one browser control center for setup, services, flags, submitter, exploits, traffic, filters, patching, checker lab, workers, monitoring, automation, RBAC, plugins and exports. See `docs/ULTRA_WEB.md`.
