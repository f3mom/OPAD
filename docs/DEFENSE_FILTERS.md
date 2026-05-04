# Defense Filter Apply Flow

OPAD never applies blocking rules immediately.

Flow:

```text
traffic finding -> rule draft -> render -> checker replay -> suspicious replay -> healthcheck -> apply gate -> optional apply
```

Apply requires:

```text
1. gate.ok == true
2. request payload confirm == true
3. environment OPAD_ENABLE_DANGEROUS_APPLY=true
```

Providers:

- `ctf_proxy`: generated Python filter body.
- `yampa`: generated plugin hook body.
- `nginx`: URI/header-oriented draft rules.
- `iptables`: coarse IP/port controls only; OPAD refuses to pretend iptables can safely do app-payload filtering.

Example render:

```bash
curl -X POST http://localhost:1337/api/defense/rules/render \
  -H 'Content-Type: application/json' \
  -d '{"name":"block_traversal","service_name":"notes","pattern":"../","pattern_type":"substring","direction":"request","action":"block","provider":"ctf_proxy"}'
```
