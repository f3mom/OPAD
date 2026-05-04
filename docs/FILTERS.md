# Defense Filter Apply-flow

OPAD does not blindly push blocking rules. The flow is:

```text
finding -> draft -> stage -> checker replay -> healthcheck -> apply or dry-run -> rollback plan
```

Supported providers:

- `ctf_proxy`: generates Python filter artifacts.
- `yampa`: generates YAMPA plugin artifacts.
- `iptables`: generates coarse nftables/iptables-style drafts for IP/port rules only.

API:

```text
POST /api/defense/rules/draft
POST /api/defense/rules/stage
POST /api/defense/rules/apply-plan
POST /api/defense/rules/apply
```

`apply` requires:

```json
{
  "rule_id": "...",
  "checker_replay_passed": true,
  "healthcheck_passed": true,
  "rollback_plan": "restore previous config and reload proxy",
  "confirm": "APPLY",
  "dry_run": true
}
```

Execution is disabled by default. To let OPAD execute an apply command, configure:

```yaml
defense_filters:
  execution:
    enabled: true
  providers:
    ctf_proxy:
      apply_command: "bash scripts/apply_ctf_proxy_rule.sh {staged_dir}"
```

Prefer L7 proxy rules for payload filtering. Use iptables/nftables only for coarse source/port controls.
