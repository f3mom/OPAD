# Emergency filter apply

Goal: Block active flag leaks while preserving checker compatibility.

## Steps

1. Prefer service-specific proxy rule over global firewall rule.
2. Render ctf_proxy/YAMPA/NGINX/nftables draft from finding.
3. Replay known-good checker-like traffic against candidate rule.
4. Replay suspicious samples and verify they are blocked or modified.
5. Stage rule, require explicit approval, then apply with fail-open if possible.
6. Monitor service health and rollback on failure.

## Safety gates

- Scope must be configured.
- Checker-like replay must pass before blocking/deploying.
- Own team must be excluded from attack jobs.
- Secrets and full flags stay redacted in shared views.
