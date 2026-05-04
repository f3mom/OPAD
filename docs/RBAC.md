# OPAD RBAC

Roles:

- `admin`: full access.
- `defense`: service/patch/rule/traffic operations.
- `attack`: exploit/flag/submitter operations.
- `traffic`: traffic findings, patterns, rule drafts.
- `viewer`: read-only.

Authentication methods:

- HMAC-signed session cookie after `/api/rbac/login`.
- Bearer API token; token is only shown once and stored as SHA-256 hash.

Bootstrap:

```bash
curl -X POST http://localhost:1337/api/rbac/bootstrap \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"change-me-very-long"}'
```

Production requirements:

- Set `OPAD_SECRET_KEY` to a long random value.
- Run behind TLS or on a private management network.
- Do not expose OPAD directly to the game network.
- Keep `/data/opad.db` backed up and access-controlled.
