# OPAD Safe Scope

OPAD is for authorized Attack-Defense CTFs and isolated labs.

Required controls:

- `scope.allowed_cidrs` must contain only the game/lab network.
- `scope.require_target_in_scope` should stay true.
- `scope.exclude_own_team` should stay true.
- Worker clients must refuse jobs outside their assigned shard.
- Defense filters must be staged and checker-gated before apply.
- Traffic capture must not include unrelated user/Internet traffic.

OPAD intentionally avoids stealth, persistence, unauthorized scanning and any attempt to evade monitoring outside the CTF game rules.
