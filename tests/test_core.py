from opad.main import DEFAULT_CONFIG, FlagEngine, gen_targets, ip_allowed, preset_regex

def test_flag_engine_base31():
    cfg = DEFAULT_CONFIG.copy()
    cfg["flags"] = {"extractors": [{"name": "base31", "type": "regex", "regex": r"(?<![A-Z0-9=])[A-Z0-9]{31}=(?![A-Z0-9=])"}], "normalize": {"trim": True}}
    flag = "ABCDEFGHIJKLMNOPQRSTUVWXYZ12345="
    matches = FlagEngine(cfg).extract(f"hello {flag} bye")
    assert len(matches) == 1
    assert matches[0].value == flag

def test_target_exclude():
    targets = gen_targets("10.10.{team_id}.1", 1, 3, [2])
    assert [t.team_id for t in targets] == [1, 3]

def test_scope_blocks_outside():
    cfg = DEFAULT_CONFIG.copy()
    cfg["scope"] = {"allowed_cidrs": ["10.10.0.0/16"], "require_target_in_scope": True, "exclude_own_team": True}
    cfg["game"] = {"team_id": 7}
    ok, _ = ip_allowed(cfg, "8.8.8.8", 1)
    assert not ok

def test_preset_contains_length():
    assert "{31}" in preset_regex("base31_eq", "A-Z0-9", 31, "=")
