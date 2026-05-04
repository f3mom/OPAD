from pathlib import Path

from opad.defense.filter_providers import DefenseRuleManager
from opad.integrations.traffic_providers import PackmateProvider, Pkappa2Provider, ShovelProvider, TulipProvider


def sample_cfg():
    return {
        "services": {"shop": {"port": 8080, "protocol": "http"}},
        "traffic": {
            "providers": {
                "packmate": {"enabled": True, "url": "http://127.0.0.1:65000"},
                "tulip": {"enabled": False, "url": "http://127.0.0.1:3000"},
                "pkappa2": {"enabled": True, "url": "http://127.0.0.1:8080"},
                "shovel": {"enabled": True, "url": "http://127.0.0.1:8081"},
            }
        },
        "defense_filters": {"providers": {"ctf_proxy": {}, "yampa": {}, "iptables": {}}},
    }


def test_packmate_payloads():
    p = PackmateProvider(sample_cfg())
    assert p.services_payload()[0]["name"] == "shop"
    patterns = p.patterns_payload([{"name": "FLAG", "type": "regex", "value": "ABC", "direction": "response"}])
    assert patterns[0]["pattern"] == "ABC"


def test_pkappa2_upload_plan():
    plan = Pkappa2Provider(sample_cfg()).upload_plan("x.pcap").asdict()
    assert "/upload/x.pcap" in plan["data"]["url"]


def test_tulip_exploit_draft():
    draft = TulipProvider(sample_cfg()).exploit_draft_from_flow({"service": "shop", "method": "GET", "path": "/x"}).asdict()
    assert "@exploit.service" in draft["data"]["code"]


def test_shovel_rule_draft():
    rule = ShovelProvider(sample_cfg()).suricata_rule_draft("TEST", "../", 8080).asdict()
    assert "alert tcp" in rule["data"]["rule"]


def test_defense_rule_stage(tmp_path: Path):
    manager = DefenseRuleManager(tmp_path, sample_cfg())
    draft = manager.draft("ctf_proxy", "shop", "../")
    result = manager.stage(draft)
    assert result["ok"]
    assert Path(result["manifest"]).exists()
