"""Shield config tests: strict Pydantic model, upstream authorization, defaults."""

from pydantic import ValidationError

from sentinelx.shield.config import ShieldConfig, load_shield_config


def test_defaults():
    cfg = ShieldConfig(upstream="http://orders.lab.test:18080")
    assert cfg.mode == "monitor"
    assert cfg.auto_shield is False
    assert cfg.fail_open is True
    assert cfg.listen.port == 18090
    assert cfg.listen.host == "127.0.0.1"
    assert cfg.lab_mode is False
    assert cfg.kill_switch_file is None
    assert cfg.evidence_batch_interval_s == 5.0
    assert cfg.suspicious_rate_cap_per_min == 20


def test_load_from_yaml():
    cfg = load_shield_config("configs/shield/default.yaml")
    assert cfg.upstream == "http://orders.lab.test:18080"
    assert cfg.mode == "monitor"
    assert cfg.fail_open is True


def test_mode_must_be_valid():
    try:
        ShieldConfig(upstream="http://orders.lab.test:18080", mode="bad")
        raise AssertionError("expected ValidationError")
    except ValidationError:
        pass


def test_upstream_must_be_lab_target():
    try:
        ShieldConfig(upstream="http://evil.example/", listen_port=18090)
        raise AssertionError("expected ValidationError for non-lab upstream")
    except ValidationError:
        pass


def test_upstream_loopback_allowed():
    cfg = ShieldConfig(upstream="http://127.0.0.1:18080")
    assert cfg.upstream == "http://127.0.0.1:18080"


def test_extra_field_forbidden():
    try:
        ShieldConfig(upstream="http://orders.lab.test:18080", nope=1)
        raise AssertionError("expected ValidationError for extra field")
    except ValidationError:
        pass
