"""Detection tests: each signal fires on purpose-built requests, not on benign ones;
sliding windows trigger at thresholds; deterministic."""


from sentinelx.shield.detect import Detector


def _detector(clock_value):
    class Clock:
        def __init__(self, v):
            self.v = v

        def __call__(self):
            return self.v

    return Detector.load("configs/shield/signals.yaml", clock=Clock(clock_value))


def test_env_path_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/.env", {}, {}, "", False, 1000.0)
    names = {s.name for s in sigs}
    assert "sensitive_path_env" in names


def test_git_path_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/.git/config", {}, {}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"sensitive_path_git"}


def test_backup_extension_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/backup.db.bak", {}, {}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"backup_extension"}


def test_debug_route_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/debug", {}, {}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"debug_route"}


def test_sql_break_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/search", {"q": "'; DROP TABLE"}, {}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"sql_break_char"}


def test_markup_reflected_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/x", {"q": "<script>"}, {}, "<script>", False, 1000.0)
    assert {s.name for s in sigs} == {"markup_reflected"}


def test_scanner_ua_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/", {}, {"user-agent": "sqlmap/1.0"}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"scanner_ua"}


def test_oversized_param_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/x", {"q": "A" * 3000}, {}, "", False, 1000.0)
    assert {s.name for s in sigs} == {"oversized_param"}


def test_protected_no_session_signal_fires():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/admin", {}, {}, "", False, 1000.0)
    names = {s.name for s in sigs}
    assert "protected_no_session" in names


def test_benign_request_no_signals():
    d = _detector(1000.0)
    sigs = d.scan_request("c1", "GET", "/checkout", {"item": "1"}, {}, "", True, 1000.0)
    assert sigs == []


def test_high_404_window_triggers():
    clock = [1000.0]

    def now():
        return clock[0]

    d = Detector.load("configs/shield/signals.yaml", clock=now)
    for i in range(25):
        d.scan_request("c1", "GET", f"/missing{i}", {}, {}, "", False, now())
        d.record_response("c1", f"/missing{i}", 404, now())
    sigs = d.scan_request("c1", "GET", "/x", {}, {}, "", False, now())
    names = {s.name for s in sigs}
    assert "high_404_rate" in names


def test_repeated_failed_logins_window_triggers():
    clock = [1000.0]

    def now():
        return clock[0]

    d = Detector.load("configs/shield/signals.yaml", clock=now)
    for _ in range(5):
        d.scan_request("c1", "POST", "/login", {}, {}, "", False, now())
        d.record_response("c1", "/login", 401, now())
    sigs = d.scan_request("c1", "GET", "/x", {}, {}, "", False, now())
    assert {s.name for s in sigs} == {"repeated_failed_logins"}


def test_object_id_enumeration_window_triggers():
    clock = [1000.0]

    def now():
        return clock[0]

    d = Detector.load("configs/shield/signals.yaml", clock=now)
    for i in range(10):
        d.scan_request("c1", "GET", f"/order/{i}", {}, {}, "", False, now())
        d.record_response("c1", f"/order/{i}", 200, now())
    sigs = d.scan_request("c1", "GET", "/x", {}, {}, "", False, now())
    names = {s.name for s in sigs}
    assert "object_id_enumeration" in names


def test_admin_probe_window_triggers():
    clock = [1000.0]

    def now():
        return clock[0]

    d = Detector.load("configs/shield/signals.yaml", clock=now)
    for _ in range(5):
        d.scan_request("c1", "GET", "/admin/users", {}, {}, "", False, now())
        d.record_response("c1", "/admin/users", 200, now())
    sigs = d.scan_request("c1", "GET", "/x", {}, {}, "", False, now())
    assert {s.name for s in sigs} == {"admin_probe"}


def test_load_detector_from_yaml():
    d = Detector.load("configs/shield/signals.yaml")
    assert len(d.rules) == 9
    assert len(d.windows) == 5
