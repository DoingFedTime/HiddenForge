"""Operator-facing wording of evaluate(), and the "no address" per-service case.

These pin the exact substrings of doc["reason"] that an operator reads to
diagnose a fault, plus the fact that a service without an address must be
reported as NOT uploaded (rather than assumed uploaded).
"""
from loader import load_file, source_path

HEALTHCHECK_PATH = source_path(__file__, "healthcheck.py")

ONION = "atdorl67o6q7anir2qm3sly4expi3ywvs2ltw3wl53zezgycohzi2zqd"
OTHER = "b" * 56


def _hc():
    return load_file(HEALTHCHECK_PATH, "healthcheck")


def _reply(intro_lines=(), bootstrap=True, circuit=True):
    body = "".join(f"{line}\r\n" for line in intro_lines)
    return ("250 OK\r\n"
            f"250-status/circuit-established={1 if circuit else 0}\r\n"
            "250-status/bootstrap-phase=NOTICE BOOTSTRAP "
            f"PROGRESS={100 if bootstrap else 45} TAG=done\r\n"
            "250+circuit-status=\r\n"
            f"{body}"
            ".\r\n"
            "250 OK\r\n"
            "250 closing connection\r\n").encode()


def _intro_line(cid, addr):
    return (f"{cid} BUILT $AAAA~guard,$BBBB~middle,$CCCC~intro "
            f"PURPOSE=HS_SERVICE_INTRO HS_STATE=HSSI_ESTABLISHED REND_QUERY={addr} "
            f"TIME_CREATED=2026-09-18T00:00:00.000000")


def _hs(tmp_path, name, hostname):
    d = tmp_path / name
    d.mkdir(parents=True)
    if hostname is not None:
        d.joinpath("hostname").write_bytes(hostname.encode())
    return str(d)


def _world(hc, monkeypatch, tmp_path, reply, services=(), vanguards=True, uploaded=None):
    dirs = [_hs(tmp_path, name, hostname) for name, hostname in services]
    if uploaded is None:
        uploaded = {hostname.removesuffix(".onion") for _n, hostname in services
                    if hostname}
    monkeypatch.setattr(hc, "_query", lambda: reply)
    monkeypatch.setattr(hc, "_hidden_service_dirs", lambda: dirs)
    monkeypatch.setattr(hc, "_vanguards_running", lambda: vanguards)
    monkeypatch.setattr(hc, "_uploaded_addresses", lambda path=None: set(uploaded))


def test_the_no_service_reason_reads_as_one_operator_sentence(monkeypatch, tmp_path):
    hc = _hc()
    _world(hc, monkeypatch, tmp_path, _reply(), services=[])
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["reason"] == (
        "no onion service is configured - every mapping was dropped at startup; "
        "`hiddenforge status` lists why")


def test_the_no_service_reason_keeps_its_diagnosis_and_pointer(monkeypatch, tmp_path):
    hc = _hc()
    _world(hc, monkeypatch, tmp_path, _reply(), services=[])
    _rc, doc = hc.evaluate()
    assert "dropped at startup; `hiddenforge status` lists why" in doc["reason"]


def test_the_not_uploaded_reason_joins_names_with_a_comma_and_space(monkeypatch, tmp_path):
    hc = _hc()
    _world(hc, monkeypatch, tmp_path,
           _reply([_intro_line("1", ONION), _intro_line("2", OTHER)]),
           services=[("alpha", ONION + ".onion"), ("beta", OTHER + ".onion")],
           uploaded=set())
    rc, doc = hc.evaluate()
    assert rc == 1
    assert doc["reason"].startswith(
        "no descriptor uploaded to the network yet for: alpha, beta -")
    assert "alpha, beta" in doc["reason"]


def test_a_service_without_an_address_is_not_reported_as_uploaded(monkeypatch, tmp_path):
    hc = _hc()
    _world(hc, monkeypatch, tmp_path, _reply(),
           services=[("app", None)], uploaded={""})
    _rc, doc = hc.evaluate()
    assert doc["services"][0]["descriptor_uploaded"] is False
