"""Tests pinning the operator-facing messages for an unresolved backend.

A backend whose name does not resolve yet (e.g. after a host reboot, before its
container is up) is not a typo: the mapping is skipped for now, the name is
recorded as pending, and the dropped-mapping record tells the operator that the
mapping comes back by itself once the name resolves.  These tests pin the exact
wording, because those messages are what the operator reads to tell a temporary
race apart from a misconfiguration.
"""
import entrypoint as e


def test_unresolved_mapping_message_names_the_offending_mapping(
        monkeypatch, mock_dns, capsys):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:web:80")
    e.build_torrc_string()
    out = capsys.readouterr().out
    assert "Skipping mapping '80:web:80' for now:" in out
    assert "Cannot resolve 'web'" in out


def test_unresolved_mapping_note_in_dropped_record_is_operator_wording(
        monkeypatch, mock_dns):
    monkeypatch.setenv("APP_TOR_SERVICE_HOSTS", "80:web:80")
    pending, dropped = set(), []
    e.build_torrc_string(dropped=dropped, unresolved=pending)
    assert pending == {"web"}
    entry = dropped[0]
    assert entry.startswith(
        "APP_TOR_SERVICE_HOSTS: invalid mapping '80:web:80': Cannot resolve 'web'")
    assert entry.endswith(
        "Is the backend container running and on the same network?"
        " It is added automatically once the name resolves."), entry
