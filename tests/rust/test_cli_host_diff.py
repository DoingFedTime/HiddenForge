"""show, doctor and rotate in the image against the Python host CLI.

Same arguments on identical fixtures: the exit code, both streams and the files
left behind must match scripts/hiddenforge (`doctor --keys-only`, the form 2.x
ran inside the image). Relative --keys paths keep the two outputs comparable.
"""

import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_cli_common import (  # noqa: F401  (scratch is a fixture, used by name)
    ONION,
    OTHER_ONION,
    OTHER_PUB,
    PUB,
    Pair,
    env_for,
    needs_rust,
    norm,
    py,
    rust,
    same,
    scratch,
    service,
    write,
)

pytestmark = needs_rust

K = ["--keys", "keys"]


# ───────────────────────────────── show ─────────────────────────────────


def fx_ready(d):
    service(d / "keys", "a")


def fx_nofiles(d):
    service(d / "keys", "a", hostname=None, pub=None, secret=False)


def fx_inconsistent(d):
    service(d / "keys", "a", hostname=OTHER_ONION, pub=PUB)


def fx_published(d):
    service(d / "keys", "a", hostname=None, pub=None, secret=False)
    write(d / "keys" / "a.onion", ONION + "\n")


def fx_derived(d):
    service(d / "keys", "a", hostname=None, pub=PUB, secret=False)


def fx_mixed(d):
    service(d / "keys", "c", hostname=OTHER_ONION, pub=PUB)
    service(d / "keys", "b", hostname=None, pub=None, secret=False)
    service(d / "keys", "a")


def fx_not_ready_and_ready(d):
    service(d / "keys", "z")
    service(d / "keys", "m", hostname=None, pub=None, secret=False)


def fx_listing_noise(d):
    keys = d / "keys"
    service(keys, "b")
    service(keys, "a", hostname=OTHER_ONION)
    (keys / "Upper").mkdir()
    (keys / ".rotated-1700000000").mkdir()
    (keys / "has_underscore").mkdir()
    write(keys / "afile", "x")
    write(keys / "c.onion", ONION + "\n")
    (keys / "linked").symlink_to("b")


def fx_empty(d):
    (d / "keys").mkdir()


def fx_missing(d):
    pass


def fx_unlistable(d):
    service(d / "keys", "a")
    (d / "keys").chmod(0o311)


def fx_closed_service_published(d):
    service(d / "keys", "a")
    write(d / "keys" / "a.onion", ONION + "\n")
    (d / "keys" / "a").chmod(0o000)


def fx_closed_service(d):
    service(d / "keys", "a")
    (d / "keys" / "a").chmod(0o000)


def fx_closed_but_other_ready(d):
    service(d / "keys", "a")
    service(d / "keys", "b")
    (d / "keys" / "a").chmod(0o000)


FIXTURES = [
    fx_ready,
    fx_nofiles,
    fx_inconsistent,
    fx_published,
    fx_derived,
    fx_mixed,
    fx_not_ready_and_ready,
    fx_listing_noise,
    fx_empty,
    fx_missing,
    fx_unlistable,
    fx_closed_service_published,
    fx_closed_service,
    fx_closed_but_other_ready,
]
SHOW_ARGS = [
    [],
    ["--json"],
    ["--name", "a"],
    ["--name", "a", "--json"],
    ["--name", "nope"],
    ["--name", "nope", "--json"],
]


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda f: f.__name__)
@pytest.mark.parametrize("args", SHOW_ARGS, ids=lambda a: " ".join(a) or "list")
def test_show_matches_the_host_cli(scratch, fixture, args):
    Pair(scratch, fixture).check(["show", *K, *args])


@pytest.mark.parametrize(
    "args",
    [
        ["--name", "Bad"],
        ["--name", "../x"],
        ["--name=-x"],
        ["--name", "a" * 64],
        ["--name", "a", "--container=-x"],
        ["--container", "a b"],
        ["--container", ""],
    ],
    ids=" ".join,
)
def test_show_refuses_bad_names_and_containers_like_the_host_cli(scratch, args):
    p = Pair(scratch, fx_ready)
    r = p.check(["show", *K, *args, "--json"])
    assert r.rc == 2


@pytest.mark.parametrize(
    "value",
    [
        "-5",
        "-1x",
        "-.5",
        "-1.5",
        "-1.",
        "-.",
        "-1e5",
        "-a b",
        "-",
        "--",
        "-x",
        "--json",
        "--na",
        "-0",
        "5-",
        "- 5",
        "-5 ",
    ],
)
def test_option_values_that_start_with_a_dash_follow_argparse(scratch, value):
    """argparse takes `-5`, `-.5` and anything with a space as a value; `-1x`, `-x` are options."""
    p = Pair(scratch, fx_ready)
    r, q = p.run(["show", *K, "--name", value, "--json"])
    assert (r.rc, r.out) == (q.rc, q.out), value
    # argparse wraps the usage line to the terminal width; the error line is what counts
    assert r.err.strip().splitlines()[-1:] == q.err.strip().splitlines()[-1:], value


@pytest.mark.parametrize(
    "args",
    [
        ["setup", "-o"],
        ["setup", "--out"],
        ["setup", "-o", "--force"],
        ["setup", "--runtime", "lxc"],
        ["setup", "--onion-port", "x"],
        ["setup", "-o=a", "--force=1"],
        ["setup", "--force=1"],
    ],
)
def test_argument_errors_name_the_option_like_argparse(scratch, args):
    d = scratch / "w"
    d.mkdir()
    r = rust(args, d)
    q = py(args, d)
    assert r.rc == q.rc == 2
    assert r.err.strip().splitlines()[-1] == q.err.strip().splitlines()[-1]


def test_show_json_documents_have_the_contract_fields(scratch):
    d = scratch / "w"
    d.mkdir()
    fx_ready(d)
    r = rust(["show", *K, "--name", "a", "--json"], d)
    doc = json.loads(r.out)
    assert r.rc == 0 and doc == {
        "ok": True,
        "exit_code": 0,
        "name": "a",
        "onion": ONION,
        "source": "hostname",
        "derived_matches": True,
        "key_path": "keys/a/hs_ed25519_secret_key",
        "public_key_path": "keys/a/hs_ed25519_public_key",
        "address_path": "keys/a.onion",
        "key_dir": "keys/a",
    }
    assert r.out.endswith("\n") and r.out.count("\n") == 1


def test_show_exit_codes_are_0_4_1_2(scratch):
    codes = {}
    for fx in (fx_ready, fx_nofiles, fx_inconsistent, fx_missing, fx_mixed, fx_not_ready_and_ready):
        d = scratch / fx.__name__
        d.mkdir()
        fx(d)
        codes[fx.__name__] = rust(["show", *K, "--json"], d).rc
    assert codes == {
        "fx_ready": 0,
        "fx_nofiles": 4,
        "fx_inconsistent": 1,
        "fx_missing": 2,
        "fx_mixed": 1,
        "fx_not_ready_and_ready": 4,
    }


def test_show_address_is_the_first_sorted_service(scratch):
    d = scratch / "w"
    d.mkdir()
    service(d / "keys", "zeta", hostname=OTHER_ONION, pub=OTHER_PUB)
    service(d / "keys", "alpha")
    doc = json.loads(rust(["show", *K, "--json"], d).out)
    assert [e["name"] for e in doc["addresses"]] == ["alpha", "zeta"]
    assert doc["address"] == ONION


def test_show_default_keys_dir_is_tor_keys_or_the_environment(scratch):
    d = scratch / "w"
    d.mkdir()
    service(d / "tor-keys", "a")
    service(d / "elsewhere", "a", hostname=OTHER_ONION, pub=OTHER_PUB)
    assert rust(["show", "--name", "a"], d).out == f"a {ONION}\n"
    env = env_for(HIDDENFORGE_KEYS_DIR="elsewhere")
    assert rust(["show", "--name", "a"], d, env=env).out == f"a {OTHER_ONION}\n"
    # --keys beats the environment
    assert rust(["show", "--keys", "tor-keys", "--name", "a"], d, env=env).out == f"a {ONION}\n"


def test_show_says_why_there_is_no_address(scratch):
    """The three not-ready strings, word for word."""
    d = scratch / "w"
    d.mkdir()
    service(d / "keys", "nodir", hostname=None, pub=None, secret=False)
    (d / "keys" / "nodir").rmdir()
    service(d / "keys", "empty", hostname=None, pub=None, secret=False)
    service(d / "keys", "closed", hostname=None, pub=None, secret=False, dirmode=0)
    err = {
        n: json.loads(rust(["show", *K, "--name", n, "--json"], d).out)["error"]
        for n in ("nodir", "empty", "closed")
    }
    assert err["nodir"] == "address not generated yet (no key directory for this service)"
    assert err["empty"] == "address not generated yet (Tor has not written hostname)"
    assert err["closed"] == (
        "address not published yet: keys/closed exists but is not readable by this user, "
        "and keys/closed.onion does not exist. It appears once the service is reachable; "
        "pass --container <name> to read the address from inside the container sooner."
    )
    assert rust(["show", *K, "--name", "closed"], d).rc == 4


def test_show_inconsistent_error_names_both_addresses(scratch):
    d = scratch / "w"
    d.mkdir()
    fx_inconsistent(d)
    doc = json.loads(rust(["show", *K, "--name", "a", "--json"], d).out)
    assert doc["error"] == (
        f"a: the hostname file says {OTHER_ONION} but the public key is {ONION}. Tor serves "
        "the key's address and rewrites hostname at startup, so the file is wrong. The "
        "directory holds files from two key sets (a partial restore or copy): restore the "
        "whole directory from one backup before publishing any address."
    )
    assert doc["exit_code"] == 1 and doc["onion"] is None


# ──────────────────────────────── doctor ────────────────────────────────


def keysdir(mode):
    def build(d):
        service(d / "keys", "a")
        (d / "keys").chmod(mode)

    return build


@pytest.mark.parametrize("mode", [0o700, 0o750, 0o751, 0o755, 0o770, 0o777, 0o711, 0o311, 0o702])
@pytest.mark.parametrize("flags", [[], ["--json"]], ids=["text", "json"])
def test_doctor_volume_modes(scratch, mode, flags):
    Pair(scratch, keysdir(mode)).check(
        ["doctor", "--keys-only", *K, *flags], ["doctor", *K, *flags]
    )


def doctor_fx(dirmode=0o700, keymode=0o600, **kw):
    def build(d):
        service(d / "keys", "a", dirmode=dirmode, keymode=keymode, **kw)
        (d / "keys").chmod(0o700)

    return build


DOCTOR_FIXTURES = {
    "ok": doctor_fx(),
    "dir0750": doctor_fx(dirmode=0o750),
    "dir0755": doctor_fx(dirmode=0o755),
    "key0640": doctor_fx(keymode=0o640),
    "key0400": doctor_fx(keymode=0o400),
    "key0644": doctor_fx(keymode=0o644),
    "sealed": doctor_fx(sealed=True),
    "sealed0644": doctor_fx(sealed=True, keymode=0o644),
    "neither": doctor_fx(secret=False),
    "inconsistent": doctor_fx(hostname=OTHER_ONION),
    "consistent_hostname": doctor_fx(hostname=ONION),
    "closed": lambda d: (service(d / "keys", "a"), (d / "keys" / "a").chmod(0)),
    "missing": lambda d: None,
    "empty": lambda d: (d / "keys").mkdir(),
    "two": lambda d: (service(d / "keys", "a", keymode=0o640), service(d / "keys", "b")),
}


@pytest.mark.parametrize("name", DOCTOR_FIXTURES)
@pytest.mark.parametrize("flags", [[], ["--json"]], ids=["text", "json"])
def test_doctor_matches_keys_only_on_the_host_cli(scratch, name, flags):
    Pair(scratch, DOCTOR_FIXTURES[name]).check(
        ["doctor", "--keys-only", *K, *flags], ["doctor", *K, *flags], what=name
    )


def test_doctor_with_the_keys_only_flag_behaves_the_same(scratch):
    d = scratch / "w"
    d.mkdir()
    doctor_fx(keymode=0o640)(d)
    a = rust(["doctor", *K, "--json"], d)
    b = rust(["doctor", "--keys-only", *K, "--json"], d)
    same(a, b)
    assert a.rc == 1


def test_doctor_warnings_alone_exit_zero_and_failures_exit_one(scratch):
    d = scratch / "w"
    d.mkdir()
    doctor_fx(dirmode=0o700)(d)
    (d / "keys").chmod(0o755)  # the volume check is a warning only
    r = rust(["doctor", *K, "--json"], d)
    doc = json.loads(r.out)
    assert (r.rc, doc["ok"], doc["failures"]) == (0, True, [])
    assert doc["checks"][0] == {
        "check": "key volume is not group/world writable or world readable",
        "ok": False,
        "detail": "mode=0o755",
        "severity": "warn",
    }
    (d / "keys" / "a").chmod(0o750)
    r = rust(["doctor", *K, "--json"], d)
    assert (r.rc, json.loads(r.out)["failures"]) == (1, ["key dir a is 0700"])


def test_doctor_text_lines(scratch):
    d = scratch / "w"
    d.mkdir()
    doctor_fx(keymode=0o640)(d)
    assert rust(["doctor", *K], d).out == (
        "[ok  ] key volume is not group/world writable or world readable: mode=0o700\n"
        "[ok  ] key dir a is 0700: mode=0o700\n"
        "[FAIL] secret key a is 0600: mode=0o640\n"
    )


def test_doctor_rejects_a_bad_container_name(scratch):
    d = scratch / "w"
    d.mkdir()
    r = rust(["doctor", *K, "--container=-x"], d)
    assert r.rc == 2 and json.loads(r.out)["error"] == "invalid container name '-x'"


def test_doctor_unlistable_volume_says_so(scratch):
    d = scratch / "w"
    d.mkdir()
    fx_unlistable(d)
    doc = json.loads(rust(["doctor", *K, "--json"], d).out)
    assert doc["checks"][1] == {
        "check": "service key directories checked",
        "ok": True,
        "severity": "warn",
        "detail": "key volume is not listable (0751 by design); run `docker exec "
        "<container> hiddenforge doctor --keys-only` to verify service dir/file modes",
    }


# ──────────────────────────────── rotate ────────────────────────────────


def rotate_fx(d):
    service(d / "keys", "a")
    service(d / "keys", "b")
    write(d / "keys" / "a.onion", ONION + "\n")


@pytest.mark.parametrize("flags", [[], ["--json"]], ids=["text", "json"])
@pytest.mark.parametrize("confirm", [None, "", "rotate", "ROTATE", " ROTATE ", "ROTATE!", "yes"])
def test_rotate_confirmation(scratch, confirm, flags):
    args = ["rotate", *K, *flags] + (["--confirm", confirm] if confirm is not None else [])
    Pair(scratch, rotate_fx).check(args)


@pytest.mark.parametrize("flags", [[], ["--json"]], ids=["text", "json"])
def test_rotate_moves_the_volume_aside_and_makes_a_private_new_one(scratch, flags):
    p = Pair(scratch, rotate_fx)
    r = p.check(["rotate", *K, "--confirm", "ROTATE", *flags])
    assert r.rc == 0
    d = p.dirs[0]
    assert (d / "keys").stat().st_mode & 0o7777 == 0o700
    assert list((d / "keys").iterdir()) == []
    archived = [x for x in d.iterdir() if x.name.startswith("keys.rotated-")]
    assert len(archived) == 1 and (archived[0] / "a" / "hostname").exists()


def test_rotate_json_document(scratch):
    d = scratch / "w"
    d.mkdir()
    rotate_fx(d)
    r = rust(["rotate", *K, "--confirm", "ROTATE", "--json"], d)
    doc = json.loads(r.out)
    assert doc["archived"].startswith("keys.rotated-") and doc["moved"] is None
    assert doc["note"].startswith("A running container keeps serving the old address")
    assert (doc["ok"], doc["exit_code"], doc["keys"]) == (True, 0, "keys")


def test_rotate_picks_a_free_archive_name(scratch):
    def build(d):
        rotate_fx(d)
        now = int(time.time())
        for t in range(now - 2, now + 4):
            (d / f"keys.rotated-{t}").mkdir()

    p = Pair(scratch, build)
    r = p.check(["rotate", *K, "--confirm", "ROTATE", "--json"])
    assert norm(json.loads(r.out)["archived"]) == "keys.rotated-<T>-1"


def test_rotate_numbers_the_archive_past_a_taken_suffix(scratch):
    def build(d):
        rotate_fx(d)
        now = int(time.time())
        for t in range(now - 2, now + 4):
            (d / f"keys.rotated-{t}").mkdir()
            (d / f"keys.rotated-{t}-1").mkdir()

    p = Pair(scratch, build)
    r = p.check(["rotate", *K, "--confirm", "ROTATE", "--json"])
    assert norm(json.loads(r.out)["archived"]) == "keys.rotated-<T>-2"


def test_rotate_refuses_a_missing_or_read_only_volume(scratch):
    p = Pair(scratch, fx_missing)
    r = p.check(["rotate", *K, "--confirm", "ROTATE", "--json"])
    assert (r.rc, json.loads(r.out)["error"]) == (2, "key directory keys does not exist")

    def ro(d):
        service(d / "keys", "a")
        (d / "keys").chmod(0o500)

    (scratch / "ro").mkdir()
    p = Pair(scratch / "ro", ro)
    r = p.check(["rotate", *K, "--confirm", "ROTATE", "--json"])
    assert r.rc == 1 and json.loads(r.out)["error"] == "key directory is not writable"
    assert (p.dirs[0] / "keys" / "a").exists()


def test_rotate_default_keys_dir_comes_from_the_environment(scratch):
    d = scratch / "w"
    d.mkdir()
    rotate_fx(d)
    env = env_for(HIDDENFORGE_KEYS_DIR="keys")
    r = rust(["rotate", "--confirm", "ROTATE", "--json"], d, env=env)
    assert r.rc == 0 and json.loads(r.out)["keys"] == "keys"
    r = rust(["rotate", "--confirm", "ROTATE", "--json"], d)  # ./tor-keys does not exist
    assert (r.rc, json.loads(r.out)["keys"]) == (2, "tor-keys")
