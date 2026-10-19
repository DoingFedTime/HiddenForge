"""_name_from_status finds the Name: line wherever it is in the text.

Real /proc/<pid>/status puts Name: on the first line, so the matcher could get
away with anchoring to the start of the text; it uses re.M instead, so a status
body laid out differently is still read. These tests pin that.
"""
import entrypoint as e

# Bodies where Name: is not the first line.
STATUS_SUEXEC = (
    "su-exec\n"
    "Name:\tsu-exec\n"
    "Umask:\t0022\n"
    "State:\tS (sleeping)\n"
    "Uid:\t0\t0\t0\t0\n"
)

STATUS_TOR = (
    "tor\n"
    "Name:\ttor\n"
    "State:\tS (sleeping)\n"
    "Uid:\t100\t100\t100\t100\n"
)


def test_name_found_when_name_line_is_not_first():
    assert e._name_from_status(STATUS_SUEXEC) == "su-exec"
    assert e._name_from_status(STATUS_TOR) == "tor"


def test_name_found_when_name_line_is_the_first_line():
    assert e._name_from_status("Name:\ttor\nUid:\t100\t100\t100\t100\n") == "tor"


def test_name_found_mid_body_ignores_other_lines():
    body = "su-exec\nUmask:\t0022\nName:\tmy-tor\nUid:\t0\t0\t0\t0\n"
    assert e._name_from_status(body) == "my-tor"


def test_missing_name_line_yields_none():
    assert e._name_from_status("State:\tS (sleeping)\nUid:\t0\t0\t0\t0\n") is None
