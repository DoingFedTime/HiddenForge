"""What the supervisor asks the kernel to leave it holding.

`_drop_setup_capabilities` is a raw `capset(2)` call built by hand out of ctypes
structures. There is no library validating the struct for us, and a wrong field
fails in the one direction nobody notices: the kernel accepts the call, the
process keeps capabilities it was supposed to give up, and the log line still
says "Dropped setup capabilities".

Mutation testing found this function had NO tests at all -- all 44 of its mutants
were unreachable by the suite. Among them: `mask & 0xFFFFFFFF` becoming
`mask | 0xFFFFFFFF`, which asks the kernel for EVERY capability in the low block
instead of three; `mask & 4294967296`, which evaluates to 0 and drops
CAP_DAC_OVERRIDE, silently and permanently disabling .onion publication; and
writing the mask into `data[1]`, the capabilities 32-63 block, leaving the ones
that matter cleared. All three still print the success line.

So these tests read back the exact bytes handed to capset. The syscall is faked;
the structure is not.
"""
import ctypes

import pytest

import entrypoint as e


class _FakeLibc:
    """Stand-in for libc that records the capset arguments instead of making the call."""

    def __init__(self, rc=0, errno=0, permitted=0xFFFFFFFFFFFFFFFF, capget_rc=0):
        self._rc = rc
        self._errno = errno
        # What the runtime granted. The default is "everything", which is what a
        # container started from docker-compose.yml effectively has for the five
        # capabilities in play, so tests that do not care read as before.
        self._permitted = permitted
        self._capget_rc = capget_rc
        self.header = None
        self.data = None
        self.calls = 0
        self.capget_calls = 0

    def capget(self, header_ref, data_ref):
        self.capget_calls += 1
        # Recorded, not ignored: the version and the pid in this header decide
        # WHOSE capabilities the answer describes, and a fake that shrugs at
        # both cannot tell a correct call from one asking about another process.
        self.header = header_ref._obj if header_ref is not None else None
        self.data = data_ref._obj
        if self._capget_rc != 0:
            return self._capget_rc
        data = data_ref._obj
        data[0].permitted = self._permitted & 0xFFFFFFFF
        data[1].permitted = (self._permitted >> 32) & 0xFFFFFFFF
        return 0

    def capset(self, header_ref, data_ref):
        # byref() yields a CArgObject wrapping the original; dereference it so the
        # assertions below see the same memory the kernel would have.
        self.header = header_ref._obj
        self.data = data_ref._obj
        self.calls += 1
        if self._rc != 0:
            ctypes.set_errno(self._errno)
        return self._rc


@pytest.fixture
def libc(monkeypatch):
    """Install a fake libc and hand the test the recorder."""
    holder = {}

    def install(rc=0, errno=0, permitted=0xFFFFFFFFFFFFFFFF, capget_rc=0):
        fake = _FakeLibc(rc=rc, errno=errno, permitted=permitted,
                         capget_rc=capget_rc)
        holder["loaded"] = []

        def fake_cdll(name, use_errno):
            holder["loaded"].append((name, use_errno))
            return fake

        monkeypatch.setattr(e.ctypes, "CDLL", fake_cdll)
        holder["fake"] = fake
        return fake

    install.loaded = holder
    return install


# ─────────────────────────────────────────────────────────────────────────────
# The mask itself
# ─────────────────────────────────────────────────────────────────────────────

def test_post_setup_caps_is_exactly_the_three_capabilities_still_needed():
    """DAC_OVERRIDE to traverse the tor-owned DataDirectory and publish addresses;
    SETUID/SETGID for su-exec. CHOWN and FOWNER must be gone -- the last chown
    happens before Tor starts, and nothing chmods a file it does not own."""
    expected = (1 << e.CAP_DAC_OVERRIDE) | (1 << e.CAP_SETGID) | (1 << e.CAP_SETUID)
    assert expected == e.POST_SETUP_CAPS
    assert e.POST_SETUP_CAPS == 0xC2
    for dropped in (e.CAP_CHOWN, e.CAP_FOWNER):
        assert not e.POST_SETUP_CAPS & (1 << dropped)
    for kept in (e.CAP_DAC_OVERRIDE, e.CAP_SETGID, e.CAP_SETUID):
        assert e.POST_SETUP_CAPS & (1 << kept)


def test_capability_numbers_match_linux_capability_h():
    """These are kernel ABI constants, not project choices. A wrong number here
    silently drops or keeps the wrong capability."""
    assert (e.CAP_CHOWN, e.CAP_DAC_OVERRIDE, e.CAP_FOWNER, e.CAP_SETGID, e.CAP_SETUID) == (
        0, 1, 3, 6, 7)
    assert e._LINUX_CAPABILITY_VERSION_3 == 0x20080522


# ─────────────────────────────────────────────────────────────────────────────
# The bytes handed to capset(2)
# ─────────────────────────────────────────────────────────────────────────────

def test_capset_is_called_with_v3_header_for_this_process(libc, capsys):
    fake = libc()
    assert e._drop_setup_capabilities() is True
    assert fake.calls == 1
    assert fake.header.version == e._LINUX_CAPABILITY_VERSION_3
    assert fake.header.pid == 0          # 0 means "me"; any other pid targets another process
    assert libc.loaded["loaded"] == [("libc.so.6", True)]
    assert "Dropped setup capabilities" in capsys.readouterr().out


def test_the_mask_lands_in_the_low_block_and_the_high_block_is_cleared(libc):
    """capset takes TWO 32-bit blocks. Capabilities 0-31 live in data[0]; writing
    the mask into data[1] would ask for capabilities 32-63 and clear the ones we
    actually need."""
    fake = libc()
    e._drop_setup_capabilities()
    assert len(fake.data) == 2
    assert fake.data[0].effective == e.POST_SETUP_CAPS
    assert fake.data[0].permitted == e.POST_SETUP_CAPS
    assert fake.data[1].effective == 0
    assert fake.data[1].permitted == 0


def test_inheritable_is_cleared_in_both_blocks(libc):
    """An inheritable capability survives an execve into a file with the matching
    permitted bit. Nothing the supervisor execs should inherit anything."""
    fake = libc()
    e._drop_setup_capabilities()
    assert fake.data[0].inheritable == 0
    assert fake.data[1].inheritable == 0


def test_dropping_from_permitted_is_what_makes_it_irreversible(libc):
    """A capability absent from PERMITTED cannot be raised into EFFECTIVE again.
    Clearing only the effective set would be cosmetic."""
    fake = libc()
    e._drop_setup_capabilities()
    assert fake.data[0].permitted & (1 << e.CAP_CHOWN) == 0
    assert fake.data[0].permitted & (1 << e.CAP_FOWNER) == 0


def test_an_explicit_mask_is_honoured_not_ignored(libc):
    """The parameter exists so a caller can narrow further; a mask that was
    ignored would be worse than no parameter at all."""
    fake = libc()
    e._drop_setup_capabilities(mask=1 << e.CAP_SETUID)
    assert fake.data[0].effective == 1 << e.CAP_SETUID
    assert fake.data[0].permitted == 1 << e.CAP_SETUID


def test_an_empty_mask_really_asks_for_nothing(libc):
    fake = libc()
    e._drop_setup_capabilities(mask=0)
    assert fake.data[0].effective == 0
    assert fake.data[0].permitted == 0


# ─────────────────────────────────────────────────────────────────────────────
# Failure is reported, not hidden -- and not fatal
# ─────────────────────────────────────────────────────────────────────────────

def test_a_refused_capset_warns_with_the_errno_and_returns_false(libc, capsys):
    """Best effort by design: a kernel or runtime that refuses capset is a reason
    to log and carry on, not to take down a container whose posture is unchanged.
    But it must say so -- a silent False reads as success to the next reader."""
    import errno as errno_mod

    libc(rc=-1, errno=errno_mod.EPERM)
    assert e._drop_setup_capabilities() is False
    out = capsys.readouterr().out
    assert "could not drop setup capabilities" in out
    assert "Operation not permitted" in out
    assert "Dropped setup capabilities" not in out


# ─────────────────────────────────────────────────────────────────────────────
# What happens when the runtime granted less than POST_SETUP_CAPS
# ─────────────────────────────────────────────────────────────────────────────

ROOTLESS_PERMITTED = ((1 << e.CAP_CHOWN) | (1 << e.CAP_SETUID)
                      | (1 << e.CAP_SETGID))


def test_a_runtime_without_dac_override_still_gives_up_chown(libc, capsys):
    """Reproduced against this project's own podman-compose.yml.

    That file deliberately withholds DAC_OVERRIDE, and capset refuses a permitted
    set that is not a subset of the current one -- so asking to keep a capability
    the runtime never granted failed the whole call and dropped NOTHING. The
    container printed "could not drop setup capabilities: Operation not
    permitted" and then kept CHOWN for its entire life, on the runtime the
    deployed instance actually uses.

    Dropping what is available beats dropping nothing.
    """
    fake = libc(permitted=ROOTLESS_PERMITTED)
    assert e._drop_setup_capabilities() is True
    kept = fake.data[0].permitted
    assert not kept & (1 << e.CAP_CHOWN), "CHOWN survived the drop"
    assert not kept & (1 << e.CAP_FOWNER)
    assert kept & (1 << e.CAP_SETUID)
    assert kept & (1 << e.CAP_SETGID)
    # It cannot keep what it was never given.
    assert not kept & (1 << e.CAP_DAC_OVERRIDE)
    assert fake.data[0].effective == kept
    out = capsys.readouterr().out
    assert "DAC_OVERRIDE" in out, "the missing capability must be named"


def test_a_full_capability_set_is_unchanged_by_the_narrowing(libc):
    """The other side: on Docker, where every capability is granted, the request
    must still be exactly POST_SETUP_CAPS."""
    fake = libc()
    assert e._drop_setup_capabilities() is True
    assert fake.data[0].permitted == e.POST_SETUP_CAPS
    assert fake.data[0].effective == e.POST_SETUP_CAPS


def test_an_unreadable_capget_falls_back_to_asking_for_the_whole_mask(libc):
    """A kernel that will not answer capget is not a reason to skip the drop."""
    fake = libc(capget_rc=-1)
    assert e._drop_setup_capabilities() is True
    assert fake.data[0].permitted == e.POST_SETUP_CAPS


def test_the_narrowing_never_widens_what_was_asked_for(libc):
    """A runtime that grants MORE than POST_SETUP_CAPS must not get more kept."""
    fake = libc(permitted=0xFFFFFFFFFFFFFFFF)
    assert e._drop_setup_capabilities(mask=1 << e.CAP_SETUID) is True
    assert fake.data[0].permitted == 1 << e.CAP_SETUID


# ─────────────────────────────────────────────────────────────────────────────
# What the operator is told, exactly
# ─────────────────────────────────────────────────────────────────────────────

def test_the_note_names_every_capability_the_runtime_withheld(libc, capsys):
    """The one line an operator gets when the drop is narrowed.

    Under the shipped podman file this is the only evidence that DAC_OVERRIDE
    was never granted, so its content is the contract: the names, the separator
    and the fallback for a bit with no name all have to be right.
    """
    unknown_bit = 20
    libc(permitted=ROOTLESS_PERMITTED)
    e._drop_setup_capabilities(mask=e.POST_SETUP_CAPS | (1 << unknown_bit))
    out = capsys.readouterr().out
    assert ("Note: this runtime did not grant DAC_OVERRIDE, bit 20; "
            "dropping everything else regardless." in out), out


def test_the_drop_line_lists_what_is_retained(libc, capsys):
    """`0xc2` alone is unreadable; the names are what make the log reviewable."""
    libc()
    e._drop_setup_capabilities()
    out = capsys.readouterr().out
    assert ("Dropped setup capabilities; supervisor retains 0xc2 "
            "(DAC_OVERRIDE, SETGID, SETUID)." in out), out
    assert "Note:" not in out, "nothing was withheld, so nothing to note"


def test_dropping_everything_says_nothing_rather_than_an_empty_bracket(libc, capsys):
    libc()
    e._drop_setup_capabilities(mask=0)
    out = capsys.readouterr().out
    assert "supervisor retains 0x00 (nothing)." in out, out


def test_an_unnamed_capability_is_reported_by_its_bit_number(libc, capsys):
    libc()
    e._drop_setup_capabilities(mask=1 << 21)
    out = capsys.readouterr().out
    assert "(bit 21)." in out, out


# ─────────────────────────────────────────────────────────────────────────────
# capget itself
# ─────────────────────────────────────────────────────────────────────────────

def test_capget_is_asked_about_this_process_with_the_v3_header(libc):
    """A wrong version makes the kernel refuse and report the one it wants; a
    non-zero pid asks about a DIFFERENT process, which would narrow the drop
    against someone else's capabilities."""
    fake = libc()
    e._permitted_capabilities(fake)
    assert fake.capget_calls == 1
    assert fake.header is not None, "capget was handed no header"
    assert fake.header.version == e._LINUX_CAPABILITY_VERSION_3
    assert fake.header.pid == 0, "0 means the calling process"
    assert len(fake.data) == 2, "v3 capabilities are two 32-bit blocks"


def test_the_high_capability_block_is_read_as_the_high_32_bits(libc):
    """Capabilities above 31 live in the second block. Shifting it wrongly would
    fold them onto the low ones and narrow the drop against a set that is not
    the one the runtime granted."""
    fake = libc(permitted=(1 << 40) | (1 << 3))
    assert e._permitted_capabilities(fake) == (1 << 40) | (1 << 3)


def test_an_unreadable_capget_returns_none_rather_than_an_empty_set(libc):
    """None means "unknown" and leaves the mask alone. Returning 0 would mean
    "nothing is permitted" and would silently drop every capability."""
    fake = libc(capget_rc=-1)
    assert e._permitted_capabilities(fake) is None
