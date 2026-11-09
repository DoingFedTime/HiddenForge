"""No key path can change the structure of what `hiddenforge setup` generates.

The key directory the operator names goes into a generated deploy.sh and into a
compose fragment. A path holding `"` once injected a command through a deploy.sh
line while every other test passed: their payloads were all newlines, which the
validator refuses anyway. This property test covers every character the
validator ACCEPTS: whatever the path, the generated shell script has the same
words as for a benign path, and the compose document has the same keys.
"""

from __future__ import annotations

import shlex

import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loader import load_file, repo_root

_HF = load_file(repo_root(__file__) / "scripts" / "hiddenforge", "hf_setup_key_paths")
_SERVICES = {"app": ["80:127.0.0.1:8080"]}
_path_chars = st.text(
    alphabet=st.characters(blacklist_categories=("Cs", "Cc"))
    | st.sampled_from(list("\"'`$\\;|&(){}[]<>*?!#~ =:/.-_")),
    min_size=1,
    max_size=40,
)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(_path_chars)
def test_no_key_path_changes_the_structure_of_the_setup_files(keys):
    try:
        _HF.validate_keys_dir(keys)
    except ValueError:
        return  # refused before it reaches any file
    for runtime in ("docker", "podman"):
        benign_sh = shlex.split(
            _HF.render_deploy_sh(_SERVICES, "/keys", "tor", runtime), comments=True
        )
        got_sh = shlex.split(_HF.render_deploy_sh(_SERVICES, keys, "tor", runtime), comments=True)
        assert len(got_sh) == len(benign_sh), (runtime, keys)
        for got, want in zip(got_sh, benign_sh, strict=True):
            assert got == want or "/keys" in want, (runtime, keys, want, got)
        benign_doc = yaml.safe_load(
            _HF.render_compose_fragment(_SERVICES, "img:1", "/keys", "tor", runtime)
        )
        got_doc = yaml.safe_load(
            _HF.render_compose_fragment(_SERVICES, "img:1", keys, "tor", runtime)
        )
        assert set(got_doc["services"]["tor"]) == set(benign_doc["services"]["tor"])
        assert got_doc["services"]["tor"]["volumes"] == [f"{keys}:/var/lib/tor/hidden_service"]
