"""TR-13: signed-line draft gate, finalize drill and workflow static checks.

Covers FR-21 / AC-10 / AC-11 / AC-14:

* TR-13.1 the scriptable gates (tag vs first_signed_version, material
  completeness, dispatch ref validation, authority selection, channel
  sequence and immutable staging) are pure functions with a CLI surface;
* TR-13.2 the workflow YAML statically keeps the publication PATCH in the
  finalize workflow only;
* TR-13.3 the exact workflow commands fail nonzero on a fixture release for
  missing materials, bad signatures, bad digests and bad Rekor entries, and
  only succeed after the independent offline verifier accepts.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import os
import subprocess
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import keysmith_trust as trust
from scripts import release_publish as publish

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
RELEASE_YML = WORKFLOWS_DIR / "release.yml"
FINALIZE_YML = WORKFLOWS_DIR / "release-finalize.yml"
TAG = "v0.7.0"
TAG_OBJECT = "b" * 40
COMMIT = "a" * 40

# ---------------------------------------------------------------------------
# Signing-ceremony reuse (full fixture pipeline from test_verify_release.py)
# ---------------------------------------------------------------------------


def _load_helper(name: str) -> types.ModuleType:
    path = REPO_ROOT / "tests" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def make_bundle(tmp_path):
    helper = _load_helper("test_verify_release.py")
    # The helper exposes its fixture as a wrapped generator function; drive
    # it manually so the complete recorded-entry ceremony stays in one place.
    return next(helper.factory.__wrapped__(tmp_path))


@pytest.fixture()
def signed_env(tmp_path, make_bundle):
    """Build one shared fixture main checkout plus per-release draft dirs."""

    repo = tmp_path / "main-checkout"
    (repo / "trust" / "root").mkdir(parents=True)
    (repo / "trust" / "revocations").mkdir(parents=True)
    (repo / "trust" / "releases").mkdir(parents=True)
    counter = {"n": 0}

    def build(
        *,
        rekor: bool = True,
        version: str = "0.7.0",
        sequence: int = 1,
        previous_index_signed=None,
        root_env=None,
        revocations_env=None,
        **overrides,
    ) -> SimpleNamespace:
        counter["n"] += 1
        label = "r{}".format(counter["n"])
        bundle = make_bundle(
            rekor=rekor,
            version=version,
            sequence=sequence,
            previous_index_signed=previous_index_signed,
            root_env=root_env,
            revocations_env=revocations_env,
            release_dir_name=label,
            **overrides,
        )
        root_path = repo / "trust" / "root" / "root.1.json"
        root_bytes = trust.canonical_json_bytes(bundle["root_env"])
        if root_path.exists():
            assert root_path.read_bytes() == root_bytes
        else:
            root_path.write_bytes(root_bytes)
        if revocations_env is not None:
            rev_path = repo / "trust" / "revocations" / "revocations.1.json"
            rev_bytes = trust.canonical_json_bytes(revocations_env)
            if rev_path.exists():
                assert rev_path.read_bytes() == rev_bytes
            else:
                rev_path.write_bytes(rev_bytes)
        state_dir = tmp_path / "{}-state".format(label)
        return SimpleNamespace(
            repo=repo,
            release_dir=bundle["release_dir"],
            trust_dir=None,
            state_dir=state_dir,
            bundle=bundle,
            tag=bundle["tag"],
        )

    return build


def _finalize_args(env: SimpleNamespace, *extra: str) -> list:
    return [
        "finalize",
        "--release-dir",
        str(env.release_dir),
        "--tag",
        env.tag,
        "--line",
        "stable",
        "--repo-root",
        str(env.repo),
        "--trust-dir",
        str(env.state_dir),
        "--json",
        *extra,
    ]


def _run_cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "release_publish.py"), *args],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )


def _offline_env() -> dict:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"))
    }
    env["PATH"] = "/usr/bin:/bin"
    return env


# ---------------------------------------------------------------------------
# TR-13.1 signed-line gate: tag vs first_signed_version
# ---------------------------------------------------------------------------


def _policy(first_signed_version):
    policy = trust.load_policy()
    policy["first_signed_version"] = first_signed_version
    return policy


def test_gate_null_policy_keeps_every_tag_on_legacy_path():
    policy = _policy(None)
    for tag in ("v0.6.0", "v0.7.0", "v1.2.3"):
        assert publish.signed_line_required(tag, policy) is False


def test_gate_threshold_matrix():
    policy = _policy("0.7.0")
    cases = {
        "v0.6.0": False,
        "v0.6.9": False,
        "v0.7.0-rc1": False,
        "v0.7.0": True,
        "v0.7.1-rc1": True,
        "v0.7.1": True,
        "v1.0.0": True,
    }
    for tag, expected in cases.items():
        assert publish.signed_line_required(tag, policy) is expected, tag


def test_gate_rejects_unknown_tags_and_lines():
    policy = _policy("0.7.0")
    for bad in (
        "0.7.0",
        "v0.7",
        "v0.7.x",
        "release-v0.7.0",
        "",
        "desktop-v0.7.0",
        "desktop-v0.7.0-beta.0",
        "desktop-v0.7.0-beta",
    ):
        with pytest.raises(publish.PublishGateError):
            publish.signed_line_required(bad, policy)
    line, core, is_pre = publish.parse_release_tag("desktop-v0.6.0-beta.2")
    assert (line, core, is_pre) == ("desktop-beta", (0, 6, 0), False)
    line, core, is_pre = publish.parse_release_tag("v0.7.0-rc1")
    assert (line, core, is_pre) == ("stable", (0, 7, 0), True)


def test_gate_desktop_beta_matrix():
    # Desktop betas are inherently pre-release artifacts: the threshold core
    # version itself is signed (no stable-style rc exemption, FR-22).
    policy = _policy("0.7.0")
    cases = {
        "desktop-v0.6.0-beta.1": False,
        "desktop-v0.6.9-beta.12": False,
        "desktop-v0.7.0-beta.1": True,
        "desktop-v0.7.0-beta.9": True,
        "desktop-v0.7.1-beta.2": True,
        "desktop-v1.0.0-beta.1": True,
    }
    for tag, expected in cases.items():
        assert publish.signed_line_required(tag, policy) is expected, tag
    assert publish.signed_line_required(
        "desktop-v0.7.0-beta.1", _policy(None)
    ) is False


def test_gate_rejects_non_string_threshold():
    with pytest.raises(publish.PublishGateError):
        publish.signed_line_required("v0.7.0", _policy(7))


def test_gate_cli_three_branches(tmp_path):
    legacy_policy = tmp_path / "legacy-policy.json"
    signed_policy = tmp_path / "signed-policy.json"
    legacy_policy.write_text(
        json.dumps(_policy(None), sort_keys=True), encoding="utf-8"
    )
    signed_policy.write_text(
        json.dumps(_policy("0.7.0"), sort_keys=True), encoding="utf-8"
    )
    legacy = _run_cli("gate", "--tag", "v0.6.0", "--policy", str(signed_policy))
    assert legacy.returncode == 0
    assert legacy.stdout.strip() == "false"
    signed = _run_cli("gate", "--tag", "v0.7.0", "--policy", str(signed_policy))
    assert signed.returncode == 0
    assert signed.stdout.strip() == "true"
    not_enabled = _run_cli("gate", "--tag", "v9.9.9", "--policy", str(legacy_policy))
    assert not_enabled.stdout.strip() == "false"
    missing = _run_cli("gate", "--tag", "v0.7.0", "--policy", str(tmp_path / "nope"))
    assert missing.returncode == 1
    assert "trust policy" in missing.stderr
    bad_tag = _run_cli("gate", "--tag", "0.7.0", "--policy", str(signed_policy))
    assert bad_tag.returncode == 1


# ---------------------------------------------------------------------------
# TR-13.1 dispatch refs and material completeness
# ---------------------------------------------------------------------------


def test_validate_dispatch_refs_matrix():
    publish.validate_dispatch_refs(TAG, TAG_OBJECT, COMMIT)
    publish.validate_dispatch_refs(
        "desktop-v0.6.0-beta.1", TAG_OBJECT, COMMIT
    )
    for bad_tag in ("0.7.0", "v0.7", "v0.7.0.1"):
        with pytest.raises(publish.PublishGateError):
            publish.validate_dispatch_refs(bad_tag, TAG_OBJECT, COMMIT)
    for bad in ("z" * 40, "A" * 40, "a" * 39, "a" * 41):
        with pytest.raises(publish.PublishGateError):
            publish.validate_dispatch_refs(TAG, bad, COMMIT)
        with pytest.raises(publish.PublishGateError):
            publish.validate_dispatch_refs(TAG, TAG_OBJECT, bad)
    with pytest.raises(publish.PublishGateError):
        publish.validate_dispatch_refs(TAG, COMMIT, COMMIT)


def test_check_refs_cli():
    ok = _run_cli("check-refs", "--tag", TAG, "--tag-object", TAG_OBJECT, "--commit", COMMIT)
    assert ok.returncode == 0
    assert ok.stdout.strip() == "refs-ok"
    bad = _run_cli("check-refs", "--tag", TAG, "--tag-object", "nope", "--commit", COMMIT)
    assert bad.returncode == 1


def test_missing_signed_materials_and_preflight(tmp_path):
    assert publish.missing_signed_materials([]) == sorted(
        publish.SIGNED_MATERIAL_NAMES
    )
    assert publish.missing_signed_materials(
        ["release-manifest.json", "release-index.json", "rekor-entry.json"]
    ) == []
    assert publish.missing_signed_materials(
        ["release-manifest.json", "release-index.json", "rekor-entry.json", "extra"]
    ) == []
    assert publish.missing_signed_materials(
        ["release-manifest.json", "rekor-entry.json"]
    ) == ["release-index.json"]

    release_dir = tmp_path / "release"
    release_dir.mkdir()
    with pytest.raises(publish.PublishGateError) as info:
        publish.preflight_materials(release_dir)
    assert "release-manifest.json" in str(info.value)

    for name in publish.SIGNED_MATERIAL_NAMES:
        (release_dir / name).write_text("not json", encoding="utf-8")
    with pytest.raises(publish.PublishGateError):
        publish.preflight_materials(release_dir)

    (release_dir / "release-manifest.json").write_text("[]", encoding="utf-8")
    (release_dir / "release-index.json").write_text("{}", encoding="utf-8")
    (release_dir / "rekor-entry.json").write_text("{}", encoding="utf-8")
    with pytest.raises(publish.PublishGateError) as info:
        publish.preflight_materials(release_dir)
    assert "release-manifest.json" in str(info.value)


def test_check_materials_cli(tmp_path):
    release_dir = tmp_path / "release"
    release_dir.mkdir()
    missing = _run_cli("check-materials", "--release-dir", str(release_dir))
    assert missing.returncode == 1
    assert "release-index.json" in missing.stderr
    for name in publish.SIGNED_MATERIAL_NAMES:
        (release_dir / name).write_text("{}", encoding="utf-8")
    ok = _run_cli("check-materials", "--release-dir", str(release_dir))
    assert ok.returncode == 0
    assert ok.stdout.strip() == "materials-ok"
    assert _run_cli("check-materials", "--release-dir", str(tmp_path / "x")).returncode == 1


# ---------------------------------------------------------------------------
# TR-13.1 manifest authority selection and channel sequence
# ---------------------------------------------------------------------------


def test_read_required_versions(signed_env):
    env = signed_env(rekor=False)
    manifest_bytes = (env.release_dir / "release-manifest.json").read_bytes()
    assert publish.read_required_versions(manifest_bytes) == (1, 0)
    with pytest.raises(publish.PublishGateError):
        publish.read_required_versions(b"{not json")
    with pytest.raises(publish.PublishGateError):
        publish.read_required_versions(
            trust.canonical_json_bytes({"signed": {}, "signatures": []})
        )


def test_authority_selection_matrix(tmp_path):
    root_dir = tmp_path / "root"
    rev_dir = tmp_path / "rev"
    root_dir.mkdir()
    rev_dir.mkdir()
    assert publish.latest_authority_version(root_dir, publish.ROOT_FILE_RE) == 0
    (root_dir / "root.1.json").write_text("{}", encoding="utf-8")
    (root_dir / "root.2.json").write_text("{}", encoding="utf-8")
    (root_dir / "root.other.json").write_text("{}", encoding="utf-8")
    assert publish.latest_authority_version(root_dir, publish.ROOT_FILE_RE) == 2

    root_file, rev_file = publish.select_authority_files(root_dir, rev_dir, 1, 0)
    assert root_file == root_dir / "root.1.json"
    assert rev_file is None

    with pytest.raises(publish.PublishGateError):
        publish.select_authority_files(root_dir, rev_dir, 3, 0)
    with pytest.raises(publish.PublishGateError):
        publish.select_authority_files(root_dir, rev_dir, 0, 0)
    with pytest.raises(publish.PublishGateError):
        publish.select_authority_files(root_dir, rev_dir, 1, 1)

    (rev_dir / "revocations.1.json").write_text("{}", encoding="utf-8")
    (rev_dir / "revocations.2.json").write_text("{}", encoding="utf-8")
    # The freshest cumulative revocations supersede the required floor.
    _root, rev_file = publish.select_authority_files(root_dir, rev_dir, 1, 1)
    assert rev_file == rev_dir / "revocations.2.json"
    _root, rev_file = publish.select_authority_files(root_dir, rev_dir, 1, 0)
    assert rev_file == rev_dir / "revocations.2.json"


def test_authority_versions_cli(tmp_path):
    root_dir = tmp_path / "root"
    rev_dir = tmp_path / "rev"
    root_dir.mkdir()
    rev_dir.mkdir()
    (root_dir / "root.1.json").write_text("{}", encoding="utf-8")
    proc = _run_cli(
        "authority-versions",
        "--root-dir",
        str(root_dir),
        "--revocations-dir",
        str(rev_dir),
    )
    assert proc.returncode == 0
    lines = dict(line.split("=", 1) for line in proc.stdout.split())
    assert lines == {"root": "1", "revocations": "0"}


def test_next_sequence_matrix(signed_env, tmp_path):
    assert publish.next_sequence(tmp_path / "absent.json", "stable") == 1
    env = signed_env(rekor=False)
    index_path = env.release_dir / "release-index.json"
    assert publish.next_sequence(index_path, "stable") == 2
    assert publish.next_sequence(index_path, "desktop-beta") == 1
    bad = tmp_path / "bad-index.json"
    bad.write_text("{broken", encoding="utf-8")
    with pytest.raises(publish.PublishGateError):
        publish.next_sequence(bad, "stable")
    with pytest.raises(publish.PublishGateError):
        publish.next_sequence(index_path, "nonsense-line")

    proc = _run_cli(
        "next-sequence",
        "--line",
        "stable",
        "--index",
        str(REPO_ROOT / "trust" / "releases" / "release-index.json"),
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "1"


def test_build_verifier_command_shape(tmp_path):
    command = publish.build_verifier_command(
        release_dir=tmp_path / "release",
        trust_dir=tmp_path / "state",
        root_file=tmp_path / "root.1.json",
        revocations_file=None,
        tag=TAG,
        line="stable",
    )
    assert command[0] == sys.executable
    assert command[1:3] == ["-m", "scripts.verify_release"]
    for flag in ("--rekor", "--json", "--root-file", "--tag", "v0.7.0", "--line"):
        assert flag in command
    assert "--revocations-file" not in command
    command = publish.build_verifier_command(
        release_dir=tmp_path / "release",
        trust_dir=tmp_path / "state",
        root_file=tmp_path / "root.1.json",
        revocations_file=tmp_path / "revocations.1.json",
        tag=TAG,
        line="stable",
    )
    assert "--revocations-file" in command


# ---------------------------------------------------------------------------
# TR-13.1 append-only channel index and immutable trust/releases/ staging
# ---------------------------------------------------------------------------


def test_stage_materials_writes_three_targets_and_refuses_overwrite(signed_env):
    env = signed_env(rekor=True)
    manifest_bytes = (env.release_dir / "release-manifest.json").read_bytes()
    index_bytes = (env.release_dir / "release-index.json").read_bytes()
    rekor_bytes = (env.release_dir / "rekor-entry.json").read_bytes()
    staged = publish.stage_signed_materials(
        repo_root=env.repo,
        tag=env.tag,
        manifest_bytes=manifest_bytes,
        index_bytes=index_bytes,
        rekor_bytes=rekor_bytes,
    )
    rels = env.repo / "trust" / "releases"
    assert staged == [
        rels / TAG / "release-manifest.json",
        rels / TAG / "rekor-entry.json",
        rels / "release-index.json",
    ]
    for path in staged:
        assert path.stat().st_mode & 0o777 == 0o644
    # Re-staging the same release is refused even with identical bytes.
    with pytest.raises(publish.PublishGateError) as info:
        publish.stage_signed_materials(
            repo_root=env.repo,
            tag=env.tag,
            manifest_bytes=manifest_bytes,
            index_bytes=index_bytes,
            rekor_bytes=rekor_bytes,
        )
    assert "already exists" in str(info.value)


def test_enforce_channel_advances_matrix(signed_env):
    first = signed_env(rekor=True, version="0.7.0", sequence=1)
    first_root = first.repo / "trust" / "root" / "root.1.json"
    first_index = (first.release_dir / "release-index.json").read_bytes()
    # First release on the channel: signature must validate against root.
    publish.enforce_channel_advances(
        new_index_bytes=first_index, old=None, root_file=first_root
    )
    second = signed_env(
        rekor=True,
        version="0.7.1",
        sequence=2,
        previous_index_signed=first.bundle["index_signed"],
    )
    second_index = (second.release_dir / "release-index.json").read_bytes()
    channel_index = first.repo / "trust" / "releases" / "release-index.json"
    channel_index.write_bytes(first_index)
    old_pair = publish.load_channel_index(channel_index)
    publish.enforce_channel_advances(
        new_index_bytes=second_index, old=old_pair, root_file=first_root
    )
    # Replaying the OLD index as a candidate cannot advance the channel.
    with pytest.raises(publish.PublishGateError) as info:
        publish.enforce_channel_advances(
            new_index_bytes=first_index, old=old_pair, root_file=first_root
        )
    assert "version must advance" in str(info.value)
    # A tampered new index fails the signature gate.
    envelope = json.loads(second_index.decode("utf-8"))
    envelope["signed"]["version"] = 99
    tampered = trust.canonical_json_bytes(envelope)
    with pytest.raises(publish.PublishGateError):
        publish.enforce_channel_advances(
            new_index_bytes=tampered, old=old_pair, root_file=first_root
        )


def test_load_channel_index_missing_and_bad(tmp_path):
    assert publish.load_channel_index(tmp_path / "nope.json") is None
    bad = tmp_path / "release-index.json"
    bad.write_text("{broken", encoding="utf-8")
    with pytest.raises(publish.PublishGateError):
        publish.load_channel_index(bad)


# ---------------------------------------------------------------------------
# TR-13.3 finalize workflow command: success and the failure drill matrix
# ---------------------------------------------------------------------------


def test_finalize_accepts_fixture_release_and_stages_offline(signed_env):
    env = signed_env(rekor=True)
    # The workflow command runs with an isolated interpreter and no proxy
    # configuration; the recorded Rekor inclusion proof is verified offline.
    env_vars = _offline_env()
    env_vars["HOME"] = str(env.repo / "home")
    proc = _run_cli(*_finalize_args(env), env=env_vars)
    assert proc.returncode == 0, proc.stderr
    record = json.loads(proc.stdout)
    assert record["ok"] is True
    assert record["tag"] == TAG
    assert record["line"] == "stable"
    assert record["sequence"] == 1
    assert record["manifest_hash"]
    assert record["root_version"] == 1
    rels = env.repo / "trust" / "releases"
    assert (rels / TAG / "release-manifest.json").read_bytes() == (
        env.release_dir / "release-manifest.json"
    ).read_bytes()
    assert (rels / TAG / "rekor-entry.json").read_bytes() == (
        env.release_dir / "rekor-entry.json"
    ).read_bytes()
    assert (rels / "release-index.json").read_bytes() == (
        env.release_dir / "release-index.json"
    ).read_bytes()
    state = trust.load_state(env.state_dir)
    accepted = state["lines"]["stable"]["accepted"]
    assert accepted["version"] == "0.7.0"
    assert accepted["manifest_hash"] == record["manifest_hash"]


def test_finalize_missing_material_fails_and_stages_nothing(signed_env):
    env = signed_env(rekor=True)
    (env.release_dir / "release-index.json").unlink()
    proc = _run_cli(*_finalize_args(env))
    assert proc.returncode == 1
    assert "release-index.json" in proc.stderr
    assert not (env.repo / "trust" / "releases" / TAG).exists()
    assert not (env.repo / "trust" / "releases" / "release-index.json").exists()


def test_finalize_bad_signature_is_rejected_at_signature_layer(signed_env):
    env = signed_env(rekor=True)
    envelope = json.loads((env.release_dir / "release-manifest.json").read_text())
    envelope["signed"]["sequence"] = 99
    (env.release_dir / "release-manifest.json").write_bytes(
        trust.canonical_json_bytes(envelope)
    )
    proc = _run_cli(*_finalize_args(env))
    assert proc.returncode == trust.EXIT_SIGNATURE
    assert "manifest" in proc.stderr or "signature" in proc.stderr
    assert not (env.repo / "trust" / "releases" / TAG).exists()


def test_finalize_bad_digest_is_rejected_at_digest_layer(signed_env):
    env = signed_env(rekor=True)
    core_name = env.bundle["names"]["core"][0]
    path = env.release_dir / core_name
    path.write_bytes(path.read_bytes() + b"tampered")
    proc = _run_cli(*_finalize_args(env))
    assert proc.returncode == trust.EXIT_DIGEST
    assert not (env.repo / "trust" / "releases" / TAG).exists()


def test_finalize_bad_rekor_entry_is_rejected_at_rekor_layer(signed_env):
    env = signed_env(rekor=True)
    entry = json.loads((env.release_dir / "rekor-entry.json").read_text())
    entry["logIndex"] = entry["logIndex"] + 1
    (env.release_dir / "rekor-entry.json").write_text(
        json.dumps(entry, sort_keys=True), encoding="utf-8"
    )
    proc = _run_cli(*_finalize_args(env))
    assert proc.returncode == trust.EXIT_REKOR
    assert not (env.repo / "trust" / "releases" / TAG).exists()


def test_finalize_requires_committed_root_authority(signed_env):
    env = signed_env(rekor=True)
    (env.repo / "trust" / "root" / "root.1.json").unlink()
    proc = _run_cli(*_finalize_args(env))
    assert proc.returncode == 1
    assert "root.1.json" in proc.stderr


def test_finalize_rejects_line_tag_mismatch(signed_env):
    env = signed_env(rekor=True)
    args = _finalize_args(env)
    args[args.index("--line") + 1] = "desktop-beta"
    proc = _run_cli(*args)
    assert proc.returncode == 1
    assert "desktop-beta" in proc.stderr


def test_finalize_second_release_extends_channel(signed_env):
    first = signed_env(version="0.7.0", sequence=1, rekor=True)
    assert _run_cli(*_finalize_args(first)).returncode == 0
    second = signed_env(
        version="0.7.1",
        sequence=2,
        rekor=True,
        previous_index_signed=first.bundle["index_signed"],
    )
    proc = _run_cli(*_finalize_args(second))
    assert proc.returncode == 0, proc.stderr
    record = json.loads(proc.stdout)
    assert record["sequence"] == 2
    rels = first.repo / "trust" / "releases"
    assert (rels / "v0.7.0" / "release-manifest.json").is_file()
    assert (rels / "v0.7.1" / "release-manifest.json").is_file()
    assert (rels / "v0.7.1" / "rekor-entry.json").is_file()
    # The channel index advanced to the second release.
    channel = trust.load_envelope(
        (rels / "release-index.json").read_bytes(), "release-index"
    )
    stable_entries = channel["signed"]["lines"]["stable"]
    assert [entry["version"] for entry in stable_entries] == ["0.7.0", "0.7.1"]


def test_finalize_rejects_index_that_rewrites_channel_history(signed_env):
    first = signed_env(version="0.7.0", sequence=1, rekor=True)
    assert _run_cli(*_finalize_args(first)).returncode == 0
    # The v0.7.1 draft is built and signed properly, but then the release
    # role is misused to seal a forked channel index: it keeps the v0.7.1
    # entry the draft ships (so the standalone verifier accepts signatures,
    # digests and Rekor), yet rewrites the already-pinned v0.7.0 slot with
    # a bogus predecessor and bumps the document version. Finalize must
    # reject that fork against the copy committed on main: a valid signature
    # alone must never rewrite pinned channel history.
    helper = _load_helper("test_verify_release.py")
    second = signed_env(
        version="0.7.1",
        sequence=2,
        rekor=True,
        previous_index_signed=first.bundle["index_signed"],
    )
    proper = trust.load_envelope(
        (second.release_dir / "release-index.json").read_bytes(), "release-index"
    )
    forged_signed = dict(proper["signed"])
    forged_entries = list(forged_signed["lines"]["stable"])
    forged_entries[0] = {
        "version": "0.6.0",
        "sequence": 1,
        "manifest_hash": helper._seed("forgotten-history").hex(),
        "rekor_uuid": None,
        "log_index": None,
    }
    forged_signed["lines"] = {
        "stable": forged_entries,
        "desktop-beta": list(forged_signed["lines"]["desktop-beta"]),
    }
    forged_signed["version"] = proper["signed"]["version"] + 1
    forged_env = trust.seal_envelope(forged_signed, [helper._seed("rel1")])
    (second.release_dir / "release-index.json").write_bytes(
        trust.canonical_json_bytes(forged_env)
    )
    proc = _run_cli(*_finalize_args(second))
    assert proc.returncode == 1
    assert "extend" in proc.stderr
    assert not (first.repo / "trust" / "releases" / "v0.7.1").exists()


def test_finalize_rerun_is_refused_by_immutability(signed_env):
    env = signed_env(rekor=True)
    assert _run_cli(*_finalize_args(env)).returncode == 0
    # Simulate a replay against a fresh channel state: even without the old
    # channel index to compare, the per-release immutable directory already
    # exists and must never be overwritten.
    (env.repo / "trust" / "releases" / "release-index.json").unlink()
    rerun_state = env.repo.parent / "rerun-state"
    args = _finalize_args(env)
    args[args.index("--trust-dir") + 1] = str(rerun_state)
    proc = _run_cli(*args)
    assert proc.returncode == 1
    assert "already exists" in proc.stderr


def test_run_finalize_in_process_pure_path(signed_env):
    env = signed_env(rekor=True)
    result = publish.run_finalize(
        release_dir=env.release_dir,
        tag=env.tag,
        line="stable",
        repo_root=env.repo,
        trust_dir=env.state_dir,
    )
    assert result["ok"] is True
    assert result["manifest_hash"]


# ---------------------------------------------------------------------------
# TR-13.2 workflow YAML static checks
# ---------------------------------------------------------------------------


def _signed_block() -> str:
    text = RELEASE_YML.read_text(encoding="utf-8")
    begin = text.index("# BEGIN SIGNED-DRAFT-BRANCH (FR-21)")
    end = text.index("# END SIGNED-DRAFT-BRANCH (FR-21)")
    return text[begin:end]


def test_release_yml_gate_and_branch_conditions_present():
    text = RELEASE_YML.read_text(encoding="utf-8")
    assert "id: gate" in text
    assert "scripts/release_publish.py gate" in text
    assert "trust/policy.json" in text
    assert "if: steps.gate.outputs.signed == 'false'" in text
    assert "if: steps.gate.outputs.signed == 'true'" in text
    # Signed builds emit the unsigned manifest, dual SBOMs and verifier and
    # derive sequence/authority versions from main instead of guessing.
    assert "--emit-trust-artifacts" in text
    assert "release_publish.py next-sequence" in text
    assert "release_publish.py authority-versions" in text
    assert "CODEX_KEYSMITH_BUILDER_INFO" in text


def test_release_yml_signed_branch_never_publishes():
    block = _signed_block()
    forbidden = ("draft=false", "make_latest", "-X PATCH", "/releases/latest")
    for token in forbidden:
        assert token not in block, token
    # It creates a draft, uploads everything, and stops deliberately.
    assert '"draft": True' in block
    assert "release-manifest.unsigned.json" in block
    assert "verify-release-{}.py" in block
    for name in (
        "release-manifest.json",
        "release-index.json",
        "rekor-entry.json",
    ):
        assert name in block  # maintainer instructions reference the trio
    assert "release-finalize" in block
    # The legacy unsigned path outside the marker keeps its behavior.
    outside = RELEASE_YML.read_text(encoding="utf-8").replace(block, "")
    assert "-F draft=false" in outside
    assert "-f make_latest=true" in outside
    assert "assert len(state[\"assets\"]) == 5" in outside
    assert "WINDOWS_FRESH_DEPLOYMENT_POLICY" in outside


def test_release_yml_uses_pinned_actions_only():
    text = RELEASE_YML.read_text(encoding="utf-8")
    assert "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7" in text
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6" in text
    assert "uses:" in text
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("uses:"):
            target = stripped[len("uses:"):].strip()
            # Local reusable-workflow references are pinned by being in-repo.
            if target.startswith("./"):
                continue
            assert "@" in line
            assert stripped != "uses: actions/checkout@v7"
            assert stripped != "uses: actions/setup-python@v6"


def test_finalize_yml_is_main_only_dispatch():
    text = FINALIZE_YML.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "  push:" not in text
    assert "  schedule:" not in text
    for input_name in ("release_tag", "expected_tag_object", "expected_commit"):
        assert input_name in text
    assert 'GITHUB_REF" != "refs/heads/main"' in text
    assert "contents: write" in text
    # No private key material, custom secrets, or draft deletion anywhere.
    assert ".key.json" not in text
    assert "secrets." not in text
    assert "-X DELETE" not in text


def test_finalize_yml_publication_is_unique_and_guarded():
    text = FINALIZE_YML.read_text(encoding="utf-8")
    assert text.count("-F draft=false") == 1
    assert text.count("-f make_latest=true") == 1
    assert text.count("release_publish.py finalize") == 1
    assert "release_publish.py check-materials" in text
    assert "release_publish.py check-refs" in text
    # Root/revocations authority is never taken from the draft download.
    assert "--root-file" not in text
    assert "--revocations-file" not in text
    assert "trust/releases" in text
    assert "git add trust/releases" in text
    assert "grep -v '^trust/releases/'" in text
    assert 'state["draft"] is True' in text
    # Pre-publication draft assets must include the signed trio.
    trio_block = text[text.index("pre_publish"):text.index("-F draft=false")]
    for name in ("release-manifest.json", "release-index.json", "rekor-entry.json"):
        assert name in trio_block


def test_finalize_yml_uses_same_pinned_actions_and_rechecks_tag():
    text = FINALIZE_YML.read_text(encoding="utf-8")
    assert "actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7" in text
    assert "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6" in text
    for line in text.splitlines():
        if "uses:" in line:
            assert "@" in line
    # Remote annotated tag is independently verified before download,
    # before the main commit and before publication.
    assert text.count("git/ref/tags/${tag}") >= 2
    assert text.count("verification.verified") >= 2


def test_release_helper_has_no_network_imports():
    source = (REPO_ROOT / "scripts" / "release_publish.py").read_text("utf-8")
    tree = ast.parse(source)
    imported = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert not (
        imported
        & {"socket", "urllib", "http", "ssl", "requests", "ftplib", "smtplib"}
    )
    # Subprocess is used only to launch the independent verifier.
    assert "subprocess.run" in source
    assert "scripts.verify_release" in source
