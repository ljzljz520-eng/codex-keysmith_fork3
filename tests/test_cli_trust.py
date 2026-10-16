"""TR-12: codex-instruct local trust integration.

Covers --trust-status (TR-12.1), standalone self-verification and the
fail-closed deployment gate (TR-12.2), one-time legacy onboarding
(TR-12.3) and the no-network/no-cryptography import audit (TR-12.4).
"""

import ast
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import keysmith_trust as trust
from scripts import verify_release as verifier

REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "codex-instruct.py"
ISSUED = "2026-07-18T10:00:00Z"
ACCEPTED_VERSION = "0.7.0"
STANDALONE_NAME = "codex-instruct-v{}.py".format(ACCEPTED_VERSION)

# ---------------------------------------------------------------------------
# Module loading (codex-instruct.py is a hyphenated single file)
# ---------------------------------------------------------------------------

_spec = importlib.util.spec_from_file_location("codex_instruct_cli_trust", MODULE_PATH)
codex_instruct = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = codex_instruct
_spec.loader.exec_module(codex_instruct)


def _ceremony():
    """Signing-ceremony helpers defined in tests/test_verify_release.py."""

    helper_path = REPO_ROOT / "tests" / "test_verify_release.py"
    spec = importlib.util.spec_from_file_location("trv_cli_trust_ceremony", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Signed stable release + accepted trust directory fixture
# ---------------------------------------------------------------------------


def _build_stable_release(base: Path, *, with_revocations: bool = False) -> dict:
    ceremony = _ceremony()
    tag = "v{}".format(ACCEPTED_VERSION)
    release_dir = base / "release"
    release_dir.mkdir(parents=True)
    core = (
        "codex-keysmith-{}.zip".format(tag),
        "codex-keysmith-{}.tar.gz".format(tag),
        "codex-instruct-{}.py".format(tag),
        "codex-keysmith-scenarios-{}.bundle".format(tag),
    )
    for name in core:
        (release_dir / name).write_bytes(
            "{}:stable-content\n".format(name).encode("utf-8")
        )
    checksum_lines = [
        "{}  {}".format(
            hashlib.sha256((release_dir / name).read_bytes()).hexdigest(), name
        )
        for name in sorted(core)
    ]
    (release_dir / "SHA256SUMS").write_text(
        "\n".join(checksum_lines) + "\n", encoding="ascii"
    )
    verifier_name = "verify-release-{}.py".format(tag)
    (release_dir / verifier_name).write_text("#!/usr/bin/env python3\nstable\n")
    spdx_name = "codex-keysmith-{}-sbom.spdx.json".format(tag)
    cdx_name = "codex-keysmith-{}-sbom.cdx.json".format(tag)
    (release_dir / spdx_name).write_bytes(
        json.dumps(ceremony._valid_spdx(), sort_keys=True).encode() + b"\n"
    )
    (release_dir / cdx_name).write_bytes(
        json.dumps(ceremony._valid_cdx(), sort_keys=True).encode() + b"\n"
    )

    def record(name: str) -> dict:
        data = (release_dir / name).read_bytes()
        return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    root_env = ceremony._root_envelope()
    revocations_env = ceremony._revocations_envelope() if with_revocations else None
    manifest = {
        "_type": trust.RELEASE_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": trust.STABLE_LINE,
        "version": ACCEPTED_VERSION,
        "tag": tag,
        "sequence": 1,
        "issued_at": ISSUED,
        "source": {"repo": "local", "commit": "a" * 40, "tag_object": "b" * 40},
        "builder": {
            "workflow_name": "release.yml",
            "workflow_ref": "refs/tags/{}".format(tag),
            "workflow_sha": "c" * 40,
            "runner": "ubuntu-24.04",
            "python_version": "3.11.9",
            "node_version": "",
            "rust_version": "",
            "pyinstaller_version": "",
            "build_manifests": {},
        },
        "artifacts": {
            name: record(name) for name in [*core, "SHA256SUMS", verifier_name]
        },
        "sboms": {spdx_name: record(spdx_name), cdx_name: record(cdx_name)},
        "required_root_version": 1,
        "required_revocations_version": 0,
    }
    trust.validate_release_manifest(manifest)
    manifest_env = trust.seal_envelope(manifest, [ceremony._seed("rel1")])
    index_signed = trust.append_index_entry(
        None, manifest_env, issued_at=ISSUED
    )
    index_env = trust.seal_envelope(index_signed, [ceremony._seed("rel1")])

    (release_dir / verifier.ROOT_BUNDLE_NAME).write_bytes(
        trust.canonical_json_bytes(root_env)
    )
    if revocations_env is not None:
        (release_dir / verifier.REVOCATIONS_BUNDLE_NAME).write_bytes(
            trust.canonical_json_bytes(revocations_env)
        )
    (release_dir / verifier.SIGNED_MANIFEST_NAME).write_bytes(
        trust.canonical_json_bytes(manifest_env)
    )
    (release_dir / verifier.INDEX_NAME).write_bytes(
        trust.canonical_json_bytes(index_env)
    )
    return {
        "release_dir": release_dir,
        "root_env": root_env,
        "revocations_env": revocations_env,
        "manifest": manifest,
        "manifest_env": manifest_env,
    }


@pytest.fixture()
def accepted(tmp_path):
    """A trust directory that has TOFU-accepted signed stable v0.7.0."""

    bundle = _build_stable_release(tmp_path / "inputs")
    trust_dir = tmp_path / "trust"
    result = verifier.verify_release(
        release_dir=bundle["release_dir"], trust_dir=trust_dir
    )
    bundle["trust_dir"] = trust_dir
    bundle["result"] = result
    return bundle


def _materialize_standalone(accepted_bundle: dict, dest_dir: Path, *, name=None):
    name = name or STANDALONE_NAME
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / name
    path.write_bytes(
        (accepted_bundle["release_dir"] / STANDALONE_NAME).read_bytes()
    )
    return path


def _write_empty_state(trust_dir: Path) -> None:
    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "state.json").write_text(
        json.dumps(trust.empty_state(), sort_keys=True), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# TR-12.1 --trust-status
# ---------------------------------------------------------------------------


def test_trust_status_reports_root_watermarks_and_audit(accepted):
    status = codex_instruct.read_trust_status(accepted["trust_dir"])

    assert status["initialized"] is True
    assert status["state_error"] is None
    assert status["root_error"] is None
    assert status["revocations_error"] is None
    assert status["audit_error"] is None

    state = status["state"]
    assert set(state["lines"]) == {"stable", "desktop-beta"}
    stable_accepted = state["lines"]["stable"]["accepted"]
    assert stable_accepted["version"] == ACCEPTED_VERSION
    assert stable_accepted["sequence"] == 1
    assert stable_accepted["manifest_hash"] == accepted["result"]["manifest_hash"]
    assert state["lines"]["desktop-beta"]["accepted"] is None

    root = status["root"]
    assert root["version"] == 1
    assert root["expired"] is False
    assert root["fingerprint"] == trust.root_fingerprint(
        accepted["root_env"]["signed"]
    )
    # No revocations bundle was shipped with this release.
    assert status["revocations"] is None

    audit_tail = status["audit_tail"]
    assert audit_tail and all(isinstance(entry, dict) for entry in audit_tail)
    assert {"tofu", "root-tofu"} <= {entry["event"] for entry in audit_tail}


def test_trust_status_reports_cached_revocations(tmp_path):
    bundle = _build_stable_release(tmp_path / "inputs", with_revocations=True)
    trust_dir = tmp_path / "trust"
    verifier.verify_release(release_dir=bundle["release_dir"], trust_dir=trust_dir)

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["revocations_error"] is None
    revocations = status["revocations"]
    assert revocations["version"] == 1
    assert revocations["expires"] == bundle["revocations_env"]["signed"]["expires"]
    assert isinstance(revocations["expired"], bool)


def test_trust_status_malformed_state_json_is_fail_closed(tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "state.json").write_text("{not json", encoding="utf-8")

    status = codex_instruct.read_trust_status(trust_dir)
    assert status["initialized"] is False
    assert status["state_error"]

    rc = codex_instruct.run_trust_status_command(trust_dir, [])
    assert rc == 1


def test_trust_status_bad_state_schema_is_fail_closed(tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "state.json").write_text(
        json.dumps({"schema_version": 1, "lines": {}}), encoding="utf-8"
    )

    status = codex_instruct.read_trust_status(trust_dir)
    assert status["state_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


def test_trust_status_broken_audit_is_fail_closed(tmp_path):
    trust_dir = tmp_path / "trust"
    _write_empty_state(trust_dir)
    (trust_dir / "audit.jsonl").write_text('{"event": "tofu"}\n\n', encoding="utf-8")

    status = codex_instruct.read_trust_status(trust_dir)
    assert status["audit_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


def test_trust_status_missing_or_empty_dir_is_informational(tmp_path, capsys):
    missing = tmp_path / "missing-trust"
    status = codex_instruct.read_trust_status(missing)
    assert status["initialized"] is False
    assert status["state"] is None
    assert codex_instruct.run_trust_status_command(missing, []) == 0

    empty = tmp_path / "empty-trust"
    empty.mkdir()
    assert codex_instruct.run_trust_status_command(empty, []) == 0
    output = capsys.readouterr().out
    assert "verify-release" in output


def test_trust_status_subprocess_reports_accepted_release(accepted, tmp_path):
    env = dict(os.environ)
    env["CODEX_KEYSMITH_TRUST_DIR"] = str(accepted["trust_dir"])
    completed = subprocess.run(
        [
            sys.executable,
            str(MODULE_PATH),
            "--trust-status",
            "--codex-dir",
            str(tmp_path / "no-such-codex-dir"),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "accepted {}".format(ACCEPTED_VERSION) in completed.stdout
    assert "fingerprint" in completed.stdout
    assert "line desktop-beta: no accepted release" in completed.stdout


# ---------------------------------------------------------------------------
# TR-12.2 standalone self-verification
# ---------------------------------------------------------------------------


def test_standalone_self_check_verified(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "verified"
    assert verdict["blocked"] is False
    assert verdict["version"] == ACCEPTED_VERSION
    assert verdict["artifact"] == STANDALONE_NAME
    assert verdict["manifest_hash"] == accepted["result"]["manifest_hash"]


def test_standalone_self_check_hash_mismatch_blocks(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    expected = accepted["manifest"]["artifacts"][STANDALONE_NAME]
    with standalone.open("ab") as handle:
        handle.write(b"tampered bytes\n")

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "hash-mismatch"
    assert verdict["blocked"] is True
    assert verdict["expected_sha256"] == expected["sha256"]
    assert verdict["expected_size"] == expected["size"]
    assert verdict["actual_sha256"] != expected["sha256"]
    assert verdict["actual_size"] > expected["size"]


def test_standalone_self_check_missing_record_blocks(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    manifest_hash = accepted["result"]["manifest_hash"]
    (accepted["trust_dir"] / "manifests" / "{}.json".format(manifest_hash)).unlink()

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "record-unavailable"
    assert verdict["blocked"] is True


def test_standalone_self_check_corrupt_manifest_envelope_blocks(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    manifest_hash = accepted["result"]["manifest_hash"]
    manifest_cache = accepted["trust_dir"] / "manifests" / "{}.json".format(
        manifest_hash
    )
    envelope = json.loads(manifest_cache.read_text(encoding="utf-8"))
    envelope["signed"]["version"] = "9.9.9"
    manifest_cache.write_text(json.dumps(envelope), encoding="utf-8")

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "envelope-invalid"
    assert verdict["blocked"] is True


def test_standalone_self_check_source_tree_is_not_applicable(accepted):
    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=MODULE_PATH
    )

    assert verdict["verdict"] == "not-applicable"
    assert verdict["form"] == "source-tree"
    assert verdict["blocked"] is False


def test_standalone_self_check_unaccepted_version_informational(accepted, tmp_path):
    standalone = _materialize_standalone(
        accepted, tmp_path / "bin", name="codex-instruct-v0.8.0.py"
    )

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "no-record-for-version"
    assert verdict["blocked"] is False
    assert verdict["accepted_version"] == ACCEPTED_VERSION


def test_standalone_self_check_without_trust_record_informational(tmp_path):
    standalone = tmp_path / STANDALONE_NAME
    standalone.write_bytes(b"brand new standalone\n")

    missing = tmp_path / "missing-trust"
    verdict = codex_instruct.standalone_self_verification(missing, script_path=standalone)
    assert verdict == {
        "verdict": "no-trust-record",
        "blocked": False,
        "form": "standalone",
        "version": ACCEPTED_VERSION,
    }

    empty_trust = tmp_path / "empty-trust"
    _write_empty_state(empty_trust)
    verdict = codex_instruct.standalone_self_verification(
        empty_trust, script_path=standalone
    )
    assert verdict["verdict"] == "no-trust-record"
    assert verdict["blocked"] is False


def test_deployment_gate_blocks_tampered_standalone_subprocess(accepted, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    # The copy is the real (much larger) codex-instruct source, so it cannot
    # match the v0.7.0 artifact digest pinned by the accepted manifest.
    standalone = bin_dir / STANDALONE_NAME
    standalone.write_bytes(MODULE_PATH.read_bytes())
    codex_dir = tmp_path / "codex"
    codex_dir.mkdir()

    env = dict(os.environ)
    env["CODEX_KEYSMITH_TRUST_DIR"] = str(accepted["trust_dir"])
    completed = subprocess.run(
        [
            sys.executable,
            str(standalone),
            "--reactivate",
            "--yes",
            "--codex-dir",
            str(codex_dir),
        ],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    combined = completed.stdout + completed.stderr
    assert "standalone" in combined.lower()
    # Both localized messages name the mismatched digest field.
    assert "sha256" in combined


def test_read_only_command_unaffected_by_standalone_mismatch(accepted, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    standalone = bin_dir / STANDALONE_NAME
    standalone.write_bytes(MODULE_PATH.read_bytes())

    env = dict(os.environ)
    env["CODEX_KEYSMITH_TRUST_DIR"] = str(accepted["trust_dir"])
    completed = subprocess.run(
        [sys.executable, str(standalone), "--trust-status"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "hash-mismatch" in completed.stdout


def test_accepted_manifest_cache_roundtrip_and_type_guard(accepted, tmp_path):
    trust_dir = accepted["trust_dir"]
    manifest_hash = accepted["result"]["manifest_hash"]
    cache_path = trust_dir / "manifests" / "{}.json".format(manifest_hash)
    assert cache_path.is_file()

    envelope = trust.read_accepted_manifest(trust_dir, manifest_hash)
    assert envelope["signed"] == accepted["manifest"]
    assert trust.read_accepted_manifest(trust_dir, "a" * 64) is None

    wrong_type = json.loads(json.dumps(accepted["manifest_env"]))
    wrong_type["signed"]["_type"] = trust.ROOT_TYPE
    other_dir = tmp_path / "other-trust"
    with pytest.raises(trust.StateError):
        trust.write_accepted_manifest(other_dir, wrong_type)


# ---------------------------------------------------------------------------
# TR-12.3 one-time legacy onboarding
# ---------------------------------------------------------------------------


def _write_deployment_manifest(codex_dir: Path, tool_version: str) -> None:
    codex_dir.mkdir(parents=True, exist_ok=True)
    (codex_dir / codex_instruct.MANIFEST_FILENAME).write_text(
        json.dumps({"tool_version": tool_version}), encoding="utf-8"
    )


def test_legacy_onboarding_records_one_audit_per_version(tmp_path):
    trust_dir = tmp_path / "trust"
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, "0.5.0")

    plan = codex_instruct.legacy_onboarding_plan(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )
    assert plan["status"] == "needed"
    assert plan["legacy"] == [
        {"codex_dir": str(codex_dir), "version": "0.5.0"}
    ]

    result = codex_instruct.perform_legacy_onboarding(
        trust_dir,
        [codex_dir],
        codex_instruct.VERSION,
        now_iso="2026-07-01T00:00:00Z",
    )
    assert result["status"] == "onboarded"
    assert result["entries"] == [
        {
            "time": "2026-07-01T00:00:00Z",
            "event": "legacy-onboarding",
            "line": "stable",
            "legacy_version": "0.5.0",
            "to_version": codex_instruct.VERSION,
            "source": "--trust-onboard-legacy",
        }
    ]

    audit_path = trust_dir / "audit.jsonl"
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "legacy-onboarding"
    assert stat.S_IMODE(audit_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(trust_dir.stat().st_mode) == 0o700

    # Idempotent: a second run detects the existing audit event.
    second_plan = codex_instruct.legacy_onboarding_plan(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )
    assert second_plan["status"] == "already-onboarded"
    second = codex_instruct.perform_legacy_onboarding(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )
    assert second["status"] == "already-onboarded"
    assert len(audit_path.read_text(encoding="utf-8").splitlines()) == 1


def test_legacy_onboarding_not_needed_after_signed_acceptance(accepted, tmp_path):
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, "0.5.0")

    plan = codex_instruct.legacy_onboarding_plan(
        accepted["trust_dir"], [codex_dir], codex_instruct.VERSION
    )
    assert plan["status"] == "signed-already"
    assert codex_instruct.run_legacy_onboarding_command(
        accepted["trust_dir"], [codex_dir]
    ) == 0
    audit_lines = (accepted["trust_dir"] / "audit.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert not any(
        json.loads(line).get("event") == "legacy-onboarding" for line in audit_lines
    )


def test_legacy_onboarding_none_found_for_equal_or_newer_versions(tmp_path):
    trust_dir = tmp_path / "trust"
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, codex_instruct.VERSION)
    plan = codex_instruct.legacy_onboarding_plan(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )
    assert plan["status"] == "none-found"

    _write_deployment_manifest(codex_dir, "9.9.9")
    plan = codex_instruct.legacy_onboarding_plan(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )
    assert plan["status"] == "none-found"

    # Missing / malformed deployment manifests are ignored best-effort.
    bare_dir = tmp_path / "bare"
    bare_dir.mkdir()
    assert codex_instruct.read_deployment_tool_version(bare_dir) is None
    assert (
        codex_instruct.run_legacy_onboarding_command(trust_dir, [bare_dir, codex_dir])
        == 1
    )


def test_legacy_onboarding_deduplicates_versions_across_dirs(tmp_path):
    trust_dir = tmp_path / "trust"
    first = tmp_path / "codex-a"
    second = tmp_path / "codex-b"
    third = tmp_path / "codex-c"
    _write_deployment_manifest(first, "0.5.0")
    _write_deployment_manifest(second, "0.4.0")
    _write_deployment_manifest(third, "0.5.0")

    result = codex_instruct.perform_legacy_onboarding(
        trust_dir,
        [first, second, third],
        codex_instruct.VERSION,
        now_iso="2026-07-01T00:00:00Z",
    )

    assert result["status"] == "onboarded"
    assert [entry["legacy_version"] for entry in result["entries"]] == [
        "0.5.0",
        "0.4.0",
    ]


def test_legacy_onboarding_cli_is_one_time_subprocess(tmp_path):
    trust_dir = tmp_path / "trust"
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, "0.5.0")

    env = dict(os.environ)
    env["CODEX_KEYSMITH_TRUST_DIR"] = str(trust_dir)
    args = [
        sys.executable,
        str(MODULE_PATH),
        "--trust-onboard-legacy",
        "--codex-dir",
        str(codex_dir),
    ]
    first = subprocess.run(
        args, env=env, capture_output=True, text=True, check=False
    )
    assert first.returncode == 0, first.stderr
    assert "legacy-onboarding" in first.stdout

    second = subprocess.run(
        args, env=env, capture_output=True, text=True, check=False
    )
    assert second.returncode == 0, second.stderr
    lines = (trust_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1


# ---------------------------------------------------------------------------
# TR-12.5 fail-closed branch matrix and in-process CLI wiring
# ---------------------------------------------------------------------------

_TRUST_LINES = ("stable", "desktop-beta")


def _empty_line_state():
    return {"accepted": None, "rekor_tree_size": 0, "security_exceptions": []}


def _valid_state_document():
    return {
        "schema_version": 1,
        "lines": {line: _empty_line_state() for line in _TRUST_LINES},
    }


def _accepted_record_doc(**overrides):
    record = {
        "version": "0.7.0",
        "sequence": 1,
        "manifest_hash": "a" * 64,
        "accepted_at": "2026-07-01T00:00:00Z",
    }
    record.update(overrides)
    return record


def _state_document_with_stable(stable_line):
    document = _valid_state_document()
    document["lines"]["stable"] = stable_line
    return document


def _line_with(**overrides):
    line = _empty_line_state()
    line.update(overrides)
    return line


def _json_bytes(value):
    return json.dumps(value).encode("utf-8")


def _write_state_raw(trust_dir: Path, payload: bytes) -> None:
    trust_dir.mkdir(parents=True, exist_ok=True)
    (trust_dir / "state.json").write_bytes(payload)


def _exception_doc(version="0.6.0", manifest_hash="b" * 64):
    return {
        "version": version,
        "manifest_hash": manifest_hash,
        "reason": "incident-42",
        "granted_at": "2026-06-01T00:00:00Z",
    }


_MALFORMED_STATE_PAYLOADS = [
    b"\xff",  # not UTF-8
    b"123",  # valid JSON but not an object
    _json_bytes({"schema_version": 1, "lines": {}, "extra": True}),
    _json_bytes(
        {
            "schema_version": 2,
            "lines": {line: _empty_line_state() for line in _TRUST_LINES},
        }
    ),
    _json_bytes(_state_document_with_stable({})),
    _json_bytes(
        _state_document_with_stable(_line_with(accepted={"version": "0.7.0"}))
    ),
    _json_bytes(
        _state_document_with_stable(_line_with(accepted=_accepted_record_doc(sequence=0)))
    ),
    _json_bytes(
        _state_document_with_stable(
            _line_with(accepted=_accepted_record_doc(sequence=True))
        )
    ),
    _json_bytes(
        _state_document_with_stable(
            _line_with(accepted=_accepted_record_doc(manifest_hash="not-hex"))
        )
    ),
    _json_bytes(
        _state_document_with_stable(
            _line_with(accepted=_accepted_record_doc(accepted_at=""))
        )
    ),
    _json_bytes(_state_document_with_stable(_line_with(rekor_tree_size=-1))),
    _json_bytes(
        _state_document_with_stable(_line_with(security_exceptions="nope"))
    ),
    _json_bytes(
        _state_document_with_stable(_line_with(security_exceptions=[{}]))
    ),
    _json_bytes(
        _state_document_with_stable(
            _line_with(security_exceptions=[_exception_doc(manifest_hash="zzz")])
        )
    ),
    _json_bytes(
        _state_document_with_stable(
            _line_with(
                security_exceptions=[_exception_doc(), dict(_exception_doc())]
            )
        )
    ),
]


@pytest.mark.parametrize("payload", _MALFORMED_STATE_PAYLOADS)
def test_malformed_state_matrix_is_fail_closed(tmp_path, payload):
    trust_dir = tmp_path / "trust"
    _write_state_raw(trust_dir, payload)

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["state_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


def test_unreadable_state_file_is_fail_closed(tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "state.json").mkdir()  # read_bytes() raises OSError

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["state_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


def test_validate_state_rejects_non_object_directly():
    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct._trust_validate_state([])


_BAD_AUDIT_PAYLOADS = [
    b"\xff",  # not UTF-8
    b"not-json\n",
    b"123\n",  # not an event object
]


@pytest.mark.parametrize("payload", _BAD_AUDIT_PAYLOADS)
def test_broken_audit_matrix_is_fail_closed(tmp_path, payload):
    trust_dir = tmp_path / "trust"
    _write_empty_state(trust_dir)
    (trust_dir / "audit.jsonl").write_bytes(payload)

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["audit_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


def test_audit_directory_is_fail_closed(tmp_path):
    trust_dir = tmp_path / "trust"
    _write_empty_state(trust_dir)
    (trust_dir / "audit.jsonl").mkdir()  # read_bytes() raises OSError

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["audit_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1


_BAD_ROOT_PAYLOADS = [
    {},  # signed object missing
    {"signed": {"_type": "revocations"}},  # wrong _type
    {"signed": {"_type": "root", "version": "x", "expires": "2099-01-01T00:00:00Z"}},
    {"signed": {"_type": "root", "version": 1, "expires": "garbage"}},
]


@pytest.mark.parametrize("payload", _BAD_ROOT_PAYLOADS)
def test_broken_root_cache_is_fail_closed(tmp_path, capsys, payload):
    trust_dir = tmp_path / "trust"
    _write_empty_state(trust_dir)
    (trust_dir / "root.json").write_text(json.dumps(payload), encoding="utf-8")

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["root_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1
    assert "[!]" in capsys.readouterr().out


_BAD_REVOCATIONS_PAYLOADS = [
    {},
    {"signed": {"_type": "root"}},
    {"signed": {"_type": "revocations", "expires": "garbage"}},
]


@pytest.mark.parametrize("payload", _BAD_REVOCATIONS_PAYLOADS)
def test_broken_revocations_cache_is_fail_closed(tmp_path, capsys, payload):
    trust_dir = tmp_path / "trust"
    _write_empty_state(trust_dir)
    (trust_dir / "revocations.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )

    status = codex_instruct.read_trust_status(trust_dir)

    assert status["revocations_error"]
    assert codex_instruct.run_trust_status_command(trust_dir, []) == 1
    assert "[!]" in capsys.readouterr().out


def test_expired_root_watermark_is_printed(accepted, capsys):
    trust_dir = accepted["trust_dir"]
    root_cache = trust_dir / "root.json"
    root_envelope = json.loads(root_cache.read_text(encoding="utf-8"))
    root_envelope["signed"]["expires"] = "2000-01-01T00:00:00Z"
    root_cache.write_text(json.dumps(root_envelope), encoding="utf-8")

    rc = codex_instruct.run_trust_status_command(trust_dir, [])

    output = capsys.readouterr().out
    assert rc == 0
    assert "root: v1 expires 2000-01-01T00:00:00Z [EXPIRED]" in output


def test_expired_revocations_watermark_is_printed(tmp_path, capsys):
    bundle = _build_stable_release(tmp_path / "inputs", with_revocations=True)
    trust_dir = tmp_path / "trust"
    verifier.verify_release(release_dir=bundle["release_dir"], trust_dir=trust_dir)
    cache = trust_dir / "revocations.json"
    envelope = json.loads(cache.read_text(encoding="utf-8"))
    envelope["signed"]["expires"] = "2000-01-01T00:00:00Z"
    cache.write_text(json.dumps(envelope), encoding="utf-8")

    rc = codex_instruct.run_trust_status_command(trust_dir, [])

    output = capsys.readouterr().out
    assert rc == 0
    assert "revocations: v1" in output
    assert "[EXPIRED]" in output


def test_parse_utc_rejects_bad_timestamps():
    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct._trust_parse_utc(123, "field")
    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct._trust_parse_utc("not-a-date", "field")
    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct._trust_parse_utc("2026-01-01T00:00:00", "field")
    parsed = codex_instruct._trust_parse_utc("2026-01-01T00:00:00Z", "field")
    assert parsed.tzinfo is not None


def test_standalone_self_check_broken_state_blocks(tmp_path):
    trust_dir = tmp_path / "trust"
    trust_dir.mkdir()
    (trust_dir / "state.json").write_text("{broken", encoding="utf-8")
    standalone = tmp_path / STANDALONE_NAME
    standalone.write_bytes(b"standalone bytes\n")

    verdict = codex_instruct.standalone_self_verification(
        trust_dir, script_path=standalone
    )

    assert verdict["verdict"] == "state-error"
    assert verdict["blocked"] is True
    assert verdict["detail"]


def test_standalone_self_check_accepts_explicit_state(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    state = codex_instruct._trust_load_state(accepted["trust_dir"])

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone, state=state
    )

    assert verdict["verdict"] == "verified"


def _repoint_accepted_manifest(accepted_bundle: dict, mutate_signed) -> str:
    trust_dir = accepted_bundle["trust_dir"]
    signed = json.loads(json.dumps(accepted_bundle["manifest"]))
    mutate_signed(signed)
    digest = codex_instruct._trust_canonical_sha256(signed)
    (trust_dir / "manifests" / "{}.json".format(digest)).write_text(
        json.dumps({"signed": signed}), encoding="utf-8"
    )
    state = json.loads((trust_dir / "state.json").read_text(encoding="utf-8"))
    state["lines"]["stable"]["accepted"]["manifest_hash"] = digest
    (trust_dir / "state.json").write_text(
        json.dumps(state, sort_keys=True), encoding="utf-8"
    )
    return digest


def test_standalone_envelope_invalid_variants(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")

    cases = [
        (lambda signed: signed.update(release_line="desktop-beta"), "stable"),
        (lambda signed: signed.update(version="9.9.9"), "version"),
        (lambda signed: signed.update(artifacts=[]), "artifacts"),
        (
            lambda signed: signed["artifacts"].update({STANDALONE_NAME: []}),
            STANDALONE_NAME,
        ),
        (
            lambda signed: signed["artifacts"][STANDALONE_NAME].update(sha256="zzz"),
            "sha256",
        ),
        (
            lambda signed: signed["artifacts"][STANDALONE_NAME].update(size="1"),
            "size",
        ),
    ]
    for mutate_signed, expected_fragment in cases:
        _repoint_accepted_manifest(accepted, mutate_signed)
        verdict = codex_instruct.standalone_self_verification(
            accepted["trust_dir"], script_path=standalone
        )
        assert verdict["verdict"] == "envelope-invalid", expected_fragment
        assert verdict["blocked"] is True
        assert expected_fragment in verdict["detail"]


def test_standalone_envelope_without_signed_blocks(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    digest = "f" * 64
    (accepted["trust_dir"] / "manifests" / "{}.json".format(digest)).write_text(
        "{}", encoding="utf-8"
    )
    state = json.loads(
        (accepted["trust_dir"] / "state.json").read_text(encoding="utf-8")
    )
    state["lines"]["stable"]["accepted"]["manifest_hash"] = digest
    (accepted["trust_dir"] / "state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )

    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    assert verdict["verdict"] == "envelope-invalid"
    assert verdict["blocked"] is True


def test_classify_running_form_other(tmp_path):
    assert codex_instruct.classify_running_form(
        tmp_path / "random-tool.py"
    ) == {"form": "other", "version": None}


def test_self_check_message_names_digests_and_reason(accepted, tmp_path):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    with standalone.open("ab") as handle:
        handle.write(b"tampered bytes\n")
    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )

    message = codex_instruct._trust_self_check_message(verdict)

    assert ACCEPTED_VERSION in message
    assert verdict["expected_sha256"] in message
    assert verdict["actual_sha256"] in message

    generic = codex_instruct._trust_self_check_message(
        {"verdict": "record-unavailable", "detail": "cache missing"}
    )
    assert "record-unavailable" in generic
    assert "cache missing" in generic


def test_semver_and_deployment_manifest_best_effort(tmp_path):
    assert codex_instruct._trust_semver_tuple("1.2.3-rc1+build") == (1, 2, 3)
    assert codex_instruct._trust_semver_tuple("1.2.x") is None
    assert codex_instruct._trust_semver_tuple(7) is None

    codex_dir = tmp_path / "codex"
    codex_dir.mkdir()
    manifest_path = codex_dir / codex_instruct.MANIFEST_FILENAME
    manifest_path.write_text("{broken", encoding="utf-8")
    assert codex_instruct.read_deployment_tool_version(codex_dir) is None
    manifest_path.write_text("[]", encoding="utf-8")
    assert codex_instruct.read_deployment_tool_version(codex_dir) is None
    manifest_path.write_text(
        json.dumps({"tool_version": ""}), encoding="utf-8"
    )
    assert codex_instruct.read_deployment_tool_version(codex_dir) is None
    manifest_path.write_text(
        json.dumps({"tool_version": "0.4.0"}), encoding="utf-8"
    )
    assert codex_instruct.read_deployment_tool_version(codex_dir) == "0.4.0"

    assert codex_instruct.find_legacy_deployments([codex_dir], "garbage") == []


def test_append_audit_line_oserror_wraps_failure(tmp_path):
    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct._trust_append_audit_line(
            tmp_path / "missing" / "audit.jsonl", {"event": "x"}
        )


def test_append_audit_line_without_o_nofollow(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    trust_dir = tmp_path / "trust"
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, "0.5.0")

    result = codex_instruct.perform_legacy_onboarding(
        trust_dir, [codex_dir], codex_instruct.VERSION
    )

    assert result["status"] == "onboarded"
    assert (trust_dir / "audit.jsonl").is_file()


def test_onboarding_rejects_non_directory_trust_dir(tmp_path, capsys):
    trust_dir = tmp_path / "trust-file"
    trust_dir.write_text("not a directory", encoding="utf-8")
    codex_dir = tmp_path / "codex"
    _write_deployment_manifest(codex_dir, "0.5.0")

    with pytest.raises(codex_instruct.TrustStatusError):
        codex_instruct.perform_legacy_onboarding(
            trust_dir, [codex_dir], codex_instruct.VERSION
        )

    rc = codex_instruct.run_legacy_onboarding_command(trust_dir, [codex_dir])
    assert rc == 1
    assert "[错误]" in capsys.readouterr().out


def test_scan_codex_dirs_explicit_argument(tmp_path):
    assert codex_instruct._trust_scan_codex_dirs(str(tmp_path)) == [tmp_path]


def _synthetic_status():
    return {
        "trust_dir": "/tmp/trust",
        "initialized": False,
        "state": None,
        "state_error": None,
        "root": None,
        "root_error": None,
        "revocations": None,
        "revocations_error": None,
        "audit_tail": [],
        "audit_error": None,
    }


def test_print_status_blocked_standalone_and_onboarding_hint(
    accepted, tmp_path, capsys
):
    standalone = _materialize_standalone(accepted, tmp_path / "bin")
    with standalone.open("ab") as handle:
        handle.write(b"tampered bytes\n")
    verdict = codex_instruct.standalone_self_verification(
        accepted["trust_dir"], script_path=standalone
    )
    onboarding = {"status": "needed", "legacy": [{"version": "0.5.0"}]}

    codex_instruct._print_trust_status(_synthetic_status(), verdict, onboarding)

    output = capsys.readouterr().out
    assert "standalone self-check: hash-mismatch" in output
    assert verdict["expected_sha256"] in output
    assert "--trust-onboard-legacy" in output
    assert "0.5.0" in output


def test_print_status_other_form_and_full_state(capsys):
    status = _synthetic_status()
    codex_instruct._print_trust_status(
        status, {"form": "other", "verdict": "not-applicable"}, None
    )
    assert "standalone self-check: not-applicable (other)" in capsys.readouterr().out

    status = _synthetic_status()
    document = _valid_state_document()
    document["lines"]["stable"] = {
        "accepted": _accepted_record_doc(manifest_hash="c" * 64),
        "rekor_tree_size": 3,
        "security_exceptions": [_exception_doc()],
    }
    status["initialized"] = True
    status["state"] = document
    status["root"] = {
        "version": 2,
        "expires": "2000-01-01T00:00:00Z",
        "expired": True,
        "fingerprint": "deadbeef",
    }
    status["revocations"] = {
        "version": 1,
        "issued_at": "1999-01-01T00:00:00Z",
        "expires": "2000-01-01T00:00:00Z",
        "expired": True,
    }
    status["audit_tail"] = [{"event": "tofu", "line": "stable"}]

    codex_instruct._print_trust_status(
        status, {"form": "source-tree", "verdict": "not-applicable"}, None
    )

    output = capsys.readouterr().out
    assert "line stable: accepted {}".format(ACCEPTED_VERSION) in output
    assert "rekor-tree 3" in output
    assert "active security exception:" in output
    assert "incident-42" in output
    assert "root: v2 expires 2000-01-01T00:00:00Z [EXPIRED] fingerprint deadbeef" in output
    assert "revocations: v1 issued 1999-01-01T00:00:00Z" in output
    assert '"event": "tofu"' in output


def test_main_trust_status_conflict_exits_2(monkeypatch):
    monkeypatch.setattr(
        codex_instruct.sys,
        "argv",
        ["codex-instruct.py", "--trust-status", "--yes"],
    )
    with pytest.raises(SystemExit) as exit_info:
        codex_instruct.main()
    assert exit_info.value.code == 2


def test_main_trust_status_in_process(accepted, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CODEX_KEYSMITH_TRUST_DIR", str(accepted["trust_dir"]))
    monkeypatch.setattr(
        codex_instruct.sys,
        "argv",
        [
            "codex-instruct.py",
            "--trust-status",
            "--codex-dir",
            str(tmp_path / "no-such-codex"),
        ],
    )
    with pytest.raises(SystemExit) as exit_info:
        codex_instruct.main()
    assert exit_info.value.code == 0
    assert "accepted {}".format(ACCEPTED_VERSION) in capsys.readouterr().out


def test_main_write_gate_blocked_in_process(tmp_path, monkeypatch, capsys):
    codex_dir = tmp_path / "codex"
    codex_dir.mkdir()
    blocked = {
        "verdict": "state-error",
        "blocked": True,
        "form": "standalone",
        "version": ACCEPTED_VERSION,
        "detail": "synthetic failure",
    }
    monkeypatch.setattr(
        codex_instruct, "standalone_self_verification", lambda trust_dir: blocked
    )
    monkeypatch.setattr(
        codex_instruct.sys,
        "argv",
        [
            "codex-instruct.py",
            "--reactivate",
            "--yes",
            "--codex-dir",
            str(codex_dir),
        ],
    )

    with pytest.raises(SystemExit) as exit_info:
        codex_instruct.main()

    output = capsys.readouterr().out
    assert exit_info.value.code == 1
    assert "[错误]" in output
    assert "state-error" in output


def test_main_onboard_then_read_only_status_fallthrough(
    tmp_path, monkeypatch, capsys
):
    import types

    trust_dir = tmp_path / "trust"
    codex_dir = tmp_path / "codex"
    codex_dir.mkdir()
    (codex_dir / "config.toml").write_text(
        'model = "gpt-5"\n', encoding="utf-8"
    )
    monkeypatch.setattr(codex_instruct, "find_codex_dirs", lambda: [str(codex_dir)])
    # A structurally valid deployment manifest downgraded to an older
    # tool_version is exactly the legacy deployment onboarding looks for.
    codex_instruct.deploy(
        types.SimpleNamespace(
            file=None,
            name="gpt-unrestricted",
            preset="unrestricted",
            dry_run=False,
            yes=True,
            skip_hooks_isolation=True,
        )
    )
    manifest_path = codex_dir / codex_instruct.MANIFEST_FILENAME
    deployment_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    deployment_manifest["tool_version"] = "0.5.0"
    manifest_path.write_text(
        json.dumps(deployment_manifest), encoding="utf-8"
    )

    monkeypatch.setenv("CODEX_KEYSMITH_TRUST_DIR", str(trust_dir))
    monkeypatch.setattr(
        codex_instruct.sys,
        "argv",
        [
            "codex-instruct.py",
            "--trust-onboard-legacy",
            "--status",
            "--codex-dir",
            str(codex_dir),
        ],
    )

    codex_instruct.main()  # onboarding succeeds, then falls through to --status

    audit_lines = (trust_dir / "audit.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(audit_lines) == 1
    assert json.loads(audit_lines[0])["event"] == "legacy-onboarding"
    output = capsys.readouterr().out
    assert "状态目录" in output or "Status" in output


# ---------------------------------------------------------------------------
# TR-12.4 AST import audit
# ---------------------------------------------------------------------------


def test_trust_section_adds_no_network_or_crypto_imports():
    source = MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source)

    forbidden = {
        "urllib",
        "http",
        "socket",
        "ssl",
        "requests",
        "cryptography",
        "nacl",
        "ftplib",
        "smtplib",
    }
    imported_roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported_roots.add(node.module.split(".")[0])
    assert not (imported_roots & forbidden)

    marker = "release-trust integration (FR-20)"
    start_line = next(
        number for number, line in enumerate(source.splitlines(), start=1)
        if marker in line
    )
    main_line = next(
        node.lineno
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    section_nodes = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        and start_line <= node.lineno < main_line
    ]
    assert section_nodes
    for node in section_nodes:
        for child in ast.walk(node):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                raise AssertionError(
                    "trust section must not add imports, found one at line {}".format(
                        child.lineno
                    )
                )
