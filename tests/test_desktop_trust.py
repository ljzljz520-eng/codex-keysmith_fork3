"""TR-11: signed-line desktop-beta packaging, bindings and line independence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from scripts import build_release, generate_sbom
from scripts import keysmith_trust as trust
from scripts import package_desktop_prerelease as prerelease
from scripts import validate_desktop_candidate as candidate_validator
from scripts import verify_release as verifier

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TAG = f"desktop-v{prerelease.VERSION}-beta.1"
TAG2 = f"desktop-v{prerelease.VERSION}-beta.2"
ISSUED = "2026-08-01T10:00:00Z"
TAG_OBJECT = "b" * 40
STABLE_VERSION = "0.7.0"


# ---------------------------------------------------------------------------
# Existing-test module reuse (candidate builder + signing ceremony helpers)
# ---------------------------------------------------------------------------


def _load_helper(name: str):
    path = REPO_ROOT / "tests" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _desktop_helpers():
    return _load_helper("test_desktop_prerelease.py")


def _ceremony_helpers():
    return _load_helper("test_verify_release.py")


def _builder_info(tag: str) -> dict[str, object]:
    # Toolchain versions are supplied by the candidate build manifests; the
    # builder info only carries workflow identity (python_version is filled
    # from the candidate toolchain when omitted).
    return {
        "workflow_name": "desktop-candidate.yml",
        "workflow_ref": f"refs/tags/{tag}",
        "workflow_sha": "c" * 40,
        "runner": "GitHub Actions ubuntu-24.04",
    }


def _make_candidates(base: Path):
    helper = _desktop_helpers()
    return {
        "macos": helper._candidate(base / "macos-candidates", "macos"),
        "windows": helper._candidate(base / "windows-candidates", "windows"),
    }


def _assemble_trust(
    base: Path,
    candidates: dict[str, Path],
    tag: str,
    *,
    sequence: int,
    output_name: str,
    source_repo: str = "local",
    builder_info: dict[str, object] | None = None,
):
    return prerelease.assemble_prerelease(
        candidates["macos"],
        candidates["windows"],
        base / output_name,
        tag,
        COMMIT,
        emit_trust_artifacts=True,
        trust_sequence=sequence,
        trust_issued_at=ISSUED,
        builder_info=builder_info if builder_info is not None else _builder_info(tag),
        source_repo=source_repo,
        tag_object=TAG_OBJECT,
        repo_root=REPO_ROOT,
    )


def _expected_trust_names(tag: str) -> set[str]:
    spdx_name, cdx_name = generate_sbom.sbom_asset_names(tag)
    return {
        *prerelease.PUBLIC_ASSET_NAMES,
        prerelease.BUILD_MANIFEST_LOGICAL_NAMES["macos"],
        prerelease.BUILD_MANIFEST_LOGICAL_NAMES["windows"],
        build_release.VERIFIER_STANDALONE_NAME.format(tag),
        spdx_name,
        cdx_name,
        prerelease.TRUST_UNSIGNED_MANIFEST_NAME,
    }


def _load_unsigned(output_dir: Path) -> dict:
    return json.loads(
        (output_dir / prerelease.TRUST_UNSIGNED_MANIFEST_NAME).read_text(encoding="utf-8")
    )


def _sign_release(
    output_dir: Path,
    *,
    previous_index_signed,
    root_env,
    signer: str = "rel1",
    issued_at: str = ISSUED,
):
    ceremony = _ceremony_helpers()
    manifest = _load_unsigned(output_dir)
    manifest_env = trust.seal_envelope(manifest, [ceremony._seed(signer)])
    index_signed = trust.append_index_entry(
        previous_index_signed,
        manifest_env,
        issued_at=issued_at,
    )
    index_env = trust.seal_envelope(index_signed, [ceremony._seed(signer)])
    (output_dir / verifier.SIGNED_MANIFEST_NAME).write_bytes(
        trust.canonical_json_bytes(manifest_env)
    )
    (output_dir / verifier.INDEX_NAME).write_bytes(
        trust.canonical_json_bytes(index_env)
    )
    (output_dir / verifier.ROOT_BUNDLE_NAME).write_bytes(
        trust.canonical_json_bytes(root_env)
    )
    return manifest_env, index_signed


def _verify_desktop(output_dir: Path, trust_dir: Path, *, tag: str = TAG, **overrides):
    overrides.setdefault("expected_line", trust.DESKTOP_BETA_LINE)
    overrides.setdefault("expected_tag", tag)
    return verifier.verify_release(
        release_dir=output_dir,
        trust_dir=trust_dir,
        **overrides,
    )


# ---------------------------------------------------------------------------
# TR-11.1 switch off is zero-regression; switch on covers every desktop asset
# ---------------------------------------------------------------------------


def test_switch_off_keeps_the_classic_asset_set(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs-off")
    output = prerelease.assemble_prerelease(
        candidates["macos"],
        candidates["windows"],
        tmp_path / "classic",
        TAG,
        COMMIT,
    )
    assert {path.name for path in output.iterdir()} == set(prerelease.PUBLIC_ASSET_NAMES)
    for name in _expected_trust_names(TAG) - set(prerelease.PUBLIC_ASSET_NAMES):
        assert not (output / name).exists()
    prerelease.verify_public_assets(output, COMMIT)


def test_trust_only_options_require_the_switch(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs-guard")
    with pytest.raises(prerelease.PrereleaseError, match="trust-only options"):
        prerelease.assemble_prerelease(
            candidates["macos"],
            candidates["windows"],
            tmp_path / "guard",
            TAG,
            COMMIT,
            trust_sequence=1,
        )


def test_switch_on_emits_complete_validated_desktop_trust_set(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs")
    output = _assemble_trust(
        tmp_path, candidates, TAG, sequence=1, output_name="desktop-trust"
    )

    names = {path.name for path in output.iterdir() if path.is_file()}
    assert names == _expected_trust_names(TAG)

    manifest = _load_unsigned(output)
    trust.validate_release_manifest(manifest)
    assert manifest["release_line"] == trust.DESKTOP_BETA_LINE
    assert manifest["version"] == f"{prerelease.VERSION}-beta.1"
    assert manifest["tag"] == TAG
    assert manifest["sequence"] == 1
    assert manifest["issued_at"] == ISSUED
    assert manifest["source"] == {
        "repo": "local",
        "commit": COMMIT,
        "tag_object": TAG_OBJECT,
    }
    assert set(manifest["artifacts"]) == {
        *prerelease.PUBLIC_PAYLOAD_NAMES,
        prerelease.CHECKSUMS_NAME,
        build_release.VERIFIER_STANDALONE_NAME.format(TAG),
    }
    assert len(manifest["sboms"]) == 2
    assert set(manifest["builder"]["build_manifests"]) == {
        prerelease.BUILD_MANIFEST_LOGICAL_NAMES["macos"],
        prerelease.BUILD_MANIFEST_LOGICAL_NAMES["windows"],
    }
    # Toolchain is bound from the pinned candidate build manifests.
    assert manifest["builder"]["node_version"] == "22.14.0"
    assert manifest["builder"]["python_version"] == "3.12.9"
    assert manifest["builder"]["pyinstaller_version"] == "6.16.0"
    assert manifest["builder"]["rust_version"] == "1.88.0"

    # Every manifest/SBOM/build-manifest digest recomputes from disk bytes.
    for name, record in {**manifest["artifacts"], **manifest["sboms"]}.items():
        data = (output / name).read_bytes()
        assert record == {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    for logical, digest in manifest["builder"]["build_manifests"].items():
        assert hashlib.sha256((output / logical).read_bytes()).hexdigest() == digest

    # Packaging-level recomputation pass (post-rename verification).
    assert prerelease.verify_trust_prerelease(output, COMMIT)["tag"] == TAG


def test_desktop_trust_assembly_is_byte_reproducible(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs-repro")
    first = _assemble_trust(tmp_path, candidates, TAG, sequence=1, output_name="rep-a")
    second = _assemble_trust(tmp_path, candidates, TAG, sequence=1, output_name="rep-b")
    for name in _expected_trust_names(TAG):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_builder_info_toolchain_disagreement_is_rejected(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs-bad-toolchain")
    info = _builder_info(TAG)
    info["python_version"] = "2.7.0"
    with pytest.raises(prerelease.PrereleaseError, match="disagrees"):
        _assemble_trust(
            tmp_path,
            candidates,
            TAG,
            sequence=1,
            output_name="bad-toolchain",
            builder_info=info,
        )


def test_cross_platform_toolchain_drift_is_rejected(tmp_path):
    candidates = _make_candidates(tmp_path / "inputs-drift")
    path = candidates["windows"] / "build-manifest.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["toolchain"]["node"] = "20.0.0"
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with pytest.raises(prerelease.PrereleaseError, match="toolchain"):
        _assemble_trust(
            tmp_path, candidates, TAG, sequence=1, output_name="drift"
        )


def test_cli_assemble_and_verify_trust(tmp_path, monkeypatch):
    candidates = _make_candidates(tmp_path / "inputs-cli")
    monkeypatch.setenv(
        prerelease.BUILDER_INFO_ENV_VAR, json.dumps(_builder_info(TAG))
    )
    output = tmp_path / "cli-out"
    rc = prerelease.main(
        [
            "assemble",
            "--macos-candidate-dir",
            str(candidates["macos"]),
            "--windows-candidate-dir",
            str(candidates["windows"]),
            "--output-dir",
            str(output),
            "--release-tag",
            TAG,
            "--expected-commit",
            COMMIT,
            "--emit-trust-artifacts",
            "--trust-sequence",
            "1",
            "--trust-issued-at",
            ISSUED,
            "--tag-object",
            TAG_OBJECT,
        ]
    )
    assert rc == 0
    assert (output / prerelease.TRUST_UNSIGNED_MANIFEST_NAME).exists()
    assert (
        prerelease.main(
            ["verify", str(output), "--expected-commit", COMMIT, "--trust"]
        )
        == 0
    )
    # The classic verifier rejects a directory carrying trust extras.
    assert (
        prerelease.main(["verify", str(output), "--expected-commit", COMMIT]) == 1
    )
    # Without builder info the trust switch fails deterministically.
    monkeypatch.delenv(prerelease.BUILDER_INFO_ENV_VAR)
    assert (
        prerelease.main(
            [
                "assemble",
                "--macos-candidate-dir",
                str(candidates["macos"]),
                "--windows-candidate-dir",
                str(candidates["windows"]),
                "--output-dir",
                str(tmp_path / "cli-out-nobuilder"),
                "--release-tag",
                TAG,
                "--expected-commit",
                COMMIT,
                "--emit-trust-artifacts",
                "--trust-sequence",
                "1",
                "--trust-issued-at",
                ISSUED,
                "--tag-object",
                TAG_OBJECT,
            ]
        )
        == 1
    )


def test_env_contract_matches_build_release():
    assert prerelease.BUILDER_INFO_ENV_VAR == build_release.BUILDER_INFO_ENV_VAR
    assert prerelease.SOURCE_REPO_ENV_VAR == build_release.SOURCE_REPO_ENV_VAR


def test_manifest_identity_helper_rejects_inconsistent_records(tmp_path):
    helper = _desktop_helpers()
    candidate = helper._candidate(tmp_path / "identity-candidates", "macos")
    document = json.loads((candidate / "build-manifest.json").read_text("utf-8"))
    identity = candidate_validator.manifest_identity(document)
    assert identity["source_commit"] == COMMIT
    assert identity["target"]["triple"] == "aarch64-apple-darwin"

    bad_commit = json.loads(json.dumps(document))
    bad_commit["source_commit"] = "z" * 40
    with pytest.raises(candidate_validator.CandidateError, match="source commit"):
        candidate_validator.manifest_identity(bad_commit)
    bad_triple = json.loads(json.dumps(document))
    bad_triple["target"]["triple"] = "x86_64-apple-darwin"
    with pytest.raises(candidate_validator.CandidateError, match="target"):
        candidate_validator.manifest_identity(bad_triple)
    bad_toolchain = json.loads(json.dumps(document))
    bad_toolchain["toolchain"]["rust"] = ""
    with pytest.raises(candidate_validator.CandidateError, match="toolchain"):
        candidate_validator.manifest_identity(bad_toolchain)


# ---------------------------------------------------------------------------
# TR-11.2 the signed desktop-beta release is verified through verify_release
# ---------------------------------------------------------------------------


@pytest.fixture()
def signed_desktop(tmp_path):
    ceremony = _ceremony_helpers()
    root_env = ceremony._root_envelope()
    candidates = _make_candidates(tmp_path / "inputs-signed")
    output = _assemble_trust(
        tmp_path, candidates, TAG, sequence=1, output_name="signed-out"
    )
    _manifest_env, index_signed = _sign_release(
        output, previous_index_signed=None, root_env=root_env
    )
    trust_dir = tmp_path / "trust"
    return {
        "output": output,
        "trust_dir": trust_dir,
        "root_env": root_env,
        "index_signed": index_signed,
    }


def test_signed_desktop_beta_verifies_tofu(signed_desktop):
    result = _verify_desktop(
        signed_desktop["output"], signed_desktop["trust_dir"]
    )
    assert result["ok"] is True
    assert result["line"] == trust.DESKTOP_BETA_LINE
    assert result["action"] == trust.ACTION_TOFU
    state = trust.load_state(signed_desktop["trust_dir"])
    accepted = state["lines"][trust.DESKTOP_BETA_LINE]["accepted"]
    assert accepted["version"] == f"{prerelease.VERSION}-beta.1"
    assert accepted["sequence"] == 1


def test_tampered_build_manifest_is_rejected(signed_desktop):
    target = signed_desktop["output"] / prerelease.BUILD_MANIFEST_LOGICAL_NAMES["macos"]
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(verifier.VerificationError) as info:
        _verify_desktop(signed_desktop["output"], signed_desktop["trust_dir"])
    assert info.value.exit_code == trust.EXIT_DIGEST
    assert info.value.stage == "build-manifests"


def test_replaced_desktop_asset_is_rejected(signed_desktop):
    target = signed_desktop["output"] / prerelease.MACOS_DMG_NAME
    target.write_bytes(target.read_bytes() + b"replaced")
    with pytest.raises(verifier.VerificationError) as info:
        _verify_desktop(signed_desktop["output"], signed_desktop["trust_dir"])
    assert info.value.exit_code == trust.EXIT_DIGEST
    assert info.value.stage == "artifacts"


def test_missing_sbom_is_rejected(signed_desktop):
    spdx_name, _cdx = generate_sbom.sbom_asset_names(TAG)
    (signed_desktop["output"] / spdx_name).unlink()
    with pytest.raises(verifier.VerificationError) as info:
        _verify_desktop(signed_desktop["output"], signed_desktop["trust_dir"])
    assert info.value.exit_code == trust.EXIT_DIGEST
    assert info.value.stage == "artifacts"


def test_tampered_candidate_zip_is_rejected_at_artifacts(signed_desktop):
    # Rebuild the macOS candidate ZIP with an extra byte in the bundle while
    # the public DMG stays untouched: the unsigned manifest covers the ZIP
    # digest, so the verifier must fail closed.
    output = signed_desktop["output"]
    import zipfile

    rebuilt = output / prerelease.MACOS_CANDIDATE_ZIP_NAME
    with zipfile.ZipFile(rebuilt, "r") as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    rebuilt.unlink()
    with zipfile.ZipFile(rebuilt, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(members):
            data = members[name]
            if name.endswith(".dmg"):
                data += b"x"
            archive.writestr(name, data)
    with pytest.raises(verifier.VerificationError) as info:
        _verify_desktop(output, signed_desktop["trust_dir"])
    assert info.value.exit_code == trust.EXIT_DIGEST


# ---------------------------------------------------------------------------
# TR-11.3 desktop-beta and stable keep independent water-marks/sequences
# ---------------------------------------------------------------------------


def _stable_release(
    base: Path,
    *,
    version: str,
    previous_index_signed,
    root_env,
    signer: str = "rel1",
):
    ceremony = _ceremony_helpers()
    tag = f"v{version}"
    release_dir = base / f"stable-{version}"
    release_dir.mkdir(parents=True)
    core = (
        f"codex-keysmith-{tag}.zip",
        f"codex-keysmith-{tag}.tar.gz",
        f"codex-instruct-{tag}.py",
        f"codex-keysmith-scenarios-{tag}.bundle",
    )
    for name in core:
        (release_dir / name).write_bytes(f"{name}:stable-content\n".encode("utf-8"))
    checksum_lines = [
        "{}  {}".format(
            hashlib.sha256((release_dir / name).read_bytes()).hexdigest(), name
        )
        for name in sorted(core)
    ]
    (release_dir / "SHA256SUMS").write_text(
        "\n".join(checksum_lines) + "\n", encoding="ascii"
    )
    verifier_name = f"verify-release-{tag}.py"
    (release_dir / verifier_name).write_text("#!/usr/bin/env python3\nstable\n")
    spdx_name = f"codex-keysmith-{tag}-sbom.spdx.json"
    cdx_name = f"codex-keysmith-{tag}-sbom.cdx.json"
    (release_dir / spdx_name).write_bytes(
        json.dumps(ceremony._valid_spdx(), sort_keys=True).encode() + b"\n"
    )
    (release_dir / cdx_name).write_bytes(
        json.dumps(ceremony._valid_cdx(), sort_keys=True).encode() + b"\n"
    )

    def record(name: str):
        data = (release_dir / name).read_bytes()
        return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

    manifest = {
        "_type": trust.RELEASE_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": trust.STABLE_LINE,
        "version": version,
        "tag": tag,
        "sequence": 1,
        "issued_at": ISSUED,
        "source": {"repo": "local", "commit": COMMIT, "tag_object": "b" * 40},
        "builder": {
            "workflow_name": "release.yml",
            "workflow_ref": f"refs/tags/{tag}",
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
    manifest_env = trust.seal_envelope(manifest, [ceremony._seed(signer)])
    index_signed = trust.append_index_entry(
        previous_index_signed, manifest_env, issued_at=ISSUED
    )
    index_env = trust.seal_envelope(index_signed, [ceremony._seed(signer)])
    (release_dir / verifier.SIGNED_MANIFEST_NAME).write_bytes(
        trust.canonical_json_bytes(manifest_env)
    )
    (release_dir / verifier.INDEX_NAME).write_bytes(
        trust.canonical_json_bytes(index_env)
    )
    (release_dir / verifier.ROOT_BUNDLE_NAME).write_bytes(
        trust.canonical_json_bytes(root_env)
    )
    return release_dir, index_signed


def test_desktop_beta_and_stable_watermarks_are_independent(tmp_path):
    ceremony = _ceremony_helpers()
    root_env = ceremony._root_envelope()
    trust_dir = tmp_path / "trust"
    candidates = _make_candidates(tmp_path / "candidates")

    # 1. desktop-beta beta.1 (sequence 1 on its own line).
    desktop1 = _assemble_trust(
        tmp_path, candidates, TAG, sequence=1, output_name="desktop-beta1"
    )
    _env1, index1 = _sign_release(
        desktop1, previous_index_signed=None, root_env=root_env
    )
    result = _verify_desktop(desktop1, trust_dir)
    assert result["action"] == trust.ACTION_TOFU

    # 2. stable 0.7.0 extends the same global index but starts sequence 1 too.
    stable_dir, index2 = _stable_release(
        tmp_path, version=STABLE_VERSION, previous_index_signed=index1, root_env=root_env
    )
    stable_result = verifier.verify_release(
        release_dir=stable_dir,
        trust_dir=trust_dir,
        expected_line=trust.STABLE_LINE,
        expected_tag=f"v{STABLE_VERSION}",
    )
    assert stable_result["action"] == trust.ACTION_TOFU

    # 3. desktop-beta beta.2 advances only the desktop line.
    desktop2 = _assemble_trust(
        tmp_path, candidates, TAG2, sequence=2, output_name="desktop-beta2"
    )
    _env2, _index3 = _sign_release(
        desktop2,
        previous_index_signed=index2,
        root_env=root_env,
    )
    upgraded = _verify_desktop(desktop2, trust_dir, tag=TAG2)
    assert upgraded["action"] == trust.ACTION_UPGRADE

    state = trust.load_state(trust_dir)
    desktop_accepted = state["lines"][trust.DESKTOP_BETA_LINE]["accepted"]
    stable_accepted = state["lines"][trust.STABLE_LINE]["accepted"]
    assert desktop_accepted["version"] == f"{prerelease.VERSION}-beta.2"
    assert desktop_accepted["sequence"] == 2
    assert stable_accepted["version"] == STABLE_VERSION
    assert stable_accepted["sequence"] == 1

    # The stable release reinstalls (its older index copy resolves to the
    # pinned append-only index) without touching the desktop water-mark.
    reinstall = verifier.verify_release(
        release_dir=stable_dir,
        trust_dir=trust_dir,
        expected_line=trust.STABLE_LINE,
        expected_tag=f"v{STABLE_VERSION}",
    )
    assert reinstall["ok"] is True
    assert trust.load_state(trust_dir)["lines"][trust.STABLE_LINE]["accepted"] == (
        stable_accepted
    )

    # Rolling the desktop line back to beta.1 is refused while stable stands.
    with pytest.raises(verifier.VerificationError) as info:
        _verify_desktop(desktop1, trust_dir)
    assert info.value.exit_code == trust.EXIT_DOWNGRADE
    assert info.value.stage == "downgrade"
    assert (
        trust.load_state(trust_dir)["lines"][trust.STABLE_LINE]["accepted"]
        == stable_accepted
    )
