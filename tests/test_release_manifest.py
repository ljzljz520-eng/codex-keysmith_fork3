"""TR-7: build_release opt-in trust artifacts (unsigned manifest + SBOMs)."""

import base64
import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import generate_sbom
from scripts import keysmith_trust as trust

REPO_ROOT = Path(__file__).resolve().parents[1]
BUILDER_PATH = REPO_ROOT / "scripts" / "build_release.py"
TAG = "v0.6.0"
VERSION = "0.6.0"
ISSUED_AT = "2026-07-18T10:00:00Z"
WORKFLOW_SHA = "a" * 40

CORE_ASSETS = (
    "codex-keysmith-{}.zip".format(TAG),
    "codex-keysmith-{}.tar.gz".format(TAG),
    "codex-instruct-{}.py".format(TAG),
    "codex-keysmith-scenarios-{}.bundle".format(TAG),
)
VERIFIER_ASSET = "verify-release-{}.py".format(TAG)
FIXTURE_GUI_FILES = {
    "gui/README.md": b"# GUI fixture\n",
    "gui/package.json": b'{"name":"codex-keysmith-gui","version":"0.6.0"}\n',
    "gui/scripts/build-sidecar.mjs": b"#!/usr/bin/env node\n",
    "gui/src-tauri/icons/Square44x44Logo.png": b"fixture PNG\n",
    "gui/src-tauri/icons/icon.ico": b"fixture ICO\n",
    "gui/src-tauri/tauri.windows.conf.json": b'{"bundle":{"targets":["nsis"]}}\n',
}


def _builder_info():
    return {
        "workflow_name": "release.yml",
        "workflow_ref": "refs/tags/{}".format(TAG),
        "workflow_sha": WORKFLOW_SHA,
        "runner": "GitHub Actions ubuntu-24.04",
        "python_version": "3.11.9",
        "node_version": "20.15.0",
        "rust_version": "",
        "pyinstaller_version": "",
        "build_manifests": {},
    }


@pytest.fixture(scope="module")
def release_builder():
    spec = importlib.util.spec_from_file_location("release_builder_manifest", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run(command, cwd):
    return subprocess.run(
        command,
        cwd=str(cwd),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _make_repo(tmp_path, release_builder, *, annotated_tag):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    for relative_path in release_builder.ARCHIVE_FILES:
        path = repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative_path == "VERSION":
            data = (VERSION + "\n").encode("ascii")
        elif relative_path == "codex-instruct.py":
            data = (
                '#!/usr/bin/env python3\n__version__ = "{}"\n'.format(VERSION)
            ).encode("ascii")
        elif relative_path == "CHANGELOG.md":
            data = (
                "# Changelog\n\n## [{}] - 2026-07-18\n\n- Release.\n".format(VERSION)
            ).encode("ascii")
        elif relative_path == "LICENSE":
            data = (REPO_ROOT / "LICENSE").read_bytes()
        else:
            data = "fixture for {}\n".format(relative_path).encode("utf-8")
        path.write_bytes(data)
    release_notes = repo / "docs" / "releases" / "{}.md".format(TAG)
    release_notes.parent.mkdir(parents=True, exist_ok=True)
    release_notes.write_text("# {} release notes\n".format(TAG), encoding="utf-8")

    # Trust tooling must ship byte-identical to the real repository so the
    # embedded verifier engine and SBOM generator are the reviewed code.
    for relative_path in release_builder.TRUST_ARCHIVE_FILES:
        path = repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((REPO_ROOT / relative_path).read_bytes())
        if relative_path in release_builder.TRUST_EXECUTABLE_SCRIPTS:
            path.chmod(0o755)

    for library in ("scenarios", "fixture_packs"):
        source_library = REPO_ROOT / library
        if source_library.is_dir():
            shutil.copytree(source_library, repo / library)

    for relative_path, data in FIXTURE_GUI_FILES.items():
        path = repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if relative_path.endswith(".mjs"):
            path.chmod(0o755)

    gitattributes = REPO_ROOT / ".gitattributes"
    if gitattributes.exists():
        (repo / ".gitattributes").write_bytes(gitattributes.read_bytes())

    _run(["git", "init", "-q"], repo)
    _run(["git", "config", "user.name", "Release Test"], repo)
    _run(["git", "config", "user.email", "release-test@example.invalid"], repo)
    _run(["git", "config", "core.autocrlf", "false"], repo)
    _run(["git", "add", "."], repo)
    _run(["git", "update-index", "--chmod=+x", "gui/scripts/build-sidecar.mjs"], repo)
    for relative_path in release_builder.TRUST_EXECUTABLE_SCRIPTS:
        _run(["git", "update-index", "--chmod=+x", relative_path], repo)
    _run(["git", "commit", "-qm", "release fixture"], repo)
    if annotated_tag:
        _run(["git", "tag", "-a", TAG, "-m", "release {}".format(TAG)], repo)
    else:
        _run(["git", "tag", TAG], repo)
    return repo


def _build_trust(release_builder, repo, output_dir, **overrides):
    kwargs = dict(
        emit_trust_artifacts=True,
        trust_sequence=1,
        trust_issued_at=ISSUED_AT,
        builder_info=_builder_info(),
        source_repo="https://github.com/example/codex-keysmith",
        required_root_version=1,
        required_revocations_version=0,
    )
    kwargs.update(overrides)
    return release_builder.build_release(
        TAG,
        repo,
        output_dir,
        **kwargs,
    )


def _sha256_size(path):
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_size


def _load_manifest(output_dir):
    return json.loads((output_dir / "release-manifest.unsigned.json").read_text("utf-8"))


# ---------------------------------------------------------------------------
# TR-7.1 default build stays byte-identical and trust build is complete
# ---------------------------------------------------------------------------

def test_default_build_emits_only_the_five_classic_assets(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    paths = release_builder.build_release(TAG, repo, tmp_path / "dist-classic")
    names = sorted(path.name for path in paths)
    assert names == sorted(list(CORE_ASSETS) + ["SHA256SUMS"])
    dist = tmp_path / "dist-classic"
    assert not (dist / "release-manifest.unsigned.json").exists()
    assert not (dist / VERIFIER_ASSET).exists()
    checksum_lines = (dist / "SHA256SUMS").read_text("ascii").splitlines()
    assert sorted(line.split("  ", 1)[1] for line in checksum_lines) == sorted(
        CORE_ASSETS
    )


def test_trust_build_emits_validated_manifest_sboms_and_verifier(
    release_builder, tmp_path
):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    output_dir = tmp_path / "dist-trust"
    _build_trust(release_builder, repo, output_dir)

    names = {path.name for path in output_dir.iterdir() if path.is_file()}
    spdx_asset, cdx_asset = generate_sbom.sbom_asset_names(TAG)
    assert names == (
        set(CORE_ASSETS)
        | {"SHA256SUMS", "release-manifest.unsigned.json", spdx_asset, cdx_asset}
        | {VERIFIER_ASSET}
    )

    manifest = _load_manifest(output_dir)
    trust.validate_release_manifest(manifest)
    head_commit = _run(["git", "rev-parse", "HEAD"], repo).stdout.strip()
    tag_object = _run(
        ["git", "rev-parse", "{}^{{tag}}".format(TAG)], repo
    ).stdout.strip()
    assert manifest["source"] == {
        "repo": "https://github.com/example/codex-keysmith",
        "commit": head_commit,
        "tag_object": tag_object,
    }
    assert manifest["sequence"] == 1
    assert manifest["issued_at"] == ISSUED_AT
    assert manifest["release_line"] == trust.STABLE_LINE
    assert manifest["builder"]["workflow_sha"] == WORKFLOW_SHA

    artifacts = manifest["artifacts"]
    assert set(artifacts) == set(CORE_ASSETS) | {"SHA256SUMS", VERIFIER_ASSET}
    for name, record in artifacts.items():
        digest_hex, size = _sha256_size(output_dir / name)
        assert record == {"sha256": digest_hex, "size": size}
    assert set(manifest["sboms"]) == {spdx_asset, cdx_asset}
    for name, record in manifest["sboms"].items():
        digest_hex, size = _sha256_size(output_dir / name)
        assert record == {"sha256": digest_hex, "size": size}

    spdx_doc = json.loads((output_dir / spdx_asset).read_text("utf-8"))
    cdx_doc = json.loads((output_dir / cdx_asset).read_text("utf-8"))
    assert spdx_doc["spdxVersion"] == generate_sbom.SPDX_OUTPUT_VERSION
    assert cdx_doc["specVersion"] == generate_sbom.CDX_SPEC_VERSION

    # The canonical re-render must match the published manifest bytes.
    manifest_bytes = (output_dir / "release-manifest.unsigned.json").read_bytes()
    assert release_builder._render_manifest_bytes(manifest) == manifest_bytes

    # Trust tooling is inside the archives and executable bits survive.
    with zipfile.ZipFile(output_dir / CORE_ASSETS[0]) as archive:
        zip_names = set(archive.namelist())
        assert "codex-keysmith-{}/scripts/keysmith_trust.py".format(TAG) in zip_names
        assert "codex-keysmith-{}/scripts/generate_sbom.py".format(TAG) in zip_names
        assert "codex-keysmith-{}/scripts/verify_release.py".format(TAG) in zip_names
        assert "codex-keysmith-{}/scripts/keysmith_signing.py".format(TAG) in zip_names
    with tarfile.open(output_dir / CORE_ASSETS[1], "r:gz") as archive:
        verifier_member = archive.getmember(
            "codex-keysmith-{}/scripts/verify_release.py".format(TAG)
        )
        assert verifier_member.mode & 0o111

    # The standalone verifier embeds the reviewed engine and still compiles.
    standalone = (output_dir / VERIFIER_ASSET).read_text("utf-8")
    assert standalone.startswith("#!/usr/bin/env python3")
    compile(standalone, VERIFIER_ASSET, "exec")
    payload_line = next(
        line for line in standalone.splitlines() if "KEYSMITH_TRUST_ENGINE_PAYLOAD" in line
    )
    assert '= "' in payload_line
    encoded = payload_line.split('= "', 1)[1].rstrip('"')
    engine_bytes = base64.b64decode(encoded)
    assert engine_bytes == (repo / "scripts" / "keysmith_trust.py").read_bytes()
    mode = stat.S_IMODE((output_dir / VERIFIER_ASSET).stat().st_mode)
    assert mode & 0o111


# ---------------------------------------------------------------------------
# TR-7.2 invalid trust inputs are rejected before any asset is published
# ---------------------------------------------------------------------------

def test_trust_build_rejects_lightweight_tag(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=False)
    with pytest.raises(release_builder.ReleaseError, match="annotated tag object"):
        _build_trust(release_builder, repo, tmp_path / "dist")


def test_trust_build_requires_sequence_and_timestamp(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    with pytest.raises(release_builder.ReleaseError, match="--sequence"):
        _build_trust(release_builder, repo, tmp_path / "d1", trust_sequence=0)
    with pytest.raises(release_builder.ReleaseError, match="--issued-at"):
        _build_trust(release_builder, repo, tmp_path / "d2", trust_issued_at="")
    with pytest.raises(release_builder.ReleaseError, match="UTC ISO-8601"):
        _build_trust(
            release_builder,
            repo,
            tmp_path / "d3",
            trust_issued_at="2026-07-18 10:00:00",
        )


def test_trust_build_rejects_bad_builder_info(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    missing_sha = _builder_info()
    del missing_sha["workflow_sha"]
    with pytest.raises(release_builder.ReleaseError, match="workflow_sha"):
        _build_trust(release_builder, repo, tmp_path / "d1", builder_info=missing_sha)
    bad_sha = _builder_info()
    bad_sha["workflow_sha"] = "z" * 40
    with pytest.raises(release_builder.ReleaseError, match="workflow_sha"):
        _build_trust(release_builder, repo, tmp_path / "d2", builder_info=bad_sha)
    bad_manifest = _builder_info()
    bad_manifest["build_manifests"] = {"macos.dmg": "not-a-digest"}
    with pytest.raises(release_builder.ReleaseError, match="sha256"):
        _build_trust(release_builder, repo, tmp_path / "d3", builder_info=bad_manifest)
    with pytest.raises(release_builder.ReleaseError, match="builder info object"):
        _build_trust(release_builder, repo, tmp_path / "d4", builder_info=None)


def test_trust_only_options_without_the_flag_are_rejected(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    with pytest.raises(release_builder.ReleaseError, match="--emit-trust-artifacts"):
        release_builder.build_release(
            TAG, repo, tmp_path / "d1", trust_sequence=3
        )


def test_manifest_contract_rejects_bad_source_bindings(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    # Exercise manifest assembly directly to prove the SBOM layer and the
    # engine schema (validate_release_manifest) both reject malformed bindings.
    version, sources = release_builder._read_and_validate_sources(
        repo,
        TAG,
        extra_source_files=release_builder.TRUST_ARCHIVE_FILES,
    )
    assert version == VERSION

    def staging_dir():
        directory = tmp_path / "staging-{}".format(len(list(tmp_path.iterdir())))
        directory.mkdir()
        for name in list(CORE_ASSETS) + ["SHA256SUMS"]:
            (directory / name).write_bytes(b"x")
        return directory

    with pytest.raises(release_builder.ReleaseError, match="SBOM generation failed"):
        release_builder._emit_trust_artifacts(
            repo_root=repo,
            tag=TAG,
            staging_dir=staging_dir(),
            sources=sources,
            core_asset_names=CORE_ASSETS,
            checksum_name="SHA256SUMS",
            source_commit="g" * 40,
            tag_object="b" * 40,
            source_repo="local",
            sequence=1,
            issued_at=ISSUED_AT,
            builder=_builder_info(),
            required_root_version=1,
            required_revocations_version=0,
        )

    # Well-formed commit format but a malformed annotated tag object: only the
    # manifest schema can catch this, and the error must be wrapped as
    # ReleaseError so the CLI reports a deterministic failure.
    with pytest.raises(release_builder.ReleaseError, match="failed validation"):
        release_builder._emit_trust_artifacts(
            repo_root=repo,
            tag=TAG,
            staging_dir=staging_dir(),
            sources=sources,
            core_asset_names=CORE_ASSETS,
            checksum_name="SHA256SUMS",
            source_commit="a" * 40,
            tag_object="z" * 40,
            source_repo="local",
            sequence=1,
            issued_at=ISSUED_AT,
            builder=_builder_info(),
            required_root_version=1,
            required_revocations_version=0,
        )


# ---------------------------------------------------------------------------
# TR-7.3 repeated trust builds are byte-identical (no wall-clock inputs)
# ---------------------------------------------------------------------------

def test_repeated_trust_builds_are_byte_identical(release_builder, tmp_path):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    first_dir = tmp_path / "dist-a"
    second_dir = tmp_path / "dist-b"
    _build_trust(release_builder, repo, first_dir)
    # The second build must tolerate existing first-run assets and still
    # reproduce identical bytes (idempotent no-overwrite publication).
    _build_trust(release_builder, repo, first_dir)
    _build_trust(release_builder, repo, second_dir)

    names = sorted(path.name for path in first_dir.iterdir() if path.is_file())
    assert "release-manifest.unsigned.json" in names
    for name in names:
        assert (first_dir / name).read_bytes() == (second_dir / name).read_bytes()


def test_cli_reads_builder_info_from_environment(release_builder, tmp_path, monkeypatch):
    repo = _make_repo(tmp_path, release_builder, annotated_tag=True)
    output_dir = tmp_path / "dist-cli"
    monkeypatch.setenv(
        release_builder.BUILDER_INFO_ENV_VAR, json.dumps(_builder_info())
    )
    monkeypatch.setenv(
        release_builder.SOURCE_REPO_ENV_VAR,
        "https://github.com/example/codex-keysmith",
    )
    exit_code = release_builder.main(
        [
            TAG,
            "--repo-root",
            str(repo),
            "--output-dir",
            str(output_dir),
            "--emit-trust-artifacts",
            "--sequence",
            "7",
            "--issued-at",
            ISSUED_AT,
        ]
    )
    assert exit_code == 0
    manifest = _load_manifest(output_dir)
    assert manifest["sequence"] == 7
    assert manifest["builder"]["workflow_name"] == "release.yml"
