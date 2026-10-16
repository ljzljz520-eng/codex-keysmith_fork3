#!/usr/bin/env python3
"""Assemble and verify the public unsigned desktop prerelease assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import validate_desktop_candidate as candidate_validator
else:
    from . import validate_desktop_candidate as candidate_validator


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCT = "codex-keysmith"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
CHECKSUMS_NAME = "SHA256SUMS"
TRUST_UNSIGNED_MANIFEST_NAME = "release-manifest.unsigned.json"
LOCAL_SOURCE_REPO = "local"
DESKTOP_TAG_PREFIX = "desktop-v"
# Platform build manifests ship under flat logical names so the release
# manifest builder.build_manifests digest map can bind both platforms.
BUILD_MANIFEST_LOGICAL_NAMES = {
    "macos": "build-manifest-macos.json",
    "windows": "build-manifest-windows.json",
}
TOOLCHAIN_TO_BUILDER_FIELDS = {
    "node": "node_version",
    "python": "python_version",
    "pyinstaller": "pyinstaller_version",
    "rust": "rust_version",
}


class PrereleaseError(RuntimeError):
    """Raised when an unsigned desktop prerelease invariant is violated."""


def _read_version() -> str:
    raw = (REPO_ROOT / "VERSION").read_text(encoding="ascii").strip()
    if VERSION_RE.fullmatch(raw) is None:
        raise PrereleaseError("VERSION must be a dotted x.y.z source version")
    return raw


VERSION = _read_version()
TAG_RE = re.compile(rf"^desktop-v{re.escape(VERSION)}-beta\.[1-9][0-9]*$")
MACOS_DMG_NAME = f"{PRODUCT}-{VERSION}-macos-arm64-unsigned.dmg"
MACOS_CANDIDATE_ZIP_NAME = f"{PRODUCT}-{VERSION}-macos-arm64-unsigned-candidate.zip"
WINDOWS_SETUP_NAME = f"{PRODUCT}-{VERSION}-windows-x64-unsigned-setup.exe"
WINDOWS_CANDIDATE_ZIP_NAME = f"{PRODUCT}-{VERSION}-windows-x64-unsigned-candidate.zip"
CLI_NAME = f"codex-instruct-v{VERSION}.py"
SOURCE_ZIP_NAME = f"{PRODUCT}-v{VERSION}.zip"
SOURCE_TAR_NAME = f"{PRODUCT}-v{VERSION}.tar.gz"
SCENARIO_BUNDLE_NAME = f"{PRODUCT}-scenarios-v{VERSION}.bundle"

# Retain the legacy names for callers that only need the Windows asset constants.
SETUP_NAME = WINDOWS_SETUP_NAME
CANDIDATE_ZIP_NAME = WINDOWS_CANDIDATE_ZIP_NAME

# Source CLI/archives/bundle stay on the matching v<VERSION> source Release.
SOURCE_RELEASE_PAYLOAD_NAMES = (
    CLI_NAME,
    SOURCE_ZIP_NAME,
    SOURCE_TAR_NAME,
    SCENARIO_BUNDLE_NAME,
)
PUBLIC_PAYLOAD_NAMES = (
    MACOS_DMG_NAME,
    MACOS_CANDIDATE_ZIP_NAME,
    WINDOWS_SETUP_NAME,
    WINDOWS_CANDIDATE_ZIP_NAME,
)
PUBLIC_ASSET_NAMES = (*PUBLIC_PAYLOAD_NAMES, CHECKSUMS_NAME)

PLATFORM_CONFIGS = {
    "macos": {
        "target": {
            "platform": "macos",
            "architecture": "arm64",
            "triple": "aarch64-apple-darwin",
            "bundle_format": "dmg",
            "signing_mode": "unsigned",
        },
        "bundle_suffix": ".dmg",
        "public_bundle": MACOS_DMG_NAME,
        "candidate_zip": MACOS_CANDIDATE_ZIP_NAME,
        "fixed_files": {
            "build-manifest.json",
            "codex-keysmith-gui",
            "codex-keysmith-cli",
            "icon.icns",
            CHECKSUMS_NAME,
        },
    },
    "windows": {
        "target": {
            "platform": "windows",
            "architecture": "x86_64",
            "triple": "x86_64-pc-windows-msvc",
            "bundle_format": "nsis",
            "signing_mode": "unsigned",
        },
        "bundle_suffix": ".exe",
        "public_bundle": WINDOWS_SETUP_NAME,
        "candidate_zip": WINDOWS_CANDIDATE_ZIP_NAME,
        "fixed_files": {
            "build-manifest.json",
            "codex-keysmith-gui.exe",
            "codex-keysmith-cli.exe",
            "icon.ico",
            CHECKSUMS_NAME,
        },
    },
}


def _require_regular_file(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except OSError as exc:
        raise PrereleaseError(f"missing prerelease file {path}: {exc}") from exc
    if not stat.S_ISREG(mode):
        raise PrereleaseError(f"prerelease path must be a regular file, not a symlink: {path}")


def _sha256(path: Path) -> str:
    _require_regular_file(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    _require_regular_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrereleaseError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PrereleaseError(f"expected a JSON object in {path}")
    return value


def _validate_tag_and_commit(tag: str, expected_commit: str) -> None:
    if TAG_RE.fullmatch(tag) is None:
        raise PrereleaseError(
            f"release tag must match desktop-v{VERSION}-beta.N with N starting at 1"
        )
    if COMMIT_RE.fullmatch(expected_commit) is None:
        raise PrereleaseError("expected commit must be a full lowercase 40-character SHA")


def _validate_candidate(
    candidate_dir: Path,
    expected_commit: str,
    platform: str,
) -> dict[str, Any]:
    config = PLATFORM_CONFIGS[platform]
    candidate_dir = candidate_dir.absolute()
    if not candidate_dir.is_dir() or candidate_dir.is_symlink():
        raise PrereleaseError(f"candidate directory is missing or unsafe: {candidate_dir}")
    manifest_path = candidate_dir / "build-manifest.json"
    manifest = _read_json(manifest_path)
    if manifest.get("desktop_version") != VERSION or manifest.get("cli_version") != VERSION:
        raise PrereleaseError(f"candidate versions must both be {VERSION}")
    if manifest.get("source_commit") != expected_commit:
        raise PrereleaseError("candidate manifest source commit does not match expected commit")
    if manifest.get("target") != config["target"]:
        raise PrereleaseError(f"candidate must match the unsigned {platform} target policy")
    provenance = manifest.get("sidecar_provenance")
    if not isinstance(provenance, dict) or provenance.get("relation") != "exact-copy":
        raise PrereleaseError("unsigned candidate sidecar must be the exact tested build output")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise PrereleaseError("candidate manifest artifacts are missing")
    bundle = artifacts.get("bundle")
    if not isinstance(bundle, dict) or not isinstance(bundle.get("file"), str):
        raise PrereleaseError("candidate manifest bundle record is missing")
    bundle_name = bundle["file"]
    if Path(bundle_name).name != bundle_name or not bundle_name.lower().endswith(
        str(config["bundle_suffix"])
    ):
        raise PrereleaseError(f"candidate bundle filename is unsafe or not a {platform} bundle")
    expected_files = set(config["fixed_files"]) | {bundle_name}
    entries = list(candidate_dir.iterdir())
    actual_files = {entry.name for entry in entries}
    if actual_files != expected_files:
        raise PrereleaseError(
            f"candidate directory file set is not exact: expected {sorted(expected_files)}, "
            f"got {sorted(actual_files)}"
        )
    for entry in entries:
        _require_regular_file(entry)
    try:
        candidate_validator.verify_manifest(manifest_path, execute_sidecar=False)
    except candidate_validator.CandidateError as exc:
        raise PrereleaseError(f"candidate manifest verification failed: {exc}") from exc
    return manifest


def _write_deterministic_zip(candidate_dir: Path, destination: Path) -> None:
    with zipfile.ZipFile(
        destination,
        mode="x",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for source in sorted(candidate_dir.iterdir(), key=lambda path: path.name):
            _require_regular_file(source)
            info = zipfile.ZipInfo(source.name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            archive.writestr(
                info,
                source.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )


def _verify_candidate_zip(
    output_dir: Path,
    platform: str,
    expected_commit: str,
) -> str:
    config = PLATFORM_CONFIGS[platform]
    archive_path = output_dir / str(config["candidate_zip"])
    with zipfile.ZipFile(archive_path, "r") as archive:
        names = archive.namelist()
        if names != sorted(names) or len(names) != len(set(names)):
            raise PrereleaseError("candidate ZIP entries must be sorted and unique")
        if any(Path(name).name != name for name in names):
            raise PrereleaseError("candidate ZIP contains an unsafe path")
        for info in archive.infolist():
            if info.is_dir() or info.date_time != (1980, 1, 1, 0, 0, 0):
                raise PrereleaseError("candidate ZIP metadata is not deterministic")
            archived_mode = info.external_attr >> 16
            if stat.S_IFMT(archived_mode) != stat.S_IFREG:
                raise PrereleaseError("candidate ZIP entries must be regular files")
        with tempfile.TemporaryDirectory(prefix="desktop-prerelease-verify-") as raw_temp:
            extracted = Path(raw_temp)
            for info in archive.infolist():
                (extracted / info.filename).write_bytes(archive.read(info))
            manifest = _read_json(extracted / "build-manifest.json")
            manifest_commit = manifest.get("source_commit")
            if not isinstance(manifest_commit, str) or COMMIT_RE.fullmatch(manifest_commit) is None:
                raise PrereleaseError("candidate ZIP manifest source commit is missing or invalid")
            if manifest_commit != expected_commit:
                raise PrereleaseError(
                    "candidate ZIP manifest source commit does not match expected commit"
                )
            verified_manifest = _validate_candidate(extracted, manifest_commit, platform)
            bundle_name = verified_manifest["artifacts"]["bundle"]["file"]
            public_bundle = output_dir / str(config["public_bundle"])
            if _sha256(public_bundle) != _sha256(extracted / bundle_name):
                raise PrereleaseError(
                    f"public {platform} bundle does not match the original bundle in its candidate ZIP"
                )
            return manifest_commit


def verify_public_assets(
    output_dir: Path,
    expected_commit: str,
) -> None:
    if COMMIT_RE.fullmatch(expected_commit) is None:
        raise PrereleaseError("expected commit must be a full lowercase 40-character SHA")
    output_dir = output_dir.absolute()
    if not output_dir.is_dir() or output_dir.is_symlink():
        raise PrereleaseError(f"prerelease output directory is missing or unsafe: {output_dir}")
    entries = list(output_dir.iterdir())
    actual_names = {entry.name for entry in entries}
    if actual_names != set(PUBLIC_ASSET_NAMES):
        raise PrereleaseError(
            f"public asset set is not exact: expected {sorted(PUBLIC_ASSET_NAMES)}, "
            f"got {sorted(actual_names)}"
        )
    leaked = set(actual_names) & set(SOURCE_RELEASE_PAYLOAD_NAMES)
    if leaked:
        raise PrereleaseError(
            "desktop prerelease must not republish source-release assets: "
            + ", ".join(sorted(leaked))
        )
    for entry in entries:
        _require_regular_file(entry)
    try:
        checksum_lines = (output_dir / CHECKSUMS_NAME).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise PrereleaseError(f"cannot read public SHA256SUMS: {exc}") from exc
    expected_lines = [
        f"{_sha256(output_dir / name)}  {name}" for name in sorted(PUBLIC_PAYLOAD_NAMES)
    ]
    if checksum_lines != expected_lines:
        raise PrereleaseError("public SHA256SUMS does not exactly cover all public payloads")
    macos_commit = _verify_candidate_zip(output_dir, "macos", expected_commit)
    windows_commit = _verify_candidate_zip(output_dir, "windows", expected_commit)
    if macos_commit != windows_commit:
        raise PrereleaseError("macOS and Windows candidate manifests do not bind the same commit")


# ---------------------------------------------------------------------------
# Signed desktop-beta trust artifacts (opt-in via emit_trust_artifacts)
# ---------------------------------------------------------------------------


def _trust_stack():
    """Lazily import the trust toolchain so the default path stays unchanged."""

    from scripts import build_release, generate_sbom, verify_release
    from scripts import keysmith_trust as trust

    return build_release, generate_sbom, trust, verify_release


def _record_asset(path: Path) -> dict[str, Any]:
    return {"sha256": _sha256(path), "size": path.stat().st_size}


def _render_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _desktop_version_from_tag(tag: str) -> str:
    if not tag.startswith(DESKTOP_TAG_PREFIX):
        raise PrereleaseError("desktop trust manifest tag must start with desktop-v")
    trust = _trust_stack()[2]
    version = tag[len(DESKTOP_TAG_PREFIX) :]
    try:
        trust.parse_semver(version, label="release.version")
    except trust.MetadataError as exc:
        raise PrereleaseError(str(exc)) from exc
    if trust.expected_tag_for(trust.DESKTOP_BETA_LINE, version) != tag:
        raise PrereleaseError(
            "desktop tag {!r} does not match its desktop-beta version {!r}".format(
                tag, version
            )
        )
    return version


def _validate_trust_arguments(
    *,
    tag: str,
    trust_sequence: Any,
    trust_issued_at: Any,
    builder_info: Any,
    tag_object: Any,
    source_repo: Any,
    required_root_version: Any,
    required_revocations_version: Any,
    repo_root: Path,
) -> str:
    _build_release, _generate_sbom, trust, _verify_release = _trust_stack()
    if not isinstance(trust_sequence, int) or isinstance(trust_sequence, bool) or (
        trust_sequence < 1
    ):
        raise PrereleaseError("trust sequence must be an integer >= 1")
    if not isinstance(trust_issued_at, str) or not trust_issued_at:
        raise PrereleaseError("trust issued-at timestamp is required")
    try:
        trust.require_iso8601_utc(trust_issued_at, "issued_at")
    except trust.MetadataError as exc:
        raise PrereleaseError(str(exc)) from exc
    if not isinstance(builder_info, dict):
        raise PrereleaseError(
            "desktop trust builds require a builder info object "
            "(supply JSON via $CODEX_KEYSMITH_BUILDER_INFO)"
        )
    if not isinstance(source_repo, str) or not source_repo:
        raise PrereleaseError("source repo identifier must be a non-empty string")
    if (
        not isinstance(required_root_version, int)
        or isinstance(required_root_version, bool)
        or required_root_version < 1
    ):
        raise PrereleaseError("required root metadata version must be an integer >= 1")
    if (
        not isinstance(required_revocations_version, int)
        or isinstance(required_revocations_version, bool)
        or required_revocations_version < 0
    ):
        raise PrereleaseError("required revocations version must be a non-negative integer")
    if tag_object is None:
        try:
            tag_object = _build_release._resolve_annotated_tag_object(repo_root, tag)
        except _build_release.ReleaseError as exc:
            raise PrereleaseError(str(exc)) from exc
    elif not isinstance(tag_object, str) or not re.fullmatch(r"[0-9a-f]{40}", tag_object):
        raise PrereleaseError("tag object must be a 40-character lowercase SHA-1")
    return tag_object


def _build_desktop_builder(
    builder_info: dict[str, Any],
    identities: dict[str, dict[str, Any]],
    build_manifest_digests: dict[str, str],
):
    build_release = _trust_stack()[0]
    macos_toolchain = identities["macos"]["toolchain"]
    if identities["windows"]["toolchain"] != macos_toolchain:
        raise PrereleaseError(
            "macOS and Windows build manifests disagree about the build toolchain: "
            "{} vs {}".format(
                macos_toolchain, identities["windows"]["toolchain"]
            )
        )
    raw = dict(builder_info)
    raw.setdefault("python_version", macos_toolchain["python"])
    try:
        builder = build_release._normalise_builder_info(raw)
    except build_release.ReleaseError as exc:
        raise PrereleaseError(str(exc)) from exc
    # The candidate build manifests are the authoritative toolchain record;
    # builder info may only agree, never disagree.
    for candidate_field, builder_field in TOOLCHAIN_TO_BUILDER_FIELDS.items():
        candidate_value = macos_toolchain[candidate_field]
        supplied = builder[builder_field]
        if supplied and supplied != candidate_value:
            raise PrereleaseError(
                "builder info {} {!r} disagrees with the candidate build-manifest "
                "toolchain {!r}".format(builder_field, supplied, candidate_value)
            )
        builder[builder_field] = candidate_value
    builder["build_manifests"] = dict(build_manifest_digests)
    return builder


def _emit_desktop_trust_artifacts(
    *,
    staging: Path,
    candidate_dirs: dict[str, Path],
    manifests: dict[str, dict[str, Any]],
    tag: str,
    expected_commit: str,
    sequence: int,
    issued_at: str,
    builder_info: dict[str, Any],
    source_repo: str,
    tag_object: str,
    repo_root: Path,
    required_root_version: int,
    required_revocations_version: int,
) -> dict[str, Any]:
    """Emit build manifests, standalone verifier, dual SBOMs and unsigned manifest."""

    build_release, generate_sbom, trust, _verify_release = _trust_stack()
    version = _desktop_version_from_tag(tag)

    # Extract each shipped build-manifest.json straight from its candidate ZIP
    # so the bound digest covers exactly the bytes users can download, and
    # prove cross-platform identity agreement (commit/triple/version/toolchain).
    identities: dict[str, dict[str, Any]] = {}
    build_manifest_digests: dict[str, str] = {}
    for platform in ("macos", "windows"):
        config = PLATFORM_CONFIGS[platform]
        logical_name = BUILD_MANIFEST_LOGICAL_NAMES[platform]
        with zipfile.ZipFile(staging / str(config["candidate_zip"]), "r") as archive:
            manifest_bytes = archive.read("build-manifest.json")
        if manifest_bytes != (candidate_dirs[platform] / "build-manifest.json").read_bytes():
            raise PrereleaseError(
                f"candidate ZIP build-manifest.json differs from the validated {platform} input"
            )
        (staging / logical_name).write_bytes(manifest_bytes)
        os.chmod(staging / logical_name, 0o644)
        build_manifest_digests[logical_name] = hashlib.sha256(manifest_bytes).hexdigest()
        try:
            identity = candidate_validator.manifest_identity(
                json.loads(manifest_bytes.decode("utf-8"))
            )
        except candidate_validator.CandidateError as exc:
            raise PrereleaseError(f"{platform} build manifest identity is invalid: {exc}") from exc
        if identity["desktop_version"] != VERSION or identity["cli_version"] != VERSION:
            raise PrereleaseError(f"{platform} build manifest versions must both be {VERSION}")
        if identity["source_commit"] != expected_commit:
            raise PrereleaseError(
                f"{platform} build manifest source commit does not match expected commit"
            )
        if identity["target"] != config["target"]:
            raise PrereleaseError(
                f"{platform} build manifest target does not match the unsigned target policy"
            )
        identities[platform] = identity

    builder = _build_desktop_builder(builder_info, identities, build_manifest_digests)

    verifier_name = build_release.VERIFIER_STANDALONE_NAME.format(tag)
    verifier_path = staging / verifier_name
    try:
        verifier_bytes = build_release._verifier_standalone_bytes(
            (repo_root / "scripts" / "verify_release.py").read_bytes(),
            (repo_root / "scripts" / "keysmith_trust.py").read_bytes(),
            (repo_root / "LICENSE").read_bytes(),
        )
    except (OSError, build_release.ReleaseError) as exc:
        raise PrereleaseError(f"cannot compose standalone verifier: {exc}") from exc
    verifier_path.write_bytes(verifier_bytes)
    verifier_path.chmod(0o755)

    artifact_names = list(PUBLIC_PAYLOAD_NAMES) + [CHECKSUMS_NAME, verifier_name]
    extra_files = [
        (name, staging / name)
        for name in artifact_names + [BUILD_MANIFEST_LOGICAL_NAMES[p] for p in ("macos", "windows")]
    ]
    try:
        spdx_document, cdx_document, _ = generate_sbom.build_documents(
            repo_root=repo_root,
            release_line=trust.DESKTOP_BETA_LINE,
            version=version,
            issued_at=issued_at,
            source_commit=expected_commit,
            builder=builder,
            fixed_files=(),
            include_desktop=True,
            extra_files=extra_files,
        )
    except generate_sbom.SbomError as exc:
        raise PrereleaseError(f"desktop release SBOM generation failed: {exc}") from exc
    spdx_name, cdx_name = generate_sbom.sbom_asset_names(tag)
    spdx_path = staging / spdx_name
    cdx_path = staging / cdx_name
    spdx_path.write_bytes(generate_sbom.render_document(spdx_document))
    cdx_path.write_bytes(generate_sbom.render_document(cdx_document))
    spdx_path.chmod(0o644)
    cdx_path.chmod(0o644)

    manifest: dict[str, Any] = {
        "_type": trust.RELEASE_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": trust.DESKTOP_BETA_LINE,
        "version": version,
        "tag": tag,
        "sequence": sequence,
        "issued_at": issued_at,
        "source": {
            "repo": source_repo,
            "commit": expected_commit,
            "tag_object": tag_object,
        },
        "builder": builder,
        "artifacts": {name: _record_asset(staging / name) for name in artifact_names},
        "sboms": {
            spdx_name: _record_asset(spdx_path),
            cdx_name: _record_asset(cdx_path),
        },
        "required_root_version": required_root_version,
        "required_revocations_version": required_revocations_version,
    }
    try:
        trust.validate_release_manifest(manifest)
    except trust.MetadataError as exc:
        raise PrereleaseError(f"unsigned desktop release manifest failed validation: {exc}") from exc
    manifest_path = staging / TRUST_UNSIGNED_MANIFEST_NAME
    manifest_path.write_bytes(_render_manifest_bytes(manifest))
    manifest_path.chmod(0o644)
    return manifest


def verify_trust_prerelease(output_dir: Path, expected_commit: str) -> dict[str, Any]:
    """Recompute every binding of an unsigned desktop-beta trust set on disk."""

    output_dir = output_dir.absolute()
    if not output_dir.is_dir() or output_dir.is_symlink():
        raise PrereleaseError(f"prerelease output directory is missing or unsafe: {output_dir}")
    _build_release, _generate_sbom, trust, verify_release = _trust_stack()
    try:
        manifest = json.loads(
            (output_dir / TRUST_UNSIGNED_MANIFEST_NAME).read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PrereleaseError(f"cannot read unsigned trust manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PrereleaseError("unsigned trust manifest must be a JSON object")
    try:
        trust.validate_release_manifest(manifest)
    except trust.MetadataError as exc:
        raise PrereleaseError(f"unsigned desktop release manifest failed validation: {exc}") from exc
    if manifest["release_line"] != trust.DESKTOP_BETA_LINE:
        raise PrereleaseError("unsigned manifest is not on the desktop-beta release line")
    if manifest["source"]["commit"] != expected_commit:
        raise PrereleaseError("unsigned manifest source commit does not match expected commit")
    version = _desktop_version_from_tag(str(manifest["tag"]))
    if version != manifest["version"]:
        raise PrereleaseError("unsigned manifest tag/version pair is inconsistent")

    # Classic unsigned assets must still satisfy the fixed public-asset policy.
    for name in PUBLIC_ASSET_NAMES:
        _require_regular_file(output_dir / name)
    checksum_lines = (output_dir / CHECKSUMS_NAME).read_text(encoding="ascii").splitlines()
    expected_lines = [
        f"{_sha256(output_dir / name)}  {name}" for name in sorted(PUBLIC_PAYLOAD_NAMES)
    ]
    if checksum_lines != expected_lines:
        raise PrereleaseError("public SHA256SUMS does not exactly cover all public payloads")
    macos_commit = _verify_candidate_zip(output_dir, "macos", expected_commit)
    windows_commit = _verify_candidate_zip(output_dir, "windows", expected_commit)
    if macos_commit != expected_commit or windows_commit != expected_commit:
        raise PrereleaseError("candidate ZIP manifests do not bind the expected commit")

    # Every artifact/SBOM digest and size must recompute from on-disk bytes.
    for name, record in manifest["artifacts"].items():
        actual = _record_asset(output_dir / name)
        if actual != record:
            raise PrereleaseError(
                f"artifact {name} digest/size changed after manifest emission:\n"
                f"  manifest {record}\n  disk     {actual}"
            )
    for name, record in manifest["sboms"].items():
        actual = _record_asset(output_dir / name)
        if actual != record:
            raise PrereleaseError(
                f"SBOM {name} digest/size changed after manifest emission:\n"
                f"  manifest {record}\n  disk     {actual}"
            )
        try:
            verify_release._check_sbom_document(name, (output_dir / name).read_bytes())
        except verify_release.VerificationError as exc:
            raise PrereleaseError(str(exc)) from exc

    # Both platform build manifests must be present, byte-identical to their
    # candidate ZIP members, and carry consistent identity/toolchain records.
    build_manifests = manifest["builder"]["build_manifests"]
    if set(build_manifests) != {
        BUILD_MANIFEST_LOGICAL_NAMES["macos"],
        BUILD_MANIFEST_LOGICAL_NAMES["windows"],
    }:
        raise PrereleaseError(
            "desktop builder must bind exactly the macOS and Windows build manifests"
        )
    identities = {}
    for platform in ("macos", "windows"):
        config = PLATFORM_CONFIGS[platform]
        logical_name = BUILD_MANIFEST_LOGICAL_NAMES[platform]
        data = (output_dir / logical_name).read_bytes()
        if hashlib.sha256(data).hexdigest() != build_manifests[logical_name]:
            raise PrereleaseError(f"build manifest digest does not match {logical_name}")
        with zipfile.ZipFile(output_dir / str(config["candidate_zip"]), "r") as archive:
            if archive.read("build-manifest.json") != data:
                raise PrereleaseError(
                    f"{logical_name} differs from the {platform} candidate ZIP member"
                )
        try:
            parsed = json.loads(data.decode("utf-8"))
            identity = candidate_validator.manifest_identity(parsed)
        except (UnicodeError, json.JSONDecodeError, candidate_validator.CandidateError) as exc:
            raise PrereleaseError(f"{logical_name} identity is invalid: {exc}") from exc
        if (
            identity["desktop_version"] != VERSION
            or identity["cli_version"] != VERSION
            or identity["source_commit"] != expected_commit
            or identity["target"] != config["target"]
        ):
            raise PrereleaseError(f"{logical_name} identity does not match the release policy")
        identities[platform] = identity
    if identities["macos"]["toolchain"] != identities["windows"]["toolchain"]:
        raise PrereleaseError("platform build manifests disagree about the toolchain")

    verifier_name = _build_release.VERIFIER_STANDALONE_NAME.format(str(manifest["tag"]))
    verifier_data = (output_dir / verifier_name).read_bytes()
    if not verifier_data.startswith(b"#!") or (
        _build_release.VERIFIER_ENGINE_MARKER in verifier_data
    ):
        raise PrereleaseError(f"standalone verifier {verifier_name} was not composed correctly")

    actual_names = {entry.name for entry in output_dir.iterdir() if entry.is_file()}
    expected_names = (
        set(manifest["artifacts"])
        | set(manifest["sboms"])
        | set(build_manifests)
        | {TRUST_UNSIGNED_MANIFEST_NAME}
    )
    if actual_names != expected_names:
        raise PrereleaseError(
            "desktop trust asset set is not exact: expected {}, got {}".format(
                sorted(expected_names), sorted(actual_names)
            )
        )
    return manifest


def assemble_prerelease(
    macos_candidate_dir: Path,
    windows_candidate_dir: Path,
    output_dir: Path,
    tag: str,
    expected_commit: str,
    *,
    emit_trust_artifacts: bool = False,
    trust_sequence: Any = None,
    trust_issued_at: Any = None,
    builder_info: Any = None,
    source_repo: str = LOCAL_SOURCE_REPO,
    tag_object: Any = None,
    repo_root: Path | None = None,
    required_root_version: int = 1,
    required_revocations_version: int = 0,
) -> Path:
    _validate_tag_and_commit(tag, expected_commit)
    repo_root = (repo_root or REPO_ROOT).absolute()
    if emit_trust_artifacts:
        resolved_tag_object = _validate_trust_arguments(
            tag=tag,
            trust_sequence=trust_sequence,
            trust_issued_at=trust_issued_at,
            builder_info=builder_info,
            tag_object=tag_object,
            source_repo=source_repo,
            required_root_version=required_root_version,
            required_revocations_version=required_revocations_version,
            repo_root=repo_root,
        )
    elif any(
        value is not None
        for value in (
            trust_sequence,
            trust_issued_at,
            builder_info,
            tag_object,
        )
    ) or source_repo != LOCAL_SOURCE_REPO or (
        required_root_version,
        required_revocations_version,
    ) != (1, 0):
        raise PrereleaseError("trust-only options require emit_trust_artifacts=True")
    candidate_dirs = {
        "macos": macos_candidate_dir.absolute(),
        "windows": windows_candidate_dir.absolute(),
    }
    manifests = {
        platform: _validate_candidate(candidate_dir, expected_commit, platform)
        for platform, candidate_dir in candidate_dirs.items()
    }
    output_dir = output_dir.absolute()
    if output_dir.exists():
        if output_dir.is_symlink() or not output_dir.is_dir() or any(output_dir.iterdir()):
            raise PrereleaseError(f"output directory must be absent or empty: {output_dir}")
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".desktop-prerelease-", dir=output_dir.parent))
    try:
        for platform, candidate_dir in candidate_dirs.items():
            config = PLATFORM_CONFIGS[platform]
            bundle_name = manifests[platform]["artifacts"]["bundle"]["file"]
            public_bundle = temporary / str(config["public_bundle"])
            shutil.copyfile(candidate_dir / bundle_name, public_bundle)
            os.chmod(public_bundle, 0o644)
            _write_deterministic_zip(
                candidate_dir,
                temporary / str(config["candidate_zip"]),
            )
        checksum_lines = [
            f"{_sha256(temporary / name)}  {name}"
            for name in sorted(PUBLIC_PAYLOAD_NAMES)
        ]
        (temporary / CHECKSUMS_NAME).write_text(
            "\n".join(checksum_lines) + "\n",
            encoding="ascii",
        )
        # The classic set must be exact before the trust extras are staged.
        verify_public_assets(temporary, expected_commit)
        if emit_trust_artifacts:
            _emit_desktop_trust_artifacts(
                staging=temporary,
                candidate_dirs=candidate_dirs,
                manifests=manifests,
                tag=tag,
                expected_commit=expected_commit,
                sequence=trust_sequence,
                issued_at=trust_issued_at,
                builder_info=builder_info,
                source_repo=source_repo,
                tag_object=resolved_tag_object,
                repo_root=repo_root,
                required_root_version=required_root_version,
                required_revocations_version=required_revocations_version,
            )
        if output_dir.exists():
            output_dir.rmdir()
        temporary.rename(output_dir)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    if emit_trust_artifacts:
        verify_trust_prerelease(output_dir, expected_commit)
    else:
        verify_public_assets(output_dir, expected_commit)
    return output_dir


# Keep the environment contract identical to scripts/build_release.py.
BUILDER_INFO_ENV_VAR = "CODEX_KEYSMITH_BUILDER_INFO"
SOURCE_REPO_ENV_VAR = "CODEX_KEYSMITH_SOURCE_REPO"


def _read_builder_info() -> dict[str, Any]:
    raw = os.environ.get(BUILDER_INFO_ENV_VAR)
    if raw is None:
        raise PrereleaseError(
            f"desktop trust builds require {BUILDER_INFO_ENV_VAR} to carry a JSON object"
        )
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PrereleaseError(f"${BUILDER_INFO_ENV_VAR} is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise PrereleaseError(f"${BUILDER_INFO_ENV_VAR} must contain a JSON object")
    return value


def _handle_assemble(args: argparse.Namespace) -> None:
    builder_info = _read_builder_info() if args.emit_trust_artifacts else None
    source_repo = LOCAL_SOURCE_REPO
    if args.emit_trust_artifacts:
        source_repo = args.source_repo or os.environ.get(
            SOURCE_REPO_ENV_VAR, LOCAL_SOURCE_REPO
        )
    print(
        assemble_prerelease(
            args.macos_candidate_dir,
            args.windows_candidate_dir,
            args.output_dir,
            args.release_tag,
            args.expected_commit,
            emit_trust_artifacts=args.emit_trust_artifacts,
            trust_sequence=args.trust_sequence,
            trust_issued_at=args.trust_issued_at,
            builder_info=builder_info,
            source_repo=source_repo,
            tag_object=args.tag_object,
            required_root_version=args.required_root_version,
            required_revocations_version=args.required_revocations_version,
        )
    )


def _handle_verify(args: argparse.Namespace) -> None:
    if args.trust:
        verify_trust_prerelease(args.output_dir, args.expected_commit)
    else:
        verify_public_assets(args.output_dir, args.expected_commit)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    assemble = subparsers.add_parser("assemble", help="assemble fixed public prerelease assets")
    assemble.add_argument("--macos-candidate-dir", type=Path, required=True)
    assemble.add_argument("--windows-candidate-dir", type=Path, required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    assemble.add_argument("--release-tag", required=True)
    assemble.add_argument("--expected-commit", required=True)
    assemble.add_argument(
        "--emit-trust-artifacts",
        action="store_true",
        help="also emit the unsigned desktop-beta manifest, SBOMs and verifier",
    )
    assemble.add_argument("--trust-sequence", type=int)
    assemble.add_argument("--trust-issued-at")
    assemble.add_argument("--source-repo")
    assemble.add_argument("--tag-object")
    assemble.add_argument("--required-root-version", type=int, default=1)
    assemble.add_argument("--required-revocations-version", type=int, default=0)
    assemble.set_defaults(handler=_handle_assemble)
    verify = subparsers.add_parser("verify", help="verify the fixed public asset set")
    verify.add_argument("output_dir", type=Path)
    verify.add_argument("--expected-commit", required=True)
    verify.add_argument(
        "--trust",
        action="store_true",
        help="verify the signed-line desktop-beta set (manifest, SBOMs, verifier)",
    )
    verify.set_defaults(handler=_handle_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        args.handler(args)
    except (OSError, zipfile.BadZipFile, PrereleaseError) as exc:
        print(f"desktop prerelease packaging failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
