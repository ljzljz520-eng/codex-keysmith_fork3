#!/usr/bin/env python3
"""Offline release verifier for codex-keysmith (FR-8 .. FR-16).

The verification order is fixed and fail-closed:

    root bootstrap / no-rollback
        -> metadata schema, signatures and thresholds
        -> release keyids not revoked
        -> release-index pins exactly this manifest
        -> every artifact/SBOM sha256 and size (streaming)
        -> SHA256SUMS internal consistency / desktop build manifests
        -> revocations (keys, releases, artifacts)
        -> local water-mark / downgrade / security-exception decision
        -> optional Rekor SET + RFC 6962 inclusion (only with --rekor)
        -> atomic state update and append-only audit

The default path performs no network IO.  ``--refresh-online`` and
``--rekor`` are explicit, opt-in online surfaces; their network helpers are
imported lazily so this file stays importable (and socket-free) offline.

This file is also the template for the single-file ``verify-release-<tag>.py``
release asset: build_release.py replaces the marker below with the embedded
keysmith_trust engine payload.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# build_release.py replaces this marker with the base64-embedded engine when
# composing the standalone verify-release-<tag>.py asset.
KEYSMITH_TRUST_ENGINE_PAYLOAD = None

SPDX_VERSION = "SPDX-2.3"
CDX_VERSION = "1.6"

SIGNED_MANIFEST_NAME = "release-manifest.json"
UNSIGNED_MANIFEST_NAME = "release-manifest.unsigned.json"
INDEX_NAME = "release-index.json"
REKOR_ENTRY_NAME = "rekor-entry.json"
ROOT_BUNDLE_NAME = "root.json"
REVOCATIONS_BUNDLE_NAME = "revocations.json"
CHECKSUMS_NAME = "SHA256SUMS"
ONLINE_TIMEOUT_SECONDS = 15.0

VERIFIER_PRODUCT = "codex-keysmith verify-release"


def _load_engine():
    """Return the trust engine module from source tree or embedded payload."""

    if KEYSMITH_TRUST_ENGINE_PAYLOAD is not None:
        module = types.ModuleType("keysmith_trust")
        engine_bytes = base64.b64decode(KEYSMITH_TRUST_ENGINE_PAYLOAD)
        exec(  # noqa: S102 - deliberate standalone engine bootstrap
            compile(engine_bytes, "<embedded keysmith_trust.py>", "exec"),
            module.__dict__,
        )
        return module
    from scripts import keysmith_trust as engine

    return engine


trust = _load_engine()


class VerificationError(RuntimeError):
    """A failure at a specific verification layer (carries an exit code)."""

    def __init__(self, exit_code: int, stage: str, message: str):
        super().__init__(message)
        self.exit_code = exit_code
        self.stage = stage


# Exception -> (exit code, stage), most specific first.
_EXCEPTION_LAYER = (
    (trust.RevocationError, trust.EXIT_REVOKED, "revocation"),
    (trust.DowngradeError, trust.EXIT_DOWNGRADE, "downgrade"),
    (trust.RekorError, trust.EXIT_REKOR, "rekor"),
    (trust.StateError, trust.EXIT_STATE, "state"),
    (trust.DigestError, trust.EXIT_DIGEST, "digest"),
    (trust.SignatureError, trust.EXIT_SIGNATURE, "signature"),
    (trust.PolicyError, trust.EXIT_SIGNATURE, "policy"),
    (trust.MetadataError, trust.EXIT_SIGNATURE, "metadata"),
)


def _fail(exit_code: int, stage: str, message: str) -> None:
    raise VerificationError(exit_code, stage, message)


# ---------------------------------------------------------------------------
# Online surfaces (lazy imports; never used on the default path)
# ---------------------------------------------------------------------------


def https_fetch(url: str, *, timeout: float = ONLINE_TIMEOUT_SECONDS) -> bytes:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise OnlineNotFound(url) from exc
        raise trust.TrustError(
            "online refresh of {} failed: HTTP {}".format(url, exc.code)
        ) from exc
    try:
        return response.read()
    finally:
        response.close()


class OnlineNotFound(trust.TrustError):
    """Raised when an online metadata URL answers 404 (freshness probe)."""


def git_ls_remote(repo_url: str, tag: str) -> Tuple[str, str]:
    """Return (annotated_tag_object_sha, peeled_commit_sha) for an annotated tag."""

    import subprocess

    try:
        completed = subprocess.run(
            ["git", "ls-remote", repo_url, "refs/tags/{}".format(tag)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=ONLINE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise trust.TrustError(
            "git ls-remote against {} failed: {}".format(repo_url, exc)
        ) from exc
    if completed.returncode != 0:
        raise trust.TrustError(
            "git ls-remote against {} failed: {}".format(
                repo_url, completed.stderr.decode("utf-8", "replace").strip()
            )
        )
    object_sha = None
    peeled_sha = None
    wanted = "refs/tags/{}".format(tag)
    for line in completed.stdout.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        sha, _, ref = line.partition("\t")
        if ref == wanted:
            object_sha = sha.strip()
        elif ref == wanted + "^{}":
            peeled_sha = sha.strip()
    if object_sha is None:
        raise trust.TrustError("remote repository has no tag {}".format(tag))
    if peeled_sha is None:
        raise trust.TrustError("remote tag {} is not an annotated tag object".format(tag))
    return object_sha, peeled_sha


# ---------------------------------------------------------------------------
# Metadata resolution (root, revocations, index)
# ---------------------------------------------------------------------------


def _read_json_envelope(path: Path, label: str) -> dict:
    try:
        data = trust.read_regular_file(path)
    except trust.StateError as exc:
        _fail(trust.EXIT_SIGNATURE, label, str(exc))
    try:
        return trust.load_envelope(data, label)
    except trust.MetadataError as exc:
        _fail(trust.EXIT_SIGNATURE, label, "{}: {}".format(label, exc))


def _canonical_fingerprint(envelope: dict) -> str:
    return trust.canonical_sha256(envelope["signed"])


def resolve_root(
    *,
    root_file: Optional[Path],
    trust_dir: Path,
    release_dir: Path,
    online: Optional[Dict[str, Callable]],
    now_iso: str,
) -> Tuple[dict, dict, bool, bool, List[str]]:
    """Return (root_signed, root_envelope, was_tofu, was_rotated, warnings)."""

    warnings: List[str] = []
    was_rotated = False
    cached_envelope = trust.read_cached_envelope(trust_dir, trust.ROOT_TYPE)
    if cached_envelope is not None:
        try:
            trust.validate_root_signed(cached_envelope["signed"])
        except trust.MetadataError as exc:
            _fail(
                trust.EXIT_STATE,
                "state",
                "pinned root metadata is unusable: {}".format(exc),
            )
    candidate_envelope = None
    candidate_source = None

    if root_file is not None:
        candidate_envelope = _read_json_envelope(root_file, "root metadata")
        candidate_source = "--root-file"
    elif online is not None:
        target_version = (
            cached_envelope["signed"]["version"] + 1 if cached_envelope is not None else 1
        )
        policy = trust.load_policy()
        url = trust.policy_channel_url(
            policy, "root_url_template", version=str(target_version)
        )
        try:
            candidate_envelope = trust.load_envelope(online["fetch"](url), "root metadata")
            candidate_source = "online channel"
        except OnlineNotFound:
            candidate_envelope = None
    if candidate_envelope is None:
        bundled = release_dir / ROOT_BUNDLE_NAME
        if bundled.exists():
            candidate_envelope = _read_json_envelope(bundled, "root metadata")
            candidate_source = "release channel copy"

    if candidate_envelope is None and cached_envelope is None:
        _fail(
            trust.EXIT_SIGNATURE,
            "root",
            "no root metadata available; provide --root-file, pin one into the trust "
            "directory, or place {} next to the release".format(ROOT_BUNDLE_NAME),
        )

    was_tofu = cached_envelope is None
    try:
        if cached_envelope is None:
            root_signed = trust.verify_root_document(candidate_envelope, None)
            root_envelope = candidate_envelope
        else:
            cached_signed = trust.validate_root_signed(cached_envelope["signed"])
            if candidate_envelope is None:
                # No fresh feed: keep using the pinned root.
                root_signed = cached_signed
                root_envelope = cached_envelope
            else:
                candidate_signed = trust.validate_root_signed(
                    candidate_envelope["signed"]
                )
                pinned_version = cached_signed["version"]
                offered_version = candidate_signed["version"]
                if offered_version == pinned_version:
                    if _canonical_fingerprint(
                        candidate_envelope
                    ) != _canonical_fingerprint(cached_envelope):
                        _fail(
                            trust.EXIT_SIGNATURE,
                            "root",
                            "root v{} from {!r} differs from the pinned root; a same-version "
                            "silent replacement is refused".format(
                                pinned_version, candidate_source
                            ),
                        )
                    root_signed = cached_signed
                    root_envelope = cached_envelope
                elif offered_version == pinned_version + 1:
                    root_signed = trust.verify_root_document(
                        candidate_envelope, cached_signed
                    )
                    root_envelope = candidate_envelope
                    was_rotated = True
                elif offered_version < pinned_version:
                    _fail(
                        trust.EXIT_SIGNATURE,
                        "root",
                        "root v{} from {!r} is older than the pinned root v{}; a root "
                        "rollback is refused (retained root history still verifies older "
                        "releases)".format(
                            offered_version, candidate_source, pinned_version
                        ),
                    )
                else:
                    _fail(
                        trust.EXIT_SIGNATURE,
                        "root",
                        "root rotation from v{} to v{} skips intermediate versions".format(
                            pinned_version, offered_version
                        ),
                    )
    except VerificationError:
        raise
    except trust.TrustError as exc:
        _fail(trust.EXIT_SIGNATURE, "root", str(exc))

    if was_tofu:
        warnings.append(
            "TOFU: trusting root v{} from {}.\n"
            "  root fingerprint: {}\n"
            "  Compare this fingerprint against the value published through the "
            "maintainer out-of-band channels before relying on it; pin it with "
            "--root-file afterwards.".format(
                root_signed["version"],
                candidate_source,
                trust.grouped_hex(trust.root_fingerprint(root_signed)),
            )
        )
    if root_signed["expires"] <= now_iso:
        warnings.append(
            "root v{} expired at {}; signatures still verify but obtain a fresh root "
            "document.".format(root_signed["version"], root_signed["expires"])
        )
    return root_signed, root_envelope, was_tofu, was_rotated, warnings


def resolve_revocations(
    *,
    revocations_file: Optional[Path],
    trust_dir: Path,
    release_dir: Path,
    root_signed: dict,
    required_version: int,
    online: Optional[Dict[str, Callable]],
) -> Tuple[Optional[dict], Optional[dict], bool, List[str]]:
    """Return (signed or None, envelope or None, was_updated, warnings)."""

    warnings: List[str] = []
    cached_envelope = trust.read_cached_envelope(trust_dir, trust.REVOCATIONS_TYPE)
    if cached_envelope is not None:
        try:
            trust.validate_revocations(cached_envelope["signed"])
        except trust.MetadataError as exc:
            _fail(
                trust.EXIT_STATE,
                "state",
                "pinned revocations metadata is unusable: {}".format(exc),
            )

    candidate_envelope = None
    if revocations_file is not None:
        candidate_envelope = _read_json_envelope(
            revocations_file, "revocations metadata"
        )
    elif online is not None:
        target_version = (
            cached_envelope["signed"]["version"] + 1 if cached_envelope else 1
        )
        policy = trust.load_policy()
        url = trust.policy_channel_url(
            policy, "revocations_url_template", version=str(target_version)
        )
        try:
            candidate_envelope = trust.load_envelope(
                online["fetch"](url), "revocations metadata"
            )
        except OnlineNotFound:
            candidate_envelope = None
    if candidate_envelope is None:
        bundled = release_dir / REVOCATIONS_BUNDLE_NAME
        if bundled.exists():
            candidate_envelope = _read_json_envelope(bundled, "revocations metadata")
    if candidate_envelope is None:
        candidate_envelope = cached_envelope

    if candidate_envelope is None:
        if required_version > 0:
            _fail(
                trust.EXIT_SIGNATURE,
                "revocations",
                "manifest requires revocations v{} but no revocations document is "
                "available".format(required_version),
            )
        return None, None, False, warnings

    cached_signed = cached_envelope["signed"] if cached_envelope else None
    try:
        candidate_signed = trust.verify_revocations_signature(
            candidate_envelope, root_signed
        )
        if cached_signed is not None:
            if candidate_signed["version"] == cached_signed["version"]:
                if trust.canonical_sha256(
                    candidate_signed
                ) != trust.canonical_sha256(cached_signed):
                    _fail(
                        trust.EXIT_SIGNATURE,
                        "revocations",
                        "revocations v{} from the channel differs from the pinned copy; "
                        "a same-version silent replacement is refused".format(
                            cached_signed["version"]
                        ),
                    )
            else:
                trust.ensure_revocations_cumulative(candidate_signed, cached_signed)
    except VerificationError:
        raise
    except trust.TrustError as exc:
        layer = (
            trust.EXIT_REVOKED
            if isinstance(exc, trust.RevocationError)
            else trust.EXIT_SIGNATURE
        )
        _fail(layer, "revocations", str(exc))

    if candidate_signed["version"] < required_version:
        _fail(
            trust.EXIT_SIGNATURE,
            "revocations",
            "revocations v{} is older than the manifest-required v{}".format(
                candidate_signed["version"], required_version
            ),
        )
    was_updated = cached_signed is None or (
        candidate_signed["version"] > cached_signed["version"]
    )
    if trust.revocations_is_expired(candidate_signed, trust.utc_now_iso()):
        warnings.append(
            "revocations v{} expired at {}; listed revocations stay in force. Refresh "
            "with --refresh-online or a fresh --revocations-file.".format(
                candidate_signed["version"], candidate_signed["expires"]
            )
        )
    return candidate_signed, candidate_envelope, was_updated, warnings


def resolve_index(
    *,
    release_dir: Path,
    trust_dir: Path,
    root_signed: dict,
    era_root_signed: Optional[dict],
    manifest_envelope: dict,
    online: Optional[Dict[str, Callable]],
) -> Tuple[dict, dict, dict, bool]:
    """Return (index_signed, index_envelope, index_entry, was_updated)."""

    candidate_envelope = None
    if online is not None:
        try:
            policy = trust.load_policy()
            url = trust.policy_channel_url(policy, "release_index_url_template")
            candidate_envelope = trust.load_envelope(
                online["fetch"](url), "release-index metadata"
            )
        except OnlineNotFound:
            candidate_envelope = None
    if candidate_envelope is None:
        candidate_envelope = _read_json_envelope(
            release_dir / INDEX_NAME, "release-index metadata"
        )
    cached_envelope = trust.read_cached_envelope(trust_dir, trust.RELEASE_INDEX_TYPE)
    if cached_envelope is not None:
        try:
            trust.validate_release_index(cached_envelope["signed"])
        except trust.MetadataError as exc:
            _fail(
                trust.EXIT_STATE,
                "state",
                "pinned release-index is unusable: {}".format(exc),
            )
    try:
        candidate_signed = trust.validate_release_index(candidate_envelope["signed"])
    except trust.TrustError as exc:
        layer = trust.EXIT_DIGEST if isinstance(exc, trust.DigestError) else trust.EXIT_SIGNATURE
        _fail(layer, "index", str(exc))

    chosen_envelope = candidate_envelope
    chosen_signed = candidate_signed
    if cached_envelope is None:
        try:
            trust.verify_index_signature(candidate_envelope, root_signed)
        except trust.TrustError as exc:
            _fail(trust.EXIT_SIGNATURE, "index", str(exc))
    else:
        cached_signed = cached_envelope["signed"]
        if candidate_signed["version"] > cached_signed["version"]:
            try:
                trust.verify_index_signature(candidate_envelope, root_signed)
                trust.ensure_index_extends(candidate_signed, cached_signed)
            except trust.TrustError as exc:
                _fail(trust.EXIT_SIGNATURE, "index", str(exc))
        elif candidate_signed["version"] == cached_signed["version"]:
            try:
                trust.verify_index_signature(candidate_envelope, root_signed)
            except trust.TrustError as exc:
                _fail(trust.EXIT_SIGNATURE, "index", str(exc))
            if _canonical_fingerprint(candidate_envelope) != _canonical_fingerprint(
                cached_envelope
            ):
                _fail(
                    trust.EXIT_SIGNATURE,
                    "index",
                    "release-index v{} from the channel differs from the pinned copy; a "
                    "same-version silent replacement is refused".format(
                        cached_signed["version"]
                    ),
                )
        else:
            # The channel copy is older than the pinned one (typical when
            # re-verifying a previously published release directory). It was
            # signed under the release role of its own era; authenticate it
            # against the retained era root, but never roll the pin backwards
            # -- the freshest pinned (append-only) index does the manifest
            # pinning.
            if era_root_signed is None:
                _fail(
                    trust.EXIT_SIGNATURE,
                    "index",
                    "channel release-index v{} predates the pinned v{} and no retained "
                    "root for the manifest era is available to authenticate it".format(
                        candidate_signed["version"], cached_signed["version"]
                    ),
                )
            try:
                trust.verify_index_signature(candidate_envelope, era_root_signed)
                trust.verify_index_signature(cached_envelope, root_signed)
            except trust.TrustError as exc:
                _fail(
                    trust.EXIT_SIGNATURE,
                    "index",
                    "release-index signature cannot be verified for the rolled-back "
                    "channel copy: {}".format(exc),
                )
            chosen_envelope = cached_envelope
            chosen_signed = cached_signed

    try:
        index_entry = trust.verify_index_against_manifest(
            chosen_signed, manifest_envelope
        )
    except trust.TrustError as exc:
        layer = trust.EXIT_DIGEST if isinstance(exc, trust.DigestError) else trust.EXIT_SIGNATURE
        _fail(layer, "index", str(exc))
    was_updated = cached_envelope is None or _canonical_fingerprint(
        chosen_envelope
    ) != _canonical_fingerprint(cached_envelope)
    return chosen_signed, chosen_envelope, index_entry, was_updated


# ---------------------------------------------------------------------------
# Filesystem / artifact verification (FR-10, FR-11 offline half)
# ---------------------------------------------------------------------------


def _list_release_files(release_dir: Path) -> List[str]:
    try:
        entries = list(os.scandir(str(release_dir)))
    except OSError as exc:
        _fail(trust.EXIT_GENERIC, "release-dir", "cannot read release directory: {}".format(exc))
    names = []
    for entry in entries:
        if entry.is_symlink():
            _fail(
                trust.EXIT_DIGEST,
                "artifacts",
                "release directory contains a symbolic link: {}".format(entry.name),
            )
        if entry.is_dir(follow_symlinks=False):
            _fail(
                trust.EXIT_DIGEST,
                "artifacts",
                "release directory contains an unexpected subdirectory: {}".format(
                    entry.name
                ),
            )
        names.append(entry.name)
    return sorted(names)


def parse_sha256sums(data: bytes) -> Dict[str, str]:
    sums: Dict[str, str] = {}
    for line_number, raw in enumerate(data.decode("utf-8").splitlines(), start=1):
        if not raw.strip():
            _fail(
                trust.EXIT_DIGEST,
                CHECKSUMS_NAME,
                "{} contains a blank line at {}".format(CHECKSUMS_NAME, line_number),
            )
        if len(raw) < 66:
            _fail(
                trust.EXIT_DIGEST,
                CHECKSUMS_NAME,
                "{} line {} is malformed".format(CHECKSUMS_NAME, line_number),
            )
        digest = raw[:64]
        try:
            int(digest, 16)
        except ValueError:
            digest = None
        if digest is None or raw[64] != " " or raw[65] not in (" ", "*"):
            _fail(
                trust.EXIT_DIGEST,
                CHECKSUMS_NAME,
                "{} line {} is not a '<sha256>  <file>' record".format(
                    CHECKSUMS_NAME, line_number
                ),
            )
        name = raw[66:]
        try:
            trust.validate_asset_name(name, CHECKSUMS_NAME)
        except trust.MetadataError as exc:
            _fail(trust.EXIT_DIGEST, CHECKSUMS_NAME, str(exc))
        if name in sums:
            _fail(
                trust.EXIT_DIGEST,
                CHECKSUMS_NAME,
                "{} lists {} twice".format(CHECKSUMS_NAME, name),
            )
        sums[name] = digest.lower()
    if not sums:
        _fail(trust.EXIT_DIGEST, CHECKSUMS_NAME, "{} is empty".format(CHECKSUMS_NAME))
    return sums


def _check_sbom_document(name: str, data: bytes) -> None:
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(trust.EXIT_DIGEST, name, "SBOM {} is not valid JSON: {}".format(name, exc))
    if not isinstance(document, dict):
        _fail(trust.EXIT_DIGEST, name, "SBOM {} is not a JSON object".format(name))
    if name.endswith(".spdx.json"):
        if document.get("spdxVersion") != SPDX_VERSION:
            _fail(
                trust.EXIT_DIGEST,
                name,
                "{} is not an SPDX {} document".format(name, SPDX_VERSION),
            )
        if not str(document.get("SPDXID", "")).startswith("SPDXRef-DOCUMENT"):
            _fail(trust.EXIT_DIGEST, name, "{} lacks the SPDX document id".format(name))
    elif name.endswith(".cdx.json"):
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != CDX_VERSION:
            _fail(
                trust.EXIT_DIGEST,
                name,
                "{} is not a CycloneDX {} document".format(name, CDX_VERSION),
            )
    else:
        _fail(trust.EXIT_DIGEST, name, "SBOM file {} has an unrecognised suffix".format(name))


def verify_artifacts(
    *,
    release_dir: Path,
    manifest: dict,
    require_rekor_entry: bool,
) -> Dict[str, Any]:
    artifacts = manifest["artifacts"]
    sboms = manifest["sboms"]
    build_manifests = manifest["builder"]["build_manifests"]

    optional = {
        ROOT_BUNDLE_NAME,
        REVOCATIONS_BUNDLE_NAME,
        UNSIGNED_MANIFEST_NAME,
    }
    optional.add(REKOR_ENTRY_NAME)
    expected = set(artifacts) | set(sboms) | set(build_manifests)
    expected |= {SIGNED_MANIFEST_NAME, INDEX_NAME}
    actual = set(_list_release_files(release_dir))

    extra = actual - expected - optional
    if extra:
        _fail(
            trust.EXIT_DIGEST,
            "artifacts",
            "release directory contains unlisted file(s): {}. Remove them or obtain a "
            "manifest that covers them".format(", ".join(sorted(extra))),
        )
    missing = expected - actual
    if missing:
        _fail(
            trust.EXIT_DIGEST,
            "artifacts",
            "release directory is missing file(s) bound by the manifest: {}".format(
                ", ".join(sorted(missing))
            ),
        )

    def hash_and_compare(name: str, record: Dict[str, Any], layer: str) -> str:
        path = release_dir / name
        try:
            digest, size = trust.sha256_file(path)
        except trust.StateError as exc:
            _fail(trust.EXIT_DIGEST, layer, str(exc))
        if size != record["size"]:
            _fail(
                trust.EXIT_DIGEST,
                layer,
                "{} size mismatch: manifest lists {} bytes, file is {} bytes".format(
                    name, record["size"], size
                ),
            )
        if digest != record["sha256"]:
            _fail(
                trust.EXIT_DIGEST,
                layer,
                "{} sha256 mismatch:\n  expected {}\n  actual   {}".format(
                    name, record["sha256"], digest
                ),
            )
        return digest

    observed: Dict[str, str] = {}
    for name in sorted(artifacts):
        observed[name] = hash_and_compare(name, artifacts[name], "artifacts")
    for name in sorted(sboms):
        observed[name] = hash_and_compare(name, sboms[name], "sbom")
        _check_sbom_document(name, trust.read_regular_file(release_dir / name))
    for name in sorted(build_manifests):
        path = release_dir / name
        data = trust.read_regular_file(path)
        digest = hashlib.sha256(data).hexdigest()
        if digest != build_manifests[name]:
            _fail(
                trust.EXIT_DIGEST,
                "build-manifests",
                "desktop build manifest {} digest mismatch:\n  expected {}\n  actual   "
                "{}".format(name, build_manifests[name], digest),
            )
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            _fail(trust.EXIT_DIGEST, "build-manifests", "{} is not valid JSON: {}".format(name, exc))
        if not isinstance(parsed, dict):
            _fail(trust.EXIT_DIGEST, "build-manifests", "{} is not a JSON object".format(name))

    # SHA256SUMS internal consistency: every line must hit a manifest artifact.
    if CHECKSUMS_NAME not in artifacts:
        _fail(
            trust.EXIT_DIGEST,
            CHECKSUMS_NAME,
            "manifest does not bind {}; legacy checksum interop is mandatory".format(
                CHECKSUMS_NAME
            ),
        )
    sums = parse_sha256sums(trust.read_regular_file(release_dir / CHECKSUMS_NAME))
    unknown = set(sums) - set(artifacts)
    if unknown:
        _fail(
            trust.EXIT_DIGEST,
            CHECKSUMS_NAME,
            "{} names file(s) absent from the manifest: {}".format(
                CHECKSUMS_NAME, ", ".join(sorted(unknown))
            ),
        )
    for name, listed_digest in sorted(sums.items()):
        if listed_digest != artifacts[name]["sha256"]:
            _fail(
                trust.EXIT_DIGEST,
                CHECKSUMS_NAME,
                "{} digest for {} disagrees with the signed manifest".format(
                    CHECKSUMS_NAME, name
                ),
            )

    if require_rekor_entry and REKOR_ENTRY_NAME not in actual:
        _fail(
            trust.EXIT_REKOR,
            "rekor",
            "--rekor requested but {} is not present in the release directory".format(
                REKOR_ENTRY_NAME
            ),
        )
    return observed


# ---------------------------------------------------------------------------
# Online tag cross-check (FR-11 online half)
# ---------------------------------------------------------------------------


def verify_remote_tag(manifest: dict, online: Dict[str, Callable]) -> None:
    source = manifest["source"]
    repo = source["repo"]
    tag = manifest["tag"]
    if not isinstance(repo, str) or not repo.startswith(("https://", "http://")):
        _fail(
            trust.EXIT_SIGNATURE,
            "source",
            "--refresh-online cannot verify source.repo {!r}; an http(s) git "
            "repository URL is required".format(repo),
        )
    remote_tag_object, remote_commit = online["git_ls_remote"](repo, tag)
    if remote_tag_object != source["tag_object"]:
        _fail(
            trust.EXIT_SIGNATURE,
            "source",
            "remote tag object {} for {} does not match manifest {}".format(
                remote_tag_object, tag, source["tag_object"]
            ),
        )
    if remote_commit != source["commit"]:
        _fail(
            trust.EXIT_SIGNATURE,
            "source",
            "remote tag {} peels to commit {}, manifest binds {}".format(
                tag, remote_commit, source["commit"]
            ),
        )


# ---------------------------------------------------------------------------
# Rekor verification (FR-14)
# ---------------------------------------------------------------------------


def _rekor_log_pem(root_signed: dict, log_id: str) -> str:
    for entry in root_signed["rekor_keys"]:
        derived_id = trust.rekor_log_id_from_pem(entry["public_pem"].encode("ascii"))
        if derived_id == log_id and entry["keyid"] == trust.REKOR_KEYID_PREFIX + log_id:
            return entry["public_pem"]
    _fail(
        trust.EXIT_REKOR,
        "rekor",
        "root v{} does not trust Rekor log {}".format(root_signed["version"], log_id),
    )


def verify_rekor_binding(
    *,
    release_dir: Path,
    root_signed: dict,
    manifest_envelope: dict,
    index_entry: dict,
) -> Tuple[dict, dict]:
    path = release_dir / REKOR_ENTRY_NAME
    try:
        entry = json.loads(trust.read_regular_file(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        _fail(trust.EXIT_REKOR, "rekor", "{} is not valid JSON: {}".format(path.name, exc))
    if not isinstance(entry, dict):
        _fail(trust.EXIT_REKOR, "rekor", "{} must be a JSON object".format(path.name))
    log_id = entry.get("logID")
    if not isinstance(log_id, str):
        _fail(trust.EXIT_REKOR, "rekor", "{} lacks a logID".format(path.name))
    log_pem = _rekor_log_pem(root_signed, log_id)
    try:
        binding = trust.verify_hashedrekord_entry(entry, log_pem)
    except trust.TrustError as exc:
        _fail(trust.EXIT_REKOR, "rekor", str(exc))
    payload_digest = hashlib.sha256(
        trust.signed_payload_bytes(manifest_envelope)
    ).hexdigest()
    if binding["digest_hex"] != payload_digest:
        _fail(
            trust.EXIT_REKOR,
            "rekor",
            "Rekor entry anchors digest {} but the signed manifest payload is {}".format(
                binding["digest_hex"], payload_digest
            ),
        )
    if binding["artifact_scheme"] != "ecdsa-p256-sha256":
        _fail(
            trust.EXIT_REKOR,
            "rekor",
            "Rekor artifact signature scheme {!r} is not the production ecdsa-p256-sha256 "
            "binding".format(binding["artifact_scheme"]),
        )
    if index_entry.get("log_index") is not None:
        if binding["log_index"] != index_entry["log_index"]:
            _fail(
                trust.EXIT_REKOR,
                "rekor",
                "release-index pins Rekor logIndex {} but the entry reports {}".format(
                    index_entry["log_index"], binding["log_index"]
                ),
            )
    return binding, entry


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def verify_release(
    *,
    release_dir: Path,
    trust_dir: Path,
    root_file: Optional[Path] = None,
    revocations_file: Optional[Path] = None,
    expected_tag: Optional[str] = None,
    expected_line: Optional[str] = None,
    allow_downgrade: Optional[str] = None,
    downgrade_reason: Optional[str] = None,
    accept_revoked: Optional[str] = None,
    revoked_reason: Optional[str] = None,
    use_rekor: bool = False,
    refresh_online: bool = False,
    now_iso: Optional[str] = None,
    online: Optional[Dict[str, Callable]] = None,
    persist: bool = True,
) -> Dict[str, Any]:
    release_dir = Path(release_dir)
    trust_dir = Path(trust_dir)
    if not release_dir.is_dir():
        _fail(trust.EXIT_GENERIC, "release-dir", "release directory not found: {}".format(release_dir))
    now = now_iso or trust.utc_now_iso()
    net = online if refresh_online else None

    # 1. Signed manifest envelope.
    manifest_envelope = _read_json_envelope(
        release_dir / SIGNED_MANIFEST_NAME, "release manifest"
    )
    try:
        manifest = trust.validate_release_manifest(manifest_envelope["signed"])
    except trust.MetadataError as exc:
        _fail(trust.EXIT_SIGNATURE, "manifest", str(exc))
    if expected_tag is not None and manifest["tag"] != expected_tag:
        _fail(
            trust.EXIT_SIGNATURE,
            "manifest",
            "manifest tag {!r} does not match requested {!r}".format(
                manifest["tag"], expected_tag
            ),
        )
    if expected_line is not None and manifest["release_line"] != expected_line:
        _fail(
            trust.EXIT_SIGNATURE,
            "manifest",
            "manifest release_line {!r} does not match requested {!r}".format(
                manifest["release_line"], expected_line
            ),
        )
    line = manifest["release_line"]
    version = manifest["version"]
    manifest_hash = trust.canonical_sha256(manifest)

    # 2. Root (bootstrap, no rollback, silent replacement protection).
    root_signed, root_envelope, was_tofu, was_root_rotated, root_warnings = resolve_root(
        root_file=root_file,
        trust_dir=trust_dir,
        release_dir=release_dir,
        online=net,
        now_iso=now,
    )
    if root_signed["version"] < manifest["required_root_version"]:
        _fail(
            trust.EXIT_SIGNATURE,
            "root",
            "manifest requires root v{} but only v{} is available".format(
                manifest["required_root_version"], root_signed["version"]
            ),
        )

    # A manifest signed before a rotation is validated against the retained
    # root document of its own era (FR: old signatures stay valid), never
    # against a rolled-back root feed.
    history_warnings: List[str] = []
    if manifest["required_root_version"] == root_signed["version"]:
        manifest_root_signed = root_signed
    else:
        historical_envelope = trust.read_root_history(
            trust_dir, manifest["required_root_version"]
        )
        if historical_envelope is None:
            _fail(
                trust.EXIT_SIGNATURE,
                "root",
                "manifest was signed under root v{} but that root version is not retained "
                "in the trust directory; obtain it through --root-file or --refresh-online "
                "and rotate it forward one version at a time".format(
                    manifest["required_root_version"]
                ),
            )
        try:
            manifest_root_signed = trust.validate_root_signed(
                historical_envelope["signed"]
            )
        except trust.MetadataError as exc:
            _fail(
                trust.EXIT_STATE,
                "state",
                "retained root v{} is unusable: {}".format(
                    manifest["required_root_version"], exc
                ),
            )
        history_warnings.append(
            "verifying this release with the retained root v{} role table; current root is "
            "v{}".format(manifest_root_signed["version"], root_signed["version"])
        )

    # 3. Revocations (signed by the revocation role, cumulative, fresh enough).
    revocations_signed, revocations_envelope, revocations_updated, rev_warnings = (
        resolve_revocations(
            revocations_file=revocations_file,
            trust_dir=trust_dir,
            release_dir=release_dir,
            root_signed=root_signed,
            required_version=manifest["required_revocations_version"],
            online=net,
        )
    )

    # 4. Manifest signature / threshold, excluding revoked signing keys.
    try:
        valid_signers = trust.verify_role_envelope(
            manifest_envelope,
            trust.role_publics(manifest_root_signed, trust.ROLE_RELEASE),
            trust.role_threshold(manifest_root_signed, trust.ROLE_RELEASE),
        )
    except trust.SignatureError as exc:
        _fail(trust.EXIT_SIGNATURE, "signature", str(exc))
    if revocations_signed is not None:
        active_signers = {
            keyid
            for keyid in valid_signers
            if trust.revoked_key_entry(revocations_signed, keyid) is None
        }
        if len(active_signers) < trust.role_threshold(
            manifest_root_signed, trust.ROLE_RELEASE
        ):
            revoked = sorted(valid_signers - active_signers)
            _fail(
                trust.EXIT_REVOKED,
                "revocation",
                "manifest carries signature(s) from revoked release key(s) {} and no "
                "threshold of unrevoked keys remains".format(revoked),
            )

    # 5. Release index pins exactly this manifest; index rollback protection.
    _index_signed, index_envelope, index_entry, index_updated = resolve_index(
        release_dir=release_dir,
        trust_dir=trust_dir,
        root_signed=root_signed,
        era_root_signed=manifest_root_signed,
        manifest_envelope=manifest_envelope,
        online=net,
    )

    # 6. Artifacts, SBOMs, SHA256SUMS, desktop build manifests.
    verify_artifacts(
        release_dir=release_dir,
        manifest=manifest,
        require_rekor_entry=use_rekor,
    )

    # 7. Revocation semantics for this concrete release.
    revoked_release = None
    if revocations_signed is not None:
        for record in manifest["artifacts"].values():
            entry = trust.revoked_artifact_entry(revocations_signed, record["sha256"])
            if entry is not None:
                _fail(
                    trust.EXIT_REVOKED,
                    "revocation",
                    "bound artifact {} is revoked: {}".format(
                        record["sha256"], entry["reason"]
                    ),
                )
        for record in manifest["sboms"].values():
            entry = trust.revoked_artifact_entry(revocations_signed, record["sha256"])
            if entry is not None:
                _fail(
                    trust.EXIT_REVOKED,
                    "revocation",
                    "bound SBOM {} is revoked: {}".format(record["sha256"], entry["reason"]),
                )
        revoked_release = trust.revoked_release_entry(
            revocations_signed, line, version
        )

    # 8. Local water-mark / explicit downgrade / security exception.
    state = trust.load_state(trust_dir)
    try:
        decision = trust.evaluate_acceptance(
            state,
            manifest,
            now_iso=now,
            allow_downgrade=allow_downgrade,
            downgrade_reason=downgrade_reason,
            revoked_entry=revoked_release,
            accept_revoked=accept_revoked,
            revoked_reason=revoked_reason,
        )
    except trust.TrustError as exc:
        layer = (
            trust.EXIT_REVOKED
            if isinstance(exc, trust.RevocationError)
            else trust.EXIT_DOWNGRADE
        )
        _fail(layer, "revocation" if layer == trust.EXIT_REVOKED else "downgrade", str(exc))

    # 9. Optional online tag cross-check.
    if net is not None:
        verify_remote_tag(manifest, net)

    # 10. Optional Rekor SET / inclusion verification and tree water-mark.
    rekor_result: Dict[str, Any] = {"status": "skipped"}
    if use_rekor:
        binding, _entry = verify_rekor_binding(
            release_dir=release_dir,
            root_signed=root_signed,
            manifest_envelope=manifest_envelope,
            index_entry=index_entry,
        )
        try:
            state = trust.record_tree_size(state, line, binding["root_size"])
        except trust.RekorError as exc:
            _fail(trust.EXIT_REKOR, "rekor", str(exc))
        rekor_result = {
            "status": "verified",
            "log_id": binding["log_id"],
            "log_index": binding["log_index"],
            "integrated_time": binding["integrated_time"],
            "tree_size": binding["root_size"],
        }

    warnings = list(root_warnings) + list(history_warnings) + list(rev_warnings)

    # 11. Persist everything only after the whole pipeline has succeeded.
    new_state = trust.commit_acceptance(state, decision)
    for item in new_state["lines"][line]["security_exceptions"]:
        warnings.append(
            "active security exception for {} {} ({}) granted at {}".format(
                line, item["version"], item["reason"], item["granted_at"]
            )
        )
    if not use_rekor:
        warnings.append(
            "transparency log was not checked; pass --rekor to verify the Rekor "
            "hashedrekord entry offline after it is integrated"
        )

    if persist:
        trust.ensure_trust_layout(trust_dir)
        trust.write_cached_envelope(trust_dir, trust.ROOT_TYPE, root_envelope)
        # Retain every accepted root version so pre-rotation manifests stay
        # verifiable via their required_root_version without a root rollback.
        trust.write_root_history(trust_dir, root_envelope)
        if revocations_envelope is not None:
            trust.write_cached_envelope(
                trust_dir, trust.REVOCATIONS_TYPE, revocations_envelope
            )
        trust.write_cached_envelope(trust_dir, trust.RELEASE_INDEX_TYPE, index_envelope)
        trust.save_state(trust_dir, new_state)
        # Content-addressed manifest copy lets distributed standalone tools
        # (codex-instruct-v<X>.py) self-check their bytes against the accepted
        # artifact record without access to the release directory.
        trust.write_accepted_manifest(trust_dir, manifest_envelope)
        trust.append_audit_line(
            trust.trust_audit_path(trust_dir), trust.decision_audit_entry(decision)
        )
        if was_tofu:
            trust.record_trust_event(
                trust_dir,
                "root-tofu",
                line=line,
                root_version=root_signed["version"],
                root_fingerprint=trust.root_fingerprint(root_signed),
                time_iso=now,
            )
        if was_root_rotated:
            trust.record_trust_event(
                trust_dir,
                "root-rotated",
                line=line,
                root_version=root_signed["version"],
                root_fingerprint=trust.root_fingerprint(root_signed),
                time_iso=now,
            )
        if revocations_updated and revocations_signed is not None:
            trust.record_trust_event(
                trust_dir,
                "revocations-updated",
                version=revocations_signed["version"],
                time_iso=revocations_signed["issued_at"],
            )

    return {
        "ok": True,
        "product": trust.PRODUCT,
        "line": line,
        "version": version,
        "tag": manifest["tag"],
        "sequence": manifest["sequence"],
        "action": decision["action"],
        "manifest_hash": manifest_hash,
        "root_version": root_signed["version"],
        "root_fingerprint": trust.root_fingerprint(root_signed),
        "tofu": was_tofu,
        "revocations_version": (
            None if revocations_signed is None else revocations_signed["version"]
        ),
        "index_version": _index_signed["version"],
        "rekor": rekor_result,
        "warnings": warnings,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verify-release",
        description="Verify a signed codex-keysmith release offline (fail-closed).",
    )
    parser.add_argument("--release-dir")
    parser.add_argument("--trust-dir")
    parser.add_argument("--root-file")
    parser.add_argument("--revocations-file")
    parser.add_argument("--tag", help="cross-check the manifest tag (e.g. v0.7.0)")
    parser.add_argument(
        "--line", choices=trust.RELEASE_LINES, help="cross-check the release line"
    )
    parser.add_argument("--allow-downgrade", metavar="VERSION")
    parser.add_argument("--accept-revoked", metavar="VERSION")
    parser.add_argument(
        "--reason", help="written reason required by downgrade/revocation overrides"
    )
    parser.add_argument(
        "--rekor", action="store_true", help="verify the Rekor hashedrekord entry"
    )
    parser.add_argument(
        "--refresh-online",
        action="store_true",
        help="refresh root/revocations/index over HTTPS and cross-check the remote tag",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument(
        "--version",
        action="store_true",
        help="print the verifier version and exit",
    )
    return parser


def verifier_version_text() -> str:
    embedded = "embedded" if KEYSMITH_TRUST_ENGINE_PAYLOAD is not None else "source-tree"
    return "{} trust-spec {} ({})".format(VERIFIER_PRODUCT, trust.SPEC_VERSION, embedded)


def _failure_record(exc: VerificationError) -> Dict[str, Any]:
    return {
        "ok": False,
        "stage": exc.stage,
        "exit_code": exc.exit_code,
        "error": str(exc),
    }


def _map_trust_error(exc: trust.TrustError) -> VerificationError:
    for exc_type, exit_code, stage in _EXCEPTION_LAYER:
        if isinstance(exc, exc_type):
            return VerificationError(exit_code, stage, str(exc))
    return VerificationError(trust.EXIT_GENERIC, "verifier", str(exc))


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(verifier_version_text())
        return trust.EXIT_OK
    if not args.release_dir:
        parser.error("--release-dir is required")

    if args.allow_downgrade is None and args.accept_revoked is None and args.reason:
        print(
            "verify_release: --reason requires --allow-downgrade and/or --accept-revoked",
            file=sys.stderr,
        )
        return trust.EXIT_GENERIC
    if args.allow_downgrade is not None and not (args.reason or "").strip():
        print(
            "verify_release: --allow-downgrade requires a non-empty --reason",
            file=sys.stderr,
        )
        return trust.EXIT_DOWNGRADE
    if args.accept_revoked is not None and not (args.reason or "").strip():
        print(
            "verify_release: --accept-revoked requires a non-empty --reason",
            file=sys.stderr,
        )
        return trust.EXIT_REVOKED

    trust_dir = Path(args.trust_dir) if args.trust_dir else trust.default_trust_dir()
    online_defaults = {"fetch": https_fetch, "git_ls_remote": git_ls_remote}
    try:
        result = verify_release(
            release_dir=Path(args.release_dir),
            trust_dir=trust_dir,
            root_file=Path(args.root_file) if args.root_file else None,
            revocations_file=(
                Path(args.revocations_file) if args.revocations_file else None
            ),
            expected_tag=args.tag,
            expected_line=args.line,
            allow_downgrade=args.allow_downgrade,
            downgrade_reason=args.reason,
            accept_revoked=args.accept_revoked,
            revoked_reason=args.reason,
            use_rekor=args.rekor,
            refresh_online=args.refresh_online,
            online=online_defaults,
        )
    except VerificationError as exc:
        if args.json:
            print(json.dumps(_failure_record(exc), sort_keys=True))
        else:
            print(
                "verify_release: REJECTED at the {} layer.\n  {}".format(
                    exc.stage, exc
                ),
                file=sys.stderr,
            )
        return exc.exit_code
    except trust.TrustError as exc:
        mapped = _map_trust_error(exc)
        if args.json:
            print(json.dumps(_failure_record(mapped), sort_keys=True))
        else:
            print(
                "verify_release: REJECTED at the {} layer.\n  {}".format(
                    mapped.stage, mapped
                ),
                file=sys.stderr,
            )
        return mapped.exit_code
    except (OSError, ValueError) as exc:
        record = {
            "ok": False,
            "stage": "verifier",
            "exit_code": trust.EXIT_GENERIC,
            "error": str(exc),
        }
        if args.json:
            print(json.dumps(record, sort_keys=True))
        else:
            print("verify_release: {}".format(exc), file=sys.stderr)
        return trust.EXIT_GENERIC

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "ACCEPTED {} {} (sequence {}) on line {}".format(
                trust.PRODUCT, result["version"], result["sequence"], result["line"]
            )
        )
        print("  action:        {}".format(result["action"]))
        print("  manifest hash: {}".format(result["manifest_hash"]))
        print(
            "  root:          v{} ({})".format(
                result["root_version"], result["root_fingerprint"][:16]
            )
        )
        print(
            "  revocations:   {}".format(
                "v{}".format(result["revocations_version"])
                if result["revocations_version"] is not None
                else "none"
            )
        )
        print("  rekor:         {}".format(result["rekor"]["status"]))
        for warning in result["warnings"]:
            print("  WARNING: {}".format(warning))
    return trust.EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
