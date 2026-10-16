#!/usr/bin/env python3
"""Scriptable gates shared by the release workflows (FR-21 stable, FR-22 desktop-beta).

The signed-line publication flow is split in two:

1. ``release.yml`` builds the unsigned trust materials, creates a *draft*
   GitHub Release and stops.  The :func:`signed_line_required` gate decides
   whether a tag belongs to the signed line (``tag >= first_signed_version``
   in ``trust/policy.json``) or to the legacy unsigned path.
2. ``release-finalize.yml`` downloads the draft (including the three signed
   materials uploaded from the maintainer offline machine), runs this
   script's ``finalize`` command, which independently invokes
   ``scripts.verify_release`` in an isolated subprocess (root and revocations
   come from the main checkout, never from the draft), enforces the
   append-only release-index channel and stages immutable copies under
   ``trust/releases/``.  Only then does the workflow PATCH ``draft=false``.

This module performs no network IO itself; every decision is a pure, unit
testable function or a local subprocess/file operation.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from scripts import keysmith_trust as trust
else:
    from . import keysmith_trust as trust

ENGINE_ROOT = Path(__file__).resolve().parents[1]
TRUST_DIRNAME = Path("trust")
ROOT_DIRNAME = TRUST_DIRNAME / "root"
REVOCATIONS_DIRNAME = TRUST_DIRNAME / "revocations"
RELEASES_DIRNAME = TRUST_DIRNAME / "releases"
CHANNEL_INDEX_REL = RELEASES_DIRNAME / "release-index.json"

SIGNED_MANIFEST_NAME = "release-manifest.json"
SIGNED_INDEX_NAME = "release-index.json"
REKOR_ENTRY_NAME = "rekor-entry.json"
SIGNED_MATERIAL_NAMES = (
    SIGNED_MANIFEST_NAME,
    SIGNED_INDEX_NAME,
    REKOR_ENTRY_NAME,
)

STABLE_TAG_RE = re.compile(
    r"^v(?P<core>\d+\.\d+\.\d+)(?:-(?P<prerelease>[0-9A-Za-z.-]+))?$"
)
DESKTOP_TAG_RE = re.compile(
    r"^desktop-v(?P<core>\d+\.\d+\.\d+)-beta\.(?P<beta>[1-9][0-9]*)$"
)
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
ROOT_FILE_RE = re.compile(r"^root\.(?P<version>[0-9]+)\.json$")
REVOCATIONS_FILE_RE = re.compile(r"^revocations\.(?P<version>[0-9]+)\.json$")

STABLE_LINE = "stable"
DESKTOP_LINE = "desktop-beta"


class PublishGateError(RuntimeError):
    """A release-workflow gate invariant was violated (fail-closed)."""


class VerificationRejected(PublishGateError):
    """The independent verifier subprocess rejected the release."""

    def __init__(self, returncode: int, stdout: str, stderr: str):
        super().__init__("verifier rejected the release (exit {})".format(returncode))
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Tag / policy gates
# ---------------------------------------------------------------------------


def _version_core(version: str, label: str) -> Tuple[int, int, int]:
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        raise PublishGateError("{} must look like X.Y.Z, got {!r}".format(label, version))
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


def parse_release_tag(tag: str) -> Tuple[str, Tuple[int, int, int], bool]:
    """Return ``(release_line, core_version_tuple, is_prerelease)``.

    Stable tags are ``vX.Y.Z`` (optionally with a ``-suffix``); desktop beta
    tags are ``desktop-vX.Y.Z-beta.N``.  Anything else is rejected.
    """

    if not isinstance(tag, str) or not tag:
        raise PublishGateError("release tag must be a non-empty string")
    match = DESKTOP_TAG_RE.fullmatch(tag)
    if match is not None:
        return DESKTOP_LINE, _version_core(match.group("core"), "desktop tag"), False
    match = STABLE_TAG_RE.fullmatch(tag)
    if match is None:
        raise PublishGateError(
            "unsupported release tag {!r}; expected vX.Y.Z or "
            "desktop-vX.Y.Z-beta.N".format(tag)
        )
    return STABLE_LINE, _version_core(match.group("core"), "tag"), bool(
        match.group("prerelease")
    )


def signed_line_required(tag: str, policy: dict) -> bool:
    """Decide whether ``tag`` must use the signed-line draft gate.

    The single ``first_signed_version`` policy threshold gates both release
    lines (FR-21/FR-22).  ``None`` means the signing ceremony has not been
    enabled yet, so every tag keeps the legacy unsigned publication path.
    On the stable line a pre-release of the threshold version stays on the
    legacy path (``v0.7.0-rc1`` ships unsigned); desktop-beta tags are
    inherently pre-release artifacts, so their ``X.Y.Z`` core is compared
    directly and ``desktop-vX.Y.Z-beta.N`` at the threshold version is
    already signed.
    """

    line, core, is_prerelease = parse_release_tag(tag)
    threshold_text = policy.get("first_signed_version")
    if threshold_text is None:
        return False
    if not isinstance(threshold_text, str):
        raise PublishGateError("trust policy first_signed_version must be a string or null")
    threshold = _version_core(threshold_text, "first_signed_version")
    if core < threshold:
        return False
    if line == STABLE_LINE and core == threshold and is_prerelease:
        return False
    return True


def validate_dispatch_refs(tag: str, tag_object: str, commit: str) -> None:
    """Validate the workflow_dispatch recovery-style reference triple."""

    parse_release_tag(tag)
    for label, value in (("tag object", tag_object), ("commit", commit)):
        if not isinstance(value, str) or SHA1_RE.fullmatch(value) is None:
            raise PublishGateError(
                "expected {} to be a full 40-character lowercase hex SHA".format(label)
            )
    if tag_object == commit:
        raise PublishGateError("annotated tag object and peeled commit must differ")


# ---------------------------------------------------------------------------
# Signed material completeness
# ---------------------------------------------------------------------------


def missing_signed_materials(names: List[str]) -> List[str]:
    """Return the sorted required material names absent from ``names``."""

    present = set(names)
    return sorted(name for name in SIGNED_MATERIAL_NAMES if name not in present)


def preflight_materials(release_dir: Path) -> Dict[str, bytes]:
    """Load the three signed materials and reject missing/non-JSON ones.

    Signature validation is deliberately left to the independent verifier;
    this gate only models the "material absent / unusable document" class of
    failures so the workflow never reaches publication with a partial draft.
    """

    release_dir = Path(release_dir)
    if not release_dir.is_dir():
        raise PublishGateError("release directory not found: {}".format(release_dir))
    materials: Dict[str, bytes] = {}
    for name in SIGNED_MATERIAL_NAMES:
        path = release_dir / name
        try:
            data = trust.read_regular_file(path)
        except (OSError, trust.StateError) as exc:
            raise PublishGateError(
                "signed material {} is unreadable: {}".format(name, exc)
            ) from exc
        try:
            parsed = trust.parse_json_document(data, name)
            trust.require_object(parsed, name)
        except trust.MetadataError as exc:
            raise PublishGateError(
                "signed material {} is unusable: {}".format(name, exc)
            ) from exc
        materials[name] = data
    return materials


def read_required_versions(manifest_bytes: bytes) -> Tuple[int, int]:
    """Read required root/revocations versions from the signed manifest."""

    try:
        envelope = trust.load_envelope(manifest_bytes, SIGNED_MANIFEST_NAME)
        signed = trust.validate_release_manifest(envelope["signed"])
    except trust.TrustError as exc:
        raise PublishGateError("signed manifest is unusable: {}".format(exc)) from exc
    return signed["required_root_version"], signed["required_revocations_version"]


def latest_authority_version(directory: Path, pattern: "re.Pattern[str]") -> int:
    """Return the highest ``root.N``/``revocations.N`` version on disk."""

    directory = Path(directory)
    versions = []
    if directory.is_dir():
        for child in directory.iterdir():
            match = pattern.fullmatch(child.name)
            if match is not None and child.is_file():
                versions.append(int(match.group("version")))
    return max(versions, default=0)


def select_authority_files(
    root_dir: Path,
    revocations_dir: Path,
    required_root: int,
    required_revocations: int,
) -> Tuple[Path, Optional[Path]]:
    """Pick root/revocations documents from the main checkout.

    The exact required root era must be present (a manifest signed under
    root v1 authenticates against root v1, never a silently different feed).
    Revocations are cumulative: when newer documents than the required floor
    exist, the freshest one is used so a revoked key cannot publish.
    """

    if not isinstance(required_root, int) or required_root < 1:
        raise PublishGateError("manifest must require root version >= 1")
    root_file = Path(root_dir) / "root.{}.json".format(required_root)
    if not root_file.is_file():
        raise PublishGateError(
            "required root authority is missing from the main checkout: {}".format(root_file)
        )
    revocations_file: Optional[Path] = None
    if required_revocations >= 1:
        revocations_file = Path(revocations_dir) / "revocations.{}.json".format(
            required_revocations
        )
        if not revocations_file.is_file():
            raise PublishGateError(
                "required revocations authority is missing: {}".format(revocations_file)
            )
    latest_rev = latest_authority_version(revocations_dir, REVOCATIONS_FILE_RE)
    if latest_rev > required_revocations:
        revocations_file = Path(revocations_dir) / "revocations.{}.json".format(latest_rev)
    return root_file, revocations_file


# ---------------------------------------------------------------------------
# Independent verifier invocation
# ---------------------------------------------------------------------------


def build_verifier_command(
    *,
    release_dir: Path,
    trust_dir: Path,
    root_file: Path,
    revocations_file: Optional[Path],
    tag: str,
    line: str,
) -> List[str]:
    """Build the independent ``python -m scripts.verify_release`` command."""

    command = [
        sys.executable,
        "-m",
        "scripts.verify_release",
        "--release-dir",
        str(release_dir),
        "--trust-dir",
        str(trust_dir),
        "--root-file",
        str(root_file),
        "--tag",
        tag,
        "--line",
        line,
        "--rekor",
        "--json",
    ]
    if revocations_file is not None:
        command.extend(["--revocations-file", str(revocations_file)])
    return command


def run_independent_verifier(command: List[str]) -> dict:
    """Run the verifier in an isolated subprocess; fail closed on rejection."""

    try:
        proc = subprocess.run(
            command,
            cwd=str(ENGINE_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise PublishGateError(
            "cannot launch the independent verifier: {}".format(exc)
        ) from exc
    if proc.returncode != trust.EXIT_OK:
        raise VerificationRejected(proc.returncode, proc.stdout, proc.stderr)
    try:
        result = json.loads(proc.stdout)
    except (ValueError, TypeError) as exc:
        raise PublishGateError(
            "verifier reported success but emitted no JSON verdict: {}".format(exc)
        ) from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise PublishGateError("verifier verdict is not an acceptance record")
    return result


# ---------------------------------------------------------------------------
# Append-only channel index + immutable trust/releases/ staging
# ---------------------------------------------------------------------------


def load_channel_index(index_path: Path) -> Optional[Tuple[dict, dict]]:
    """Load the currently committed channel index, or None for the first."""

    index_path = Path(index_path)
    if not index_path.exists():
        return None
    try:
        envelope = trust.load_envelope(
            trust.read_regular_file(index_path), SIGNED_INDEX_NAME
        )
        signed = trust.validate_release_index(envelope["signed"])
    except (OSError, trust.TrustError) as exc:
        raise PublishGateError(
            "committed channel index is unusable: {}".format(exc)
        ) from exc
    return envelope, signed


def _atomic_write(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".tmp-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def stage_signed_materials(
    *,
    repo_root: Path,
    tag: str,
    manifest_bytes: bytes,
    index_bytes: bytes,
    rekor_bytes: bytes,
) -> List[Path]:
    """Stage signed materials into the immutable ``trust/releases/`` channel.

    The per-release manifest and Rekor entry can never be overwritten.  The
    channel ``release-index.json`` advances in place; its append-only and
    signature properties are checked by :func:`enforce_channel_advances`.
    """

    line, _core, _pre = parse_release_tag(tag)
    if line not in (STABLE_LINE, DESKTOP_LINE):  # pragma: no cover - defensive
        raise PublishGateError("unknown release line for tag {!r}".format(tag))
    repo_root = Path(repo_root)
    release_channel_dir = repo_root / RELEASES_DIRNAME / tag
    targets = (
        (release_channel_dir / SIGNED_MANIFEST_NAME, manifest_bytes),
        (release_channel_dir / REKOR_ENTRY_NAME, rekor_bytes),
        (repo_root / CHANNEL_INDEX_REL, index_bytes),
    )
    for path, _data in targets[:-1]:
        if path.exists():
            raise PublishGateError(
                "immutable signed material already exists and must not be "
                "overwritten: {}".format(path)
            )
    staged: List[Path] = []
    for path, data in targets:
        _atomic_write(path, data)
        staged.append(path)
    return staged


def enforce_channel_advances(
    *,
    new_index_bytes: bytes,
    old: Optional[Tuple[dict, dict]],
    root_file: Path,
) -> Tuple[dict, dict]:
    """Verify the new index signature and append-only extension of channel."""

    try:
        new_envelope = trust.load_envelope(new_index_bytes, SIGNED_INDEX_NAME)
        new_signed = trust.validate_release_index(new_envelope["signed"])
        root_envelope = trust.load_envelope(
            trust.read_regular_file(root_file), "root metadata"
        )
        root_signed = trust.validate_root_signed(root_envelope["signed"])
        trust.verify_index_signature(new_envelope, root_signed)
    except (OSError, trust.TrustError) as exc:
        raise PublishGateError("new release-index is unusable: {}".format(exc)) from exc
    if old is not None:
        _old_envelope, old_signed = old
        try:
            trust.ensure_index_extends(new_signed, old_signed)
        except trust.TrustError as exc:
            raise PublishGateError(
                "new release-index does not extend the committed channel "
                "index: {}".format(exc)
            ) from exc
    return new_envelope, new_signed


def next_sequence(index_path: Path, line: str) -> int:
    """Determine the next monotonic sequence number from the channel index."""

    if line not in trust.RELEASE_LINES:
        raise PublishGateError("unknown release line {!r}".format(line))
    index_path = Path(index_path)
    if not index_path.exists():
        return 1
    try:
        envelope = trust.load_envelope(
            trust.read_regular_file(index_path), SIGNED_INDEX_NAME
        )
        signed = trust.validate_release_index(envelope["signed"])
    except (OSError, trust.TrustError) as exc:
        raise PublishGateError("channel index is unusable: {}".format(exc)) from exc
    entries = signed["lines"][line]
    return 1 if not entries else int(entries[-1]["sequence"]) + 1


# ---------------------------------------------------------------------------
# Finalize orchestration
# ---------------------------------------------------------------------------


def run_finalize(
    *,
    release_dir: Path,
    tag: str,
    line: str,
    repo_root: Path,
    trust_dir: Path,
) -> dict:
    """Independently verify a draft release and stage its signed materials."""

    if line not in trust.RELEASE_LINES:
        raise PublishGateError("unknown release line {!r}".format(line))
    parsed_line, _core, _pre = parse_release_tag(tag)
    if parsed_line != line:
        raise PublishGateError(
            "tag {!r} belongs to line {!r}, not {!r}".format(tag, parsed_line, line)
        )
    repo_root = Path(repo_root)
    trust_dir = Path(trust_dir)
    trust_dir.mkdir(parents=True, exist_ok=True)

    materials = preflight_materials(release_dir)
    required_root, required_revocations = read_required_versions(
        materials[SIGNED_MANIFEST_NAME]
    )
    root_file, revocations_file = select_authority_files(
        repo_root / ROOT_DIRNAME,
        repo_root / REVOCATIONS_DIRNAME,
        required_root,
        required_revocations,
    )
    command = build_verifier_command(
        release_dir=Path(release_dir),
        trust_dir=trust_dir,
        root_file=root_file,
        revocations_file=revocations_file,
        tag=tag,
        line=line,
    )
    verdict = run_independent_verifier(command)

    old_index = load_channel_index(repo_root / CHANNEL_INDEX_REL)
    enforce_channel_advances(
        new_index_bytes=materials[SIGNED_INDEX_NAME],
        old=old_index,
        root_file=root_file,
    )
    staged = stage_signed_materials(
        repo_root=repo_root,
        tag=tag,
        manifest_bytes=materials[SIGNED_MANIFEST_NAME],
        index_bytes=materials[SIGNED_INDEX_NAME],
        rekor_bytes=materials[REKOR_ENTRY_NAME],
    )
    return {
        "ok": True,
        "tag": tag,
        "line": line,
        "version": verdict.get("version"),
        "sequence": verdict.get("sequence"),
        "manifest_hash": verdict.get("manifest_hash"),
        "root_version": verdict.get("root_version"),
        "revocations_version": verdict.get("revocations_version"),
        "staged": [str(path.relative_to(repo_root)) for path in staged],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_gate(args: argparse.Namespace) -> int:
    policy_path = Path(args.policy) if args.policy else trust.default_policy_path()
    try:
        policy = trust.load_policy(policy_path)
    except (OSError, trust.TrustError) as exc:
        raise PublishGateError(
            "cannot load trust policy {}: {}".format(policy_path, exc)
        ) from exc
    print("true" if signed_line_required(args.tag, policy) else "false")
    return 0


def _cmd_check_refs(args: argparse.Namespace) -> int:
    validate_dispatch_refs(args.tag, args.tag_object, args.commit)
    print("refs-ok")
    return 0


def _cmd_check_materials(args: argparse.Namespace) -> int:
    names = sorted(
        child.name
        for child in Path(args.release_dir).iterdir()
        if child.is_file()
    ) if Path(args.release_dir).is_dir() else []
    missing = missing_signed_materials(names)
    if missing:
        raise PublishGateError(
            "missing signed material(s): {}".format(", ".join(missing))
        )
    preflight_materials(Path(args.release_dir))
    print("materials-ok")
    return 0


def _cmd_next_sequence(args: argparse.Namespace) -> int:
    print(next_sequence(Path(args.index), args.line))
    return 0


def _cmd_authority_versions(args: argparse.Namespace) -> int:
    root_version = latest_authority_version(Path(args.root_dir), ROOT_FILE_RE)
    revocations_version = latest_authority_version(
        Path(args.revocations_dir), REVOCATIONS_FILE_RE
    )
    print("root={}".format(root_version))
    print("revocations={}".format(revocations_version))
    return 0


def _cmd_finalize(args: argparse.Namespace) -> int:
    result = run_finalize(
        release_dir=Path(args.release_dir),
        tag=args.tag,
        line=args.line,
        repo_root=Path(args.repo_root),
        trust_dir=Path(args.trust_dir),
    )
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("finalize-ok {} {} (sequence {})".format(
            result["line"], result["tag"], result["sequence"]
        ))
        for rel in result["staged"]:
            print("  staged {}".format(rel))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="release_publish",
        description="Signed-line release workflow gates (FR-21).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    gate = sub.add_parser("gate", help="decide the signed-line gate for a tag")
    gate.add_argument("--tag", required=True)
    gate.add_argument("--policy")
    gate.set_defaults(handler=_cmd_gate)

    refs = sub.add_parser("check-refs", help="validate dispatch tag/commit inputs")
    refs.add_argument("--tag", required=True)
    refs.add_argument("--tag-object", required=True)
    refs.add_argument("--commit", required=True)
    refs.set_defaults(handler=_cmd_check_refs)

    materials = sub.add_parser(
        "check-materials", help="verify the three signed materials are present"
    )
    materials.add_argument("--release-dir", required=True)
    materials.set_defaults(handler=_cmd_check_materials)

    sequence = sub.add_parser(
        "next-sequence", help="next monotonic manifest sequence from the channel index"
    )
    sequence.add_argument("--line", required=True, choices=trust.RELEASE_LINES)
    sequence.add_argument("--index", required=True)
    sequence.set_defaults(handler=_cmd_next_sequence)

    authority = sub.add_parser(
        "authority-versions", help="highest root/revocations versions committed on main"
    )
    authority.add_argument("--root-dir", required=True)
    authority.add_argument("--revocations-dir", required=True)
    authority.set_defaults(handler=_cmd_authority_versions)

    finalize = sub.add_parser(
        "finalize", help="independently verify a draft and stage signed materials"
    )
    finalize.add_argument("--release-dir", required=True)
    finalize.add_argument("--tag", required=True)
    finalize.add_argument("--line", required=True, choices=trust.RELEASE_LINES)
    finalize.add_argument("--repo-root", required=True)
    finalize.add_argument("--trust-dir", required=True)
    finalize.add_argument("--json", action="store_true")
    finalize.set_defaults(handler=_cmd_finalize)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except VerificationRejected as exc:
        if exc.stdout:
            sys.stderr.write(exc.stdout)
        if exc.stderr:
            sys.stderr.write(exc.stderr)
        return exc.returncode
    except PublishGateError as exc:
        print("release_publish: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
