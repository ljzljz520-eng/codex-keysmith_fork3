#!/usr/bin/env python3
"""Offline maintainer signing tool for codex-keysmith trust metadata.

This tool runs on an air-gapped maintainer machine. It generates Ed25519 key
material, bootstraps and rotates root metadata, signs release manifests and
the release index, and issues cumulative revocations documents. It only uses
the Python standard library and never prints secret seed material.

Network access exists nowhere in this module; Rekor submission lives in a
separate subcommand added by a later task.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts import keysmith_trust as trust

ROOT_EXPIRY_DAYS = 365
REVOCATIONS_EXPIRY_DAYS = 30
KEYID_SHORT_LENGTH = 16
REKOR_PROPOSAL_API_VERSION = "0.0.1"
DEFAULT_REKOR_TIMEOUT_SECONDS = 15.0
DEFAULT_REKOR_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_REKOR_MAX_WAIT_SECONDS = 60.0
REKOR_ENTRY_DEFAULT_NAME = "rekor-entry.json"


class SigningError(RuntimeError):
    """Raised when a maintainer signing operation cannot be completed."""


# ---------------------------------------------------------------------------
# Deterministic rendering and safe on-disk IO
# ---------------------------------------------------------------------------


def render_json(document: Any) -> bytes:
    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def write_public_document(path: Path, document: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    trust.atomic_write(path, render_json(document), mode=0o644)


def _looks_like_git_worktree(path: Path) -> bool:
    probe_path = path if path.exists() else path.parent
    try:
        result = subprocess.run(
            ["git", "-C", str(probe_path), "rev-parse", "--is-inside-work-tree"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        result = None
    if result is not None and result.returncode == 0 and result.stdout.strip() == "true":
        return True
    # Fallback that also works without a git binary: walk upwards looking for
    # a .git directory or file (worktree pointer).
    current = path.resolve() if path.exists() else path.parent.resolve()
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists():
            return True
    return False


def ensure_secret_directory(path: Path, *, allow_repo: bool) -> Path:
    """Validate and create the directory that will hold secret key material."""

    target = Path(path)
    trust.reject_symlink_ancestors(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not allow_repo and _looks_like_git_worktree(target):
        raise SigningError(
            "refusing to write secret key material inside a git work tree: {} "
            "(pass --i-know-this-is-not-a-repo to override)".format(target)
        )
    return trust.ensure_private_directory(target)


# ---------------------------------------------------------------------------
# Key containers
# ---------------------------------------------------------------------------


def load_key_file(path: Path) -> Dict[str, Any]:
    """Load a secret container or a public-key sidecar.

    Returns ``{"keyid", "keytype", "public", "seed"}`` with seed ``None`` for
    public-only material.
    """

    text = trust.read_regular_file(Path(path))
    try:
        obj = json.loads(text.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigningError("key file {} is not valid JSON: {}".format(path, exc)) from exc
    if not isinstance(obj, dict):
        raise SigningError("key file {} must contain a JSON object".format(path))
    if "seed" in obj:
        try:
            seed, public = trust.load_secret_container(obj, label=str(path))
        except trust.TrustError as exc:
            raise SigningError(str(exc)) from exc
        return {
            "keyid": trust.ed25519_key_id(public),
            "keytype": trust.ED25519_KEYTYPE,
            "public": public,
            "seed": seed,
            "path": str(path),
        }
    try:
        trust.exact_object(
            obj, ("keytype", "keyid", "public"), str(path)
        )
        if obj["keytype"] != trust.ED25519_KEYTYPE:
            raise trust.MetadataError("unsupported keytype")
        public_hex = trust.require_hex(obj["public"], "{}.public".format(path), 32)
        keyid = trust.key_id_for_hex_public(public_hex)
        if obj["keyid"] != keyid:
            raise trust.MetadataError("keyid does not match the public key")
    except trust.TrustError as exc:
        raise SigningError("invalid public key file {}: {}".format(path, exc)) from exc
    return {
        "keyid": keyid,
        "keytype": trust.ED25519_KEYTYPE,
        "public": bytes.fromhex(public_hex),
        "seed": None,
        "path": str(path),
    }


def require_seed(key: Dict[str, Any], purpose: str) -> bytes:
    if key.get("seed") is None:
        raise SigningError(
            "{} requires private key material, but {} is public-only".format(
                purpose, key.get("path")
            )
        )
    return key["seed"]


def _short_key_id(keyid: str) -> str:
    return keyid.split(":", 1)[1][:KEYID_SHORT_LENGTH]


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


def cmd_keygen(args: argparse.Namespace) -> Dict[str, Any]:
    if args.from_seed is not None:
        try:
            seed = bytes.fromhex(args.from_seed)
        except ValueError as exc:
            raise SigningError("--from-seed must be 64 hex characters") from exc
        if len(seed) != 32:
            raise SigningError("--from-seed must be exactly 32 bytes (64 hex chars)")
    else:
        seed = trust.ed25519_generate_seed()
    public = trust.ed25519_public_from_seed(seed)
    keyid = trust.ed25519_key_id(public)
    fingerprint = trust.openssh_ed25519_fingerprint(public)

    out_dir = ensure_secret_directory(
        Path(args.out), allow_repo=args.i_know_this_is_not_a_repo
    )
    base = args.name or "{}-{}".format(args.role, _short_key_id(keyid))
    secret_path = out_dir / "{}.key.json".format(base)
    public_path = out_dir / "{}.pub.json".format(base)
    if secret_path.exists() or public_path.exists():
        raise SigningError("refusing to overwrite existing key material: {}".format(base))
    trust.atomic_write(secret_path, render_json(trust.make_secret_container(seed)), mode=0o600)
    try:
        os.chmod(str(secret_path), 0o600)
    except OSError:
        pass
    write_public_document(
        public_path,
        {
            "keyid": keyid,
            "keytype": trust.ED25519_KEYTYPE,
            "public": public.hex(),
        },
    )
    return {
        "role": args.role,
        "keyid": keyid,
        "fingerprint": fingerprint,
        "secret_path": str(secret_path),
        "public_path": str(public_path),
        "test_seed": args.from_seed is not None,
    }


# ---------------------------------------------------------------------------
# root metadata construction
# ---------------------------------------------------------------------------


def _load_keys(paths: Sequence[str]) -> List[Dict[str, Any]]:
    keys = [load_key_file(Path(item)) for item in paths]
    seen = set()
    for key in keys:
        if key["keyid"] in seen:
            raise SigningError("key {} supplied more than once".format(key["keyid"]))
        seen.add(key["keyid"])
    return keys


def _key_map(keys: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    return {
        key["keyid"]: {
            "keytype": trust.ED25519_KEYTYPE,
            "public": key["public"].hex(),
        }
        for key in keys
    }


def _roles_table(
    role_keys: Dict[str, List[Dict[str, Any]]],
    thresholds: Dict[str, int],
) -> Dict[str, Dict[str, Any]]:
    roles: Dict[str, Dict[str, Any]] = {}
    for role_name in trust.ROLES:
        members = role_keys[role_name]
        if not members:
            raise SigningError("root role {} must have at least one key".format(role_name))
        threshold = thresholds[role_name]
        if threshold < 1 or threshold > len(members):
            raise SigningError(
                "{} threshold {} is outside the 1..{} member range".format(
                    role_name, threshold, len(members)
                )
            )
        roles[role_name] = {
            "keyids": [key["keyid"] for key in members],
            "threshold": threshold,
        }
    return roles


def _rekor_entries(pem_paths: Sequence[str]) -> List[Dict[str, str]]:
    entries = []
    for item in pem_paths:
        pem = trust.read_regular_file(Path(item)).decode("utf-8")
        keyid = trust.REKOR_KEYID_PREFIX + trust.rekor_log_id_from_pem(pem)
        entries.append(
            {"keyid": keyid, "keytype": trust.REKOR_KEYTYPE, "public_pem": pem}
        )
    return entries


def _resolve_issued_expires(
    args: argparse.Namespace, *, default_expiry_days: int
) -> Tuple[str, str]:
    issued_at = args.issued_at or trust.utc_now_iso()
    trust.require_iso8601_utc(issued_at, "issued_at")
    if args.expires:
        expires = args.expires
    else:
        issued_dt = datetime.strptime(
            issued_at.replace("Z", "+00:00"), "%Y-%m-%dT%H:%M:%S%z"
        )
        if issued_dt.tzinfo is None:
            raise SigningError("issued_at must carry UTC timezone")
        expires = (issued_dt + timedelta(days=default_expiry_days)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    trust.require_iso8601_utc(expires, "expires")
    if expires <= issued_at:
        raise SigningError("expires must be later than issued_at")
    return issued_at, expires


def _thresholds(args: argparse.Namespace) -> Dict[str, int]:
    return {
        trust.ROLE_ROOT: args.threshold_root,
        trust.ROLE_RELEASE: args.threshold_release,
        trust.ROLE_REVOCATION: args.threshold_revocation,
    }


def _seal_and_check_root(
    signed: Dict[str, Any],
    old_signed: Optional[Dict[str, Any]],
    signer_seeds: Sequence[bytes],
) -> Dict[str, Any]:
    envelope = trust.seal_envelope(signed, list(signer_seeds))
    try:
        trust.verify_root_document(envelope, old_signed)
    except trust.TrustError as exc:
        raise SigningError("new root document failed self-verification: {}".format(exc)) from exc
    return envelope


def cmd_root_init(args: argparse.Namespace) -> Dict[str, Any]:
    root_keys = _load_keys(args.root_key)
    release_keys = _load_keys(args.release_key)
    revocation_keys = _load_keys(args.revocation_key)
    all_keys = root_keys + release_keys + revocation_keys
    roles = _roles_table(
        {
            trust.ROLE_ROOT: root_keys,
            trust.ROLE_RELEASE: release_keys,
            trust.ROLE_REVOCATION: revocation_keys,
        },
        _thresholds(args),
    )
    issued_at, expires = _resolve_issued_expires(
        args, default_expiry_days=ROOT_EXPIRY_DAYS
    )
    signed = trust.make_root_signed(
        version=1,
        roles=roles,
        keys=_key_map(all_keys),
        expires=expires,
        rekor_keys=_rekor_entries(args.rekor_pub),
    )
    root_seeds = []
    for key in root_keys:
        root_seeds.append(require_seed(key, "root-init"))
    envelope = _seal_and_check_root(signed, None, root_seeds)
    write_public_document(Path(args.out), envelope)
    return {
        "document": "root",
        "version": 1,
        "out": args.out,
        "root_keyids": [key["keyid"] for key in root_keys],
        "issued_at": issued_at,
        "expires": expires,
    }


def _carry_or_replace(
    current_root: Dict[str, Any],
    role_name: str,
    replacement: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    if replacement is not None:
        return replacement
    public_by_id = current_root["keys"]
    result = []
    for keyid in current_root["roles"][role_name]["keyids"]:
        result.append(
            {
                "keyid": keyid,
                "keytype": trust.ED25519_KEYTYPE,
                "public": bytes.fromhex(public_by_id[keyid]["public"]),
                "seed": None,
            }
        )
    return result


def _build_rotated_root(
    args: argparse.Namespace,
    *,
    release_override: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any], List[bytes], List[bytes]]:
    current_envelope = trust.load_envelope(
        trust.read_regular_file(Path(args.current_root)), "current root"
    )
    current_root = trust.validate_root_signed(current_envelope["signed"])

    root_members = (
        _load_keys(args.root_key) if args.root_key else None
    )
    release_members = (
        _load_keys(args.release_key) if args.release_key else None
    )
    revocation_members = (
        _load_keys(args.revocation_key) if args.revocation_key else None
    )
    if release_override is not None:
        release_members = release_override

    root_keys = _carry_or_replace(current_root, trust.ROLE_ROOT, root_members)
    release_keys = _carry_or_replace(current_root, trust.ROLE_RELEASE, release_members)
    revocation_keys = _carry_or_replace(
        current_root, trust.ROLE_REVOCATION, revocation_members
    )

    default_thresholds = {
        role_name: current_root["roles"][role_name]["threshold"]
        for role_name in trust.ROLES
    }
    thresholds = {}
    for role_name, flag_value in (
        (trust.ROLE_ROOT, args.threshold_root),
        (trust.ROLE_RELEASE, args.threshold_release),
        (trust.ROLE_REVOCATION, args.threshold_revocation),
    ):
        thresholds[role_name] = (
            flag_value if flag_value is not None else default_thresholds[role_name]
        )
    roles = _roles_table(
        {
            trust.ROLE_ROOT: root_keys,
            trust.ROLE_RELEASE: release_keys,
            trust.ROLE_REVOCATION: revocation_keys,
        },
        thresholds,
    )
    all_keys = root_keys + release_keys + revocation_keys
    issued_at, expires = _resolve_issued_expires(
        args, default_expiry_days=ROOT_EXPIRY_DAYS
    )
    rekor_entries = (
        _rekor_entries(args.rekor_pub) if args.rekor_pub else current_root["rekor_keys"]
    )
    signed = trust.make_root_signed(
        version=current_root["version"] + 1,
        roles=roles,
        keys=_key_map(all_keys),
        expires=expires,
        rekor_keys=rekor_entries,
    )

    old_signers = _load_keys(args.root_signing_key)
    old_root_ids = set(current_root["roles"][trust.ROLE_ROOT]["keyids"])
    old_seeds = []
    for key in old_signers:
        if key["keyid"] not in old_root_ids:
            raise SigningError(
                "signing key {} is not authorised by the current root".format(key["keyid"])
            )
        old_seeds.append(require_seed(key, "root rotation"))
    new_root_seeds: List[bytes] = []
    for key in _load_keys(args.new_root_key):
        if key["keyid"] not in roles[trust.ROLE_ROOT]["keyids"]:
            raise SigningError(
                "new root key {} is not a member of the rotated root role".format(
                    key["keyid"]
                )
            )
        new_root_seeds.append(require_seed(key, "root rotation self-signature"))

    return current_root, signed, old_seeds, new_root_seeds


def cmd_root_rotate(args: argparse.Namespace) -> Dict[str, Any]:
    current_root, signed, old_seeds, new_root_seeds = _build_rotated_root(args)
    envelope = trust.seal_envelope(signed, old_seeds)
    new_root_ids = set(signed["roles"][trust.ROLE_ROOT]["keyids"])
    for seed in new_root_seeds:
        public = trust.ed25519_public_from_seed(seed)
        if trust.ed25519_key_id(public) in new_root_ids:
            envelope = trust.add_envelope_signature(envelope, seed)
    try:
        trust.verify_root_document(envelope, current_root)
    except trust.TrustError as exc:
        raise SigningError("rotated root failed verification: {}".format(exc)) from exc
    write_public_document(Path(args.out), envelope)
    return {
        "document": "root",
        "version": signed["version"],
        "out": args.out,
        "root_keyids": signed["roles"][trust.ROLE_ROOT]["keyids"],
    }


def cmd_release_key_add(args: argparse.Namespace) -> Dict[str, Any]:
    added = _load_keys([args.key])
    current_envelope = trust.load_envelope(
        trust.read_regular_file(Path(args.current_root)), "current root"
    )
    current_root = trust.validate_root_signed(current_envelope["signed"])
    existing = _carry_or_replace(current_root, trust.ROLE_RELEASE, None)
    if any(key["keyid"] == added[0]["keyid"] for key in existing):
        raise SigningError("release key {} is already registered".format(added[0]["keyid"]))
    current_root, signed, old_seeds, new_seeds = _build_rotated_root(
        args, release_override=existing + added
    )
    envelope = _seal_and_check_root(signed, current_root, old_seeds + new_seeds)
    write_public_document(Path(args.out), envelope)
    return {"document": "root", "version": signed["version"], "out": args.out,
            "added_keyid": added[0]["keyid"]}


def cmd_release_key_retire(args: argparse.Namespace) -> Dict[str, Any]:
    target = _load_keys([args.key])[0]["keyid"] if Path(args.key).exists() else args.key
    current_envelope = trust.load_envelope(
        trust.read_regular_file(Path(args.current_root)), "current root"
    )
    current_root = trust.validate_root_signed(current_envelope["signed"])
    existing = _carry_or_replace(current_root, trust.ROLE_RELEASE, None)
    remaining = [key for key in existing if key["keyid"] != target]
    if len(remaining) == len(existing):
        raise SigningError("release key {} is not currently registered".format(target))
    built, signed, old_seeds, new_seeds = _build_rotated_root(
        args, release_override=remaining
    )
    envelope = _seal_and_check_root(signed, built, old_seeds + new_seeds)
    write_public_document(Path(args.out), envelope)
    return {"document": "root", "version": signed["version"], "out": args.out,
            "retired_keyid": target}


# ---------------------------------------------------------------------------
# release manifest and index signing
# ---------------------------------------------------------------------------


def _load_root_for_check(path_value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path_value:
        return None
    envelope = trust.load_envelope(
        trust.read_regular_file(Path(path_value)), "root"
    )
    return trust.validate_root_signed(envelope["signed"])


def _signing_seeds(key_paths: Sequence[str], label: str) -> List[bytes]:
    seeds = []
    for key in _load_keys(key_paths):
        seeds.append(require_seed(key, label))
    if not seeds:
        raise SigningError("{} requires at least one private key".format(label))
    return seeds


def cmd_sign_manifest(args: argparse.Namespace) -> Dict[str, Any]:
    signed = json.loads(trust.read_regular_file(Path(args.input)).decode("utf-8"))
    try:
        trust.validate_release_manifest(signed)
    except trust.TrustError as exc:
        raise SigningError("unsigned manifest failed validation: {}".format(exc)) from exc
    seeds = _signing_seeds(args.release_key, "sign-manifest")
    if args.append_to:
        envelope = trust.load_envelope(
            trust.read_regular_file(Path(args.append_to)), "existing manifest envelope"
        )
        if envelope["signed"] != signed:
            raise SigningError(
                "--append-to envelope signs a different manifest document"
            )
        for seed in seeds:
            envelope = trust.add_envelope_signature(envelope, seed)
    else:
        envelope = trust.seal_envelope(signed, seeds)
    root_signed = _load_root_for_check(args.root)
    if root_signed is not None:
        try:
            signers = trust.verify_role_envelope(
                envelope,
                trust.role_publics(root_signed, trust.ROLE_RELEASE),
                trust.role_threshold(root_signed, trust.ROLE_RELEASE),
            )
        except trust.TrustError as exc:
            raise SigningError("manifest threshold not met under root: {}".format(exc)) from exc
    else:
        signers = {entry["keyid"] for entry in envelope["signatures"]}
    trust.load_envelope(render_json(envelope), "self-check")
    write_public_document(Path(args.out), envelope)
    return {
        "document": "release",
        "out": args.out,
        "version": signed["version"],
        "sequence": signed["sequence"],
        "signer_keyids": sorted(signers),
    }


def cmd_sign_index(args: argparse.Namespace) -> Dict[str, Any]:
    manifest_envelope = trust.load_envelope(
        trust.read_regular_file(Path(args.manifest)), "signed manifest"
    )
    old_signed = None
    if args.current_index:
        old_envelope = trust.load_envelope(
            trust.read_regular_file(Path(args.current_index)), "current index"
        )
        old_signed = trust.validate_release_index(old_envelope["signed"])
    issued_at = args.issued_at or trust.utc_now_iso()
    trust.require_iso8601_utc(issued_at, "issued_at")
    try:
        new_signed = trust.append_index_entry(
            old_signed,
            manifest_envelope,
            issued_at=issued_at,
            rekor_uuid=args.rekor_uuid,
            log_index=args.rekor_log_index,
        )
    except trust.TrustError as exc:
        raise SigningError("cannot extend release index: {}".format(exc)) from exc
    seeds = _signing_seeds(args.release_key, "sign-index")
    envelope = trust.seal_envelope(new_signed, seeds)
    root_signed = _load_root_for_check(args.root)
    signers: set = set()
    if root_signed is not None:
        try:
            signers = trust.verify_index_signature(envelope, root_signed)
        except trust.TrustError as exc:
            raise SigningError("release index threshold not met: {}".format(exc)) from exc
    write_public_document(Path(args.out), envelope)
    return {
        "document": "release-index",
        "out": args.out,
        "index_version": new_signed["version"],
        "signer_keyids": sorted(signers),
    }


# ---------------------------------------------------------------------------
# revocations
# ---------------------------------------------------------------------------


def _empty_revocations(version: int, issued_at: str, expires: str) -> Dict[str, Any]:
    return {
        "_type": trust.REVOCATIONS_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "version": version,
        "issued_at": issued_at,
        "expires": expires,
        "revoked_keys": [],
        "revoked_releases": [],
        "revoked_artifacts": [],
    }


def cmd_revoke(args: argparse.Namespace) -> Dict[str, Any]:
    issued_at, expires = _resolve_issued_expires(
        args, default_expiry_days=REVOCATIONS_EXPIRY_DAYS
    )
    if args.current_revocations:
        old_envelope = trust.load_envelope(
            trust.read_regular_file(Path(args.current_revocations)),
            "current revocations",
        )
        old_signed = trust.validate_revocations(old_envelope["signed"])
        signed = json.loads(json.dumps(old_signed))
        signed["version"] = old_signed["version"] + 1
        signed["issued_at"] = issued_at
        signed["expires"] = expires
    else:
        signed = _empty_revocations(1, issued_at, expires)

    revoked_at = args.revoked_at or issued_at
    trust.require_iso8601_utc(revoked_at, "revoked_at")
    if not args.reason:
        raise SigningError("--reason is required for every revocation")

    if args.kind == "key":
        if not args.keyid or not args.keyid.startswith(trust.ED25519_KEYTYPE + ":"):
            raise SigningError("--keyid must be an ed25519 keyid")
        if trust.revoked_key_entry(signed, args.keyid) is not None:
            raise SigningError("key {} is already revoked".format(args.keyid))
        signed["revoked_keys"].append(
            {"keyid": args.keyid, "reason": args.reason, "revoked_at": revoked_at}
        )
    elif args.kind == "artifact":
        try:
            trust.require_hex(args.sha256, "sha256", 32)
        except trust.TrustError as exc:
            raise SigningError(str(exc)) from exc
        if trust.revoked_artifact_entry(signed, args.sha256) is not None:
            raise SigningError("artifact {} is already revoked".format(args.sha256))
        signed["revoked_artifacts"].append(
            {"sha256": args.sha256, "reason": args.reason, "revoked_at": revoked_at}
        )
    elif args.kind == "release":
        if args.release_line not in trust.RELEASE_LINES:
            raise SigningError(
                "--release-line must be one of {}".format(trust.RELEASE_LINES)
            )
        trust.parse_semver(args.version, label="version")
        if args.to_version:
            trust.parse_semver(args.to_version, label="to_version")
        if args.severity not in trust.REVOCATION_SEVERITIES:
            raise SigningError(
                "--severity must be one of {}".format(trust.REVOCATION_SEVERITIES)
            )
        if args.fixed_version:
            trust.parse_semver(args.fixed_version, label="fixed_version")
        if (
            trust.revoked_release_entry(signed, args.release_line, args.version)
            is not None
        ):
            raise SigningError(
                "{} {} is already covered by a revocation".format(
                    args.release_line, args.version
                )
            )
        signed["revoked_releases"].append(
            {
                "release_line": args.release_line,
                "version": args.version,
                "to_version": args.to_version,
                "severity": args.severity,
                "reason": args.reason,
                "fixed_version": args.fixed_version,
                "security_exception_allowed": bool(args.allow_security_exception),
                "revoked_at": revoked_at,
            }
        )
    else:  # pragma: no cover - argparse choices guard
        raise SigningError("unknown revocation kind: {}".format(args.kind))

    try:
        trust.validate_revocations(signed)
        trust.ensure_revocations_cumulative(
            signed, old_signed if args.current_revocations else None
        )
    except trust.TrustError as exc:
        raise SigningError("revocations document failed validation: {}".format(exc)) from exc

    seeds = _signing_seeds(args.revocation_key, "revoke")
    envelope = trust.seal_envelope(signed, seeds)
    root_signed = _load_root_for_check(args.root)
    signers: set = set()
    if root_signed is not None:
        try:
            trust.verify_revocations_signature(envelope, root_signed)
            signers = trust.verify_role_envelope(
                envelope,
                trust.role_publics(root_signed, trust.ROLE_REVOCATION),
                trust.role_threshold(root_signed, trust.ROLE_REVOCATION),
            )
        except trust.TrustError as exc:
            raise SigningError("revocations threshold not met: {}".format(exc)) from exc
    write_public_document(Path(args.out), envelope)
    return {
        "document": "revocations",
        "out": args.out,
        "version": signed["version"],
        "kind": args.kind,
        "signer_keyids": sorted(signers),
    }


# ---------------------------------------------------------------------------
# Rekor hashedrekord submission (the ONLY network surface in this tool)
#
# The log anchors the canonical signed manifest payload. The P-256 artifact
# signature is produced offline (openssl over the raw 32-byte digest) and
# handed in via --signature-file; this code never signs with P-256.
# ---------------------------------------------------------------------------


def manifest_canonical_digest(manifest_path: Path) -> Tuple[str, bytes]:
    envelope = trust.load_envelope(
        trust.read_regular_file(Path(manifest_path)), "signed manifest"
    )
    payload = trust.signed_payload_bytes(envelope)
    return hashlib.sha256(payload).hexdigest(), payload


def build_hashedrekord_document(
    digest_hex: str,
    signature_bytes: bytes,
    public_pem: str,
    *,
    api_version: str = REKOR_PROPOSAL_API_VERSION,
) -> Dict[str, Any]:
    trust.require_hex(digest_hex, "artifact digest", 32)
    if not isinstance(public_pem, str) or "BEGIN PUBLIC KEY" not in public_pem:
        raise SigningError("artifact public key must be an X.509 SPKI PEM")
    return {
        "apiVersion": api_version,
        "kind": trust.REKOR_HASHEDREKORD_KIND,
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
            "signature": {
                "content": trust.rekor_b64_encode(signature_bytes),
                "publicKey": {
                    "content": trust.rekor_b64_encode(public_pem.encode("ascii"))
                },
            },
        },
    }


def preflight_hashedrekord(document: Dict[str, Any]) -> Dict[str, Any]:
    """Validate body shape and the artifact signature before any network call."""

    canonical = json.loads(json.dumps(document))
    canonical["apiVersion"] = trust.REKOR_HASHEDREKORD_API_VERSION
    body = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode("utf-8")
    try:
        decoded = trust.decode_hashedrekord_body(body)
        scheme, public_hex = trust.hashedrekord_verify_artifact_signature(decoded)
    except trust.TrustError as exc:
        raise SigningError(
            "hashedrekord proposal failed local verification: {}".format(exc)
        ) from exc
    return {
        "scheme": scheme,
        "public_hex": public_hex,
        "digest_hex": decoded["digest_hex"],
        "body": body,
    }


def _entry_inclusion_proof(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    verification = entry.get("verification")
    if isinstance(verification, dict) and verification.get("inclusionProof"):
        return verification["inclusionProof"]
    proof = entry.get("proof")
    if isinstance(proof, dict) and proof.get("inclusionProof"):
        return proof["inclusionProof"]
    return None


def _normalize_entry_map(status: int, data: bytes) -> Tuple[str, Dict[str, Any]]:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SigningError(
            "Rekor returned non-JSON body for HTTP {}".format(status)
        ) from exc
    if not isinstance(parsed, dict) or len(parsed) != 1:
        raise SigningError(
            "Rekor response must be a single-entry object, got {}".format(
                type(parsed).__name__
            )
        )
    uuid, entry = next(iter(parsed.items()))
    if not isinstance(uuid, str) or not isinstance(entry, dict):
        raise SigningError("Rekor entry map has an invalid shape")
    for field in ("body", "integratedTime", "logID", "logIndex"):
        if field not in entry:
            raise SigningError("Rekor entry is missing {!r}".format(field))
    return uuid, entry


def _http_request(
    method: str,
    url: str,
    *,
    data: Optional[bytes],
    timeout: float,
    ca_file: Optional[str],
    accept: str,
    content_type: Optional[str] = None,
) -> Tuple[int, bytes, Dict[str, str]]:
    import ssl
    import urllib.error
    import urllib.request

    headers = {"Accept": accept}
    if content_type is not None:
        headers["Content-Type"] = content_type
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    context = ssl.create_default_context(cafile=ca_file) if ca_file else None
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=context)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers.items())
    try:
        return response.status, response.read(), dict(response.headers.items())
    finally:
        response.close()


def _header(headers: Dict[str, str], name: str) -> Optional[str]:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def submit_rekor_entry(
    *,
    base_url: str,
    entries_path: str,
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
    out_path: Path,
    log_pem_path: Optional[Path] = None,
    api_version: str = REKOR_PROPOSAL_API_VERSION,
    ca_file: Optional[str] = None,
    timeout: float = DEFAULT_REKOR_TIMEOUT_SECONDS,
    poll_interval: float = DEFAULT_REKOR_POLL_INTERVAL_SECONDS,
    max_wait: float = DEFAULT_REKOR_MAX_WAIT_SECONDS,
    sleeper=None,
) -> Dict[str, Any]:
    import time

    if sleeper is None:
        sleeper = time.sleep
    digest_hex, _payload = manifest_canonical_digest(manifest_path)
    signature_bytes = trust.read_regular_file(Path(signature_path))
    public_pem = trust.read_regular_file(Path(public_key_path)).decode("ascii")
    document = build_hashedrekord_document(
        digest_hex, signature_bytes, public_pem, api_version=api_version
    )
    preflight = preflight_hashedrekord(document)
    if preflight["digest_hex"] != digest_hex:
        raise SigningError("hashedrekord digest mismatch during local preflight")

    post_url = base_url.rstrip("/") + "/" + entries_path.lstrip("/")
    proposal = json.dumps(
        {"proposedEntry": document}, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    try:
        status, data, headers = _http_request(
            "POST",
            post_url,
            data=proposal,
            timeout=timeout,
            ca_file=ca_file,
            accept="application/json",
            content_type="application/json",
        )
    except OSError as exc:
        raise SigningError("cannot contact Rekor at {}: {}".format(post_url, exc)) from exc

    if status not in (200, 201, 409):
        raise SigningError("Rekor rejected the proposal with HTTP {}".format(status))
    uuid, entry = _normalize_entry_map(status, data)
    if status == 409:
        location = _header(headers, "Location")
        if location:
            uuid = location.rstrip("/").split("/")[-1] or uuid
        if not uuid:
            raise SigningError("Rekor 409 response did not identify the existing entry")
        already_exists = True
    else:
        already_exists = False

    get_url = "{}/{}".format(post_url, uuid)
    deadline = time.monotonic() + max_wait
    while _entry_inclusion_proof(entry) is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SigningError(
                "timed out waiting for Rekor inclusion proof after {}s".format(max_wait)
            )
        sleeper(min(poll_interval, remaining))
        try:
            get_status, get_data, _ = _http_request(
                "GET",
                get_url,
                data=None,
                timeout=timeout,
                ca_file=ca_file,
                accept="application/json",
            )
        except OSError as exc:
            raise SigningError("Rekor poll failed: {}".format(exc)) from exc
        if get_status != 200:
            raise SigningError(
                "Rekor entry lookup returned HTTP {}".format(get_status)
            )
        _, entry = _normalize_entry_map(get_status, get_data)

    # Cross-check the body stored by the log against the proposal preflight.
    try:
        stored = trust.decode_hashedrekord_body(
            trust.rekor_b64_decode(entry["body"], "entry body")
        )
    except trust.TrustError as exc:
        raise SigningError("stored Rekor entry is malformed: {}".format(exc)) from exc
    if stored["digest_hex"] != digest_hex:
        raise SigningError(
            "stored Rekor entry anchors a different digest than the manifest"
        )
    if stored["key_scheme"] != preflight["scheme"]:
        raise SigningError("stored Rekor entry changed the artifact key scheme")

    binding = None
    if log_pem_path is not None:
        log_pem = trust.read_regular_file(Path(log_pem_path)).decode("ascii")
        try:
            binding = trust.verify_hashedrekord_entry(entry, log_pem)
        except trust.TrustError as exc:
            raise SigningError(
                "Rekor entry failed offline SET/inclusion verification: {}".format(exc)
            ) from exc

    write_public_document(Path(out_path), entry)
    return {
        "document": "rekor-entry",
        "out": str(out_path),
        "uuid": uuid,
        "log_index": entry["logIndex"],
        "integrated_time": entry["integratedTime"],
        "log_id": entry["logID"],
        "already_existed": already_exists,
        "artifact_scheme": preflight["scheme"],
        "binding": binding,
    }


def cmd_rekor_submit(args: argparse.Namespace) -> Dict[str, Any]:
    if args.rekor_url or args.entries_path:
        base_url = args.rekor_url
        entries_path = args.entries_path or "/api/v1/log/entries"
        if not base_url:
            raise SigningError("--entries-path requires --rekor-url")
    else:
        policy = trust.load_policy()
        base_url = policy["rekor"]["base_url"]
        entries_path = policy["rekor"]["entries_path"]
    return submit_rekor_entry(
        base_url=base_url,
        entries_path=entries_path,
        manifest_path=Path(args.manifest),
        signature_path=Path(args.signature_file),
        public_key_path=Path(args.public_key),
        out_path=Path(args.out),
        log_pem_path=Path(args.rekor_pub) if args.rekor_pub else None,
        api_version=args.api_version,
        ca_file=args.ca_file,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        max_wait=args.max_wait,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _add_key_repeatable(parser: argparse.ArgumentParser, name: str, help_text: str) -> None:
    parser.add_argument(name, action="append", default=[], help=help_text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="keysmith_signing.py",
        description="Air-gapped maintainer tool for codex-keysmith trust metadata.",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="generate an Ed25519 key pair")
    keygen.add_argument("--role", required=True, choices=trust.ROLES)
    keygen.add_argument("--out", required=True, help="secret key output directory")
    keygen.add_argument("--name", help="key file base name (defaults to role-keyid)")
    keygen.add_argument(
        "--from-seed",
        help="TEST ONLY: derive the key from 64 hex chars instead of os.urandom",
    )
    keygen.add_argument(
        "--i-know-this-is-not-a-repo",
        action="store_true",
        help="allow secret output inside a git work tree (danger override)",
    )

    root_init = sub.add_parser("root-init", help="create the self-signed root v1")
    root_init.add_argument("--out", required=True)
    _add_key_repeatable(root_init, "--root-key", "root key container (private)")
    _add_key_repeatable(root_init, "--release-key", "release key container")
    _add_key_repeatable(root_init, "--revocation-key", "revocation key container")
    root_init.add_argument("--threshold-root", type=int, default=1)
    root_init.add_argument("--threshold-release", type=int, default=1)
    root_init.add_argument("--threshold-revocation", type=int, default=1)
    _add_key_repeatable(root_init, "--rekor-pub", "trusted Rekor log PEM public key")
    root_init.add_argument("--issued-at")
    root_init.add_argument("--expires")

    root_rotate = sub.add_parser("root-rotate", help="issue root v(N+1)")
    root_rotate.add_argument("--current-root", required=True)
    root_rotate.add_argument("--out", required=True)
    _add_key_repeatable(
        root_rotate, "--root-signing-key",
        "current root private key (repeat to meet the old threshold)",
    )
    _add_key_repeatable(
        root_rotate, "--new-root-key",
        "new root private key that also self-signs the rotated document",
    )
    _add_key_repeatable(root_rotate, "--root-key", "full replacement root key set")
    _add_key_repeatable(root_rotate, "--release-key", "full replacement release key set")
    _add_key_repeatable(
        root_rotate, "--revocation-key", "full replacement revocation key set"
    )
    root_rotate.add_argument("--threshold-root", type=int)
    root_rotate.add_argument("--threshold-release", type=int)
    root_rotate.add_argument("--threshold-revocation", type=int)
    _add_key_repeatable(root_rotate, "--rekor-pub", "replacement trusted Rekor log PEM set")
    root_rotate.add_argument("--issued-at")
    root_rotate.add_argument("--expires")

    add_parser = sub.add_parser("release-key-add", help="register a release key")
    retire_parser = sub.add_parser("release-key-retire", help="retire a release key")
    for child, adding in ((add_parser, True), (retire_parser, False)):
        child.add_argument("--current-root", required=True)
        child.add_argument("--out", required=True)
        child.add_argument("--key", required=True,
                           help="public/private key file" if adding else "key file or keyid")
        _add_key_repeatable(
            child, "--root-signing-key", "current root private key (threshold)"
        )
        _add_key_repeatable(child, "--new-root-key", "new root self-signer")
        child.add_argument("--threshold-root", type=int)
        child.add_argument("--threshold-release", type=int)
        child.add_argument("--threshold-revocation", type=int)
        _add_key_repeatable(child, "--root-key", "full replacement root key set")
        _add_key_repeatable(child, "--release-key", "full replacement release key set")
        _add_key_repeatable(child, "--revocation-key", "full replacement revocation key set")
        _add_key_repeatable(child, "--rekor-pub", "replacement Rekor log PEM set")
        child.add_argument("--issued-at")
        child.add_argument("--expires")

    sign_manifest = sub.add_parser("sign-manifest", help="seal a release manifest")
    sign_manifest.add_argument("--input", required=True, help="unsigned manifest JSON")
    sign_manifest.add_argument("--out", required=True)
    _add_key_repeatable(sign_manifest, "--release-key", "release private key")
    sign_manifest.add_argument(
        "--append-to", help="existing signed envelope to append signature(s) to"
    )
    sign_manifest.add_argument("--root", help="optional root used to check the threshold")

    sign_index = sub.add_parser("sign-index", help="extend and seal the release index")
    sign_index.add_argument("--manifest", required=True, help="signed manifest envelope")
    sign_index.add_argument("--current-index")
    sign_index.add_argument("--out", required=True)
    _add_key_repeatable(sign_index, "--release-key", "release private key")
    sign_index.add_argument("--issued-at")
    sign_index.add_argument("--rekor-uuid")
    sign_index.add_argument("--rekor-log-index", type=int)
    sign_index.add_argument("--root")

    revoke = sub.add_parser("revoke", help="issue a cumulative revocations document")
    revoke.add_argument("--kind", required=True, choices=("key", "release", "artifact"))
    revoke.add_argument("--current-revocations")
    revoke.add_argument("--out", required=True)
    _add_key_repeatable(revoke, "--revocation-key", "revocation private key")
    revoke.add_argument("--root")
    revoke.add_argument("--reason", required=True)
    revoke.add_argument("--keyid")
    revoke.add_argument("--sha256")
    revoke.add_argument("--release-line")
    revoke.add_argument("--version")
    revoke.add_argument("--to-version")
    revoke.add_argument("--severity", choices=trust.REVOCATION_SEVERITIES)
    revoke.add_argument("--fixed-version")
    revoke.add_argument("--allow-security-exception", action="store_true")
    revoke.add_argument("--issued-at")
    revoke.add_argument("--expires")
    revoke.add_argument("--revoked-at")

    rekor_submit = sub.add_parser(
        "rekor-submit",
        help="submit a hashedrekord entry (the only network-using command)",
    )
    rekor_submit.add_argument("--manifest", required=True)
    rekor_submit.add_argument(
        "--signature-file",
        required=True,
        help="DER ECDSA-P256 signature over the raw 32-byte manifest digest",
    )
    rekor_submit.add_argument(
        "--public-key", required=True, help="signer SPKI PEM (P-256)"
    )
    rekor_submit.add_argument(
        "--out", required=True, help="path for the returned rekor-entry.json"
    )
    rekor_submit.add_argument("--rekor-url")
    rekor_submit.add_argument("--entries-path")
    rekor_submit.add_argument(
        "--rekor-pub", help="trusted Rekor log PEM; verifies SET/inclusion before write"
    )
    rekor_submit.add_argument("--ca-file")
    rekor_submit.add_argument("--api-version", default=REKOR_PROPOSAL_API_VERSION)
    rekor_submit.add_argument("--timeout", type=float, default=15.0)
    rekor_submit.add_argument("--poll-interval", type=float, default=2.0)
    rekor_submit.add_argument("--max-wait", type=float, default=60.0)
    return parser


_DISPATCH = {
    "keygen": cmd_keygen,
    "root-init": cmd_root_init,
    "root-rotate": cmd_root_rotate,
    "release-key-add": cmd_release_key_add,
    "release-key-retire": cmd_release_key_retire,
    "sign-manifest": cmd_sign_manifest,
    "sign-index": cmd_sign_index,
    "revoke": cmd_revoke,
    "rekor-submit": cmd_rekor_submit,
}


def _normalise_argv(argv: Sequence[str]) -> List[str]:
    """Support the documented ``release-key add|retire`` two-word command."""

    tokens = list(argv)
    if "release-key" in tokens:
        position = tokens.index("release-key")
        if position + 1 >= len(tokens) or tokens[position + 1] not in ("add", "retire"):
            raise SigningError("usage: release-key add|retire ...")
        tokens[position : position + 2] = [
            "release-key-{}".format(tokens[position + 1])
        ]
    return tokens


def main(argv: Optional[Sequence[str]] = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in raw_argv
    try:
        tokens = _normalise_argv(raw_argv)
        args = build_parser().parse_args(tokens)
        result = _DISPATCH[args.command](args)
    except (SigningError, trust.TrustError, OSError, ValueError) as exc:
        message = "keysmith_signing: {}".format(exc)
        if as_json:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(message, file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(dict(result or {}, ok=True), sort_keys=True))
    else:
        _print_human(args.command, result or {})
    return 0


def _print_human(command: str, result: Dict[str, Any]) -> None:
    if command == "keygen":
        print("generated {} key".format(result["role"]))
        print("  keyid:      {}".format(result["keyid"]))
        print("  fingerprint:{}".format(result["fingerprint"]))
        print("  secret:     {} (mode 0600)".format(result["secret_path"]))
        print("  public:     {}".format(result["public_path"]))
        if result["test_seed"]:
            print("  WARNING: key derived from --from-seed; never use it in production")
        print("  keep the secret container on air-gapped media; never commit it")
        return
    print("{} written: {}".format(result.get("document", "document"), result.get("out")))
    for field in (
        "version",
        "index_version",
        "added_keyid",
        "retired_keyid",
        "uuid",
        "log_index",
        "integrated_time",
    ):
        if field in result:
            print("  {}: {}".format(field, result[field]))
    keyids = result.get("signer_keyids") or result.get("root_keyids")
    if keyids:
        print("  keyids: {}".format(", ".join(keyids)))


if __name__ == "__main__":
    raise SystemExit(main())
