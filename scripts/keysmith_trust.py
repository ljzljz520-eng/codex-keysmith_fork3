#!/usr/bin/env python3
"""Release trust engine for codex-keysmith.

This module is the single cryptographic/metadata engine shared by the
release verifier, the maintainer signing tool, and the release builders.

Hard constraints:
- Python 3.9+ syntax and standard library only (no third-party imports).
- Every metadata document uses one canonical byte serialization; signatures
  are always over that exact serialization.
- Every malformed input fails closed by raising a TrustError subclass.

The implementation is intentionally data-only and side-effect free except
for the explicit filesystem helpers near the end of the module.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, List, Optional, Sequence, Tuple

PRODUCT = "codex-keysmith"
SPEC_VERSION = "1.0.0"
SCHEMA_VERSION = 1

STABLE_LINE = "stable"
DESKTOP_BETA_LINE = "desktop-beta"
RELEASE_LINES = (STABLE_LINE, DESKTOP_BETA_LINE)

ROOT_TYPE = "root"
RELEASE_TYPE = "release"
RELEASE_INDEX_TYPE = "release-index"
REVOCATIONS_TYPE = "revocations"
METADATA_TYPES = (ROOT_TYPE, RELEASE_TYPE, RELEASE_INDEX_TYPE, REVOCATIONS_TYPE)

ED25519_KEYTYPE = "ed25519"
REKOR_KEY_USE = "rekor"

ROLE_ROOT = "root"
ROLE_RELEASE = "release"
ROLE_REVOCATION = "revocation"
ROLES = (ROLE_ROOT, ROLE_RELEASE, ROLE_REVOCATION)

TRUST_DIRNAME = "trust"
STATE_DIR_BASENAME = ".codex-keysmith"
ROOT_CACHE_NAME = "root.json"
REVOCATIONS_CACHE_NAME = "revocations.json"
INDEX_CACHE_NAME = "release-index.json"
STATE_NAME = "state.json"
AUDIT_NAME = "audit.jsonl"
ROOTS_DIRNAME = "roots"
REVOCATIONS_DIRNAME = "revocations"
INDEXES_DIRNAME = "indexes"
MANIFESTS_DIRNAME = "manifests"

POLICY_RELATIVE_PATH = Path("trust") / "policy.json"
TRUST_DIR_ENV = "CODEX_KEYSMITH_TRUST_DIR"

# Exit codes consumed by verify_release.py. Centralised here so every layer
# reports the same stable contract.
EXIT_OK = 0
EXIT_GENERIC = 1
EXIT_SIGNATURE = 10
EXIT_DIGEST = 11
EXIT_REVOKED = 12
EXIT_DOWNGRADE = 13
EXIT_REKOR = 14
EXIT_STATE = 15


class TrustError(RuntimeError):
    """Base class for every trust-engine failure. Never caught for 'pass'."""

    exit_code = EXIT_GENERIC


class PolicyError(TrustError):
    """The trust policy document is missing, malformed, or unsupported."""

    exit_code = EXIT_STATE


class MetadataError(TrustError):
    """A signed metadata document violates the schema or canonical form."""

    exit_code = EXIT_SIGNATURE


class SignatureError(TrustError):
    """A signature, key, or threshold check failed."""

    exit_code = EXIT_SIGNATURE


class DigestError(TrustError):
    """An artifact digest or size does not match its signed record."""

    exit_code = EXIT_DIGEST


class RevocationError(TrustError):
    """A key, release, or artifact is blocked by signed revocations."""

    exit_code = EXIT_REVOKED


class DowngradeError(TrustError):
    """A release is below the persisted watermark without an override."""

    exit_code = EXIT_DOWNGRADE


class RekorError(TrustError):
    """A transparency-log entry, SET, or inclusion proof cannot be verified."""

    exit_code = EXIT_REKOR


class StateError(TrustError):
    """The local trust state is missing, corrupt, or tampered."""

    exit_code = EXIT_STATE


# ---------------------------------------------------------------------------
# Canonical serialization
# ---------------------------------------------------------------------------


def canonical_json_bytes(value: Any) -> bytes:
    """Return the unique byte serialization used for signing and hashing.

    The form matches the repository-wide deterministic JSON convention:
    UTF-8, two-space indentation, sorted keys, non-ASCII characters emitted
    literally, terminated by a single newline.
    """

    _require_json_value(value)
    return (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _require_json_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise MetadataError("canonical JSON cannot encode non-finite float at {}".format(path))
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise MetadataError(
                    "canonical JSON object keys must be strings at {}".format(path)
                )
            _require_json_value(item, "{}.{}".format(path, key))
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_json_value(item, "{}[{}]".format(path, index))
        return
    raise MetadataError("value of type {} is not JSON-serializable at {}".format(type(value).__name__, path))


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def parse_json_document(data: bytes, label: str) -> Any:
    if not isinstance(data, (bytes, bytearray)):
        raise MetadataError("{} must be provided as bytes".format(label))
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MetadataError("{} is not valid UTF-8".format(label)) from exc
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MetadataError("{} is not valid JSON: {}".format(label, exc.msg)) from exc
    return value


# ---------------------------------------------------------------------------
# Schema helpers
# ---------------------------------------------------------------------------


def require_object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise MetadataError("{} must be a JSON object".format(label))
    return value


def require_fields(value: dict, fields: Iterable[str], label: str) -> None:
    for field in fields:
        if field not in value:
            raise MetadataError("{} is missing required field {!r}".format(label, field))


def reject_unknown_fields(value: dict, allowed: Sequence[str], label: str) -> None:
    allowed_set = set(allowed)
    unknown = sorted(set(value) - allowed_set)
    if unknown:
        raise MetadataError(
            "{} contains unsupported field(s): {}".format(label, ", ".join(unknown))
        )


def exact_object(value: dict, fields: Sequence[str], label: str) -> None:
    require_fields(value, fields, label)
    reject_unknown_fields(value, fields, label)


def require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MetadataError("{} must be a non-empty string".format(label))
    return value


def require_int(value: Any, label: str, *, minimum: Optional[int] = None) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise MetadataError("{} must be an integer".format(label))
    if minimum is not None and value < minimum:
        raise MetadataError("{} must be >= {}".format(label, minimum))
    return value


def require_list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise MetadataError("{} must be a list".format(label))
    return value


def require_dict(value: Any, label: str) -> dict:
    return require_object(value, label)


def require_hex(value: Any, label: str, length: Optional[int] = None) -> str:
    text = require_str(value, label)
    if any(character not in "0123456789abcdef" for character in text):
        raise MetadataError("{} must be lowercase hexadecimal".format(label))
    if length is not None and len(text) != length * 2:
        raise MetadataError("{} must be exactly {} bytes ({} hex chars)".format(label, length, length * 2))
    return text


def require_iso8601_utc(value: Any, label: str) -> str:
    text = require_str(value, label)
    if not text.endswith("+00:00") and not text.endswith("Z"):
        raise MetadataError("{} must be UTC ISO-8601 (end with Z or +00:00)".format(label))
    return text


# ---------------------------------------------------------------------------
# Key identifiers and envelope structure
# ---------------------------------------------------------------------------


def ed25519_key_id(public_key: bytes) -> str:
    """Return the canonical key identifier for a raw Ed25519 public key."""

    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != 32:
        raise SignatureError("Ed25519 public keys must be 32 bytes")
    digest = hashlib.sha256(b"ed25519:" + bytes(public_key)).hexdigest()
    return "{}:{}".format(ED25519_KEYTYPE, digest)


def key_id_for_hex_public(public_hex: str) -> str:
    return ed25519_key_id(bytes.fromhex(require_hex(public_hex, "public key", 32)))


def signed_payload_bytes(envelope: dict) -> bytes:
    signed = require_object(envelope.get("signed"), "envelope.signed")
    return canonical_json_bytes(signed)


def load_envelope(data: bytes, label: str = "signed envelope") -> dict:
    envelope = require_object(parse_json_document(data, label), label)
    exact_object(envelope, ("signed", "signatures"), label)
    signed = require_object(envelope["signed"], "{}.signed".format(label))
    _type = require_str(signed.get("_type"), "{}.signed._type".format(label))
    if _type not in METADATA_TYPES:
        raise MetadataError("{} has unknown _type {!r}".format(label, _type))
    signatures = require_list(envelope["signatures"], "{}.signatures".format(label))
    seen = set()
    for index, item in enumerate(signatures):
        entry_label = "{}.signatures[{}]".format(label, index)
        entry = require_object(item, entry_label)
        exact_object(entry, ("keyid", "sig"), entry_label)
        require_str(entry["keyid"], "{}.keyid".format(entry_label))
        require_hex(entry["sig"], "{}.sig".format(entry_label))
        if len(entry["sig"]) != 128:
            raise MetadataError("{}.sig must be a 64-byte Ed25519 signature".format(entry_label))
        if entry["keyid"] in seen:
            raise MetadataError("{} repeats keyid {}".format(entry_label, entry["keyid"]))
        seen.add(entry["keyid"])
    return envelope


def envelope_signatures_by_key(envelope: dict) -> dict:
    return {entry["keyid"]: entry["sig"] for entry in envelope["signatures"]}


def make_envelope(signed: dict, signatures: Sequence[Tuple[str, bytes]]) -> dict:
    """Build a signed envelope.

    Signatures are (keyid, raw_signature) pairs; ordering is canonicalised by
    keyid so repeated sealing produces byte-identical output.
    """

    require_object(signed, "signed document")
    entries = []
    for keyid, signature in signatures:
        if not isinstance(keyid, str) or not keyid:
            raise SignatureError("signature keyid must be a non-empty string")
        if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
            raise SignatureError("Ed25519 signatures must be 64 bytes")
        entries.append({"keyid": keyid, "sig": bytes(signature).hex()})
    entries.sort(key=lambda item: item["keyid"])
    return {"signed": signed, "signatures": entries}


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def default_policy_path() -> Path:
    return repo_root() / POLICY_RELATIVE_PATH


def default_trust_dir() -> Path:
    override = os.environ.get(TRUST_DIR_ENV)
    if override:
        return Path(override)
    return Path.home() / STATE_DIR_BASENAME / TRUST_DIRNAME


_POLICY_FIELDS = (
    "schema_version",
    "spec_version",
    "product",
    "first_signed_version",
    "release_lines",
    "trust_material",
    "channels",
    "rekor",
    "revocations_default_expiry_days",
)

_SEMVER_PATTERN_CHARS = set("0123456789.-+")


def _semver_text(value: str) -> bool:
    if not value or value[0] == "v":
        return False
    core, sep, rest = value.partition("-")
    if not sep and "+" in rest:
        rest = ""
    if "+" in value:
        rest = rest.split("+", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or not all(part.isdigit() and (part == "0" or not part.startswith("0")) for part in parts):
        return False
    if sep:
        if not rest or any(not piece for piece in rest.split(".")):
            return False
    return True


def load_policy(path: Optional[Path] = None) -> dict:
    policy_path = Path(path) if path is not None else default_policy_path()
    data = read_regular_file(policy_path)
    try:
        parsed = parse_json_document(data, "trust policy")
        policy = require_object(parsed, "trust policy")
        return _validate_policy(policy)
    except MetadataError as exc:
        raise PolicyError(str(exc)) from exc


def _validate_policy(policy: dict) -> dict:
    exact_object(policy, _POLICY_FIELDS, "trust policy")
    if policy["schema_version"] != SCHEMA_VERSION:
        raise PolicyError(
            "trust policy schema_version is {}, expected {}".format(
                policy["schema_version"], SCHEMA_VERSION
            )
        )
    require_str(policy["spec_version"], "trust policy.spec_version")
    if policy["product"] != PRODUCT:
        raise PolicyError("trust policy product is not {!r}".format(PRODUCT))
    first = policy["first_signed_version"]
    if first is not None:
        if not isinstance(first, str) or not _semver_text(first):
            raise PolicyError("trust policy first_signed_version must be a semantic version or null")
    lines = policy["release_lines"]
    if not isinstance(lines, list) or not lines or any(line not in RELEASE_LINES for line in lines):
        raise PolicyError("trust policy release_lines is invalid")
    if set(lines) != set(RELEASE_LINES):
        raise PolicyError("trust policy must declare every supported release line exactly once")
    material = require_dict(policy["trust_material"], "trust policy.trust_material")
    exact_object(
        material,
        ("root_path_template", "revocations_path_template", "release_directory"),
        "trust policy.trust_material",
    )
    for field in ("root_path_template", "revocations_path_template"):
        template = require_str(material[field], "trust policy.trust_material.{}".format(field))
        if "{version}" not in template:
            raise PolicyError("trust policy {} must contain a {{version}} placeholder".format(field))
    require_str(material["release_directory"], "trust policy.trust_material.release_directory")
    channels = require_dict(policy["channels"], "trust policy.channels")
    exact_object(
        channels,
        ("root_url_template", "revocations_url_template", "release_index_url_template"),
        "trust policy.channels",
    )
    require_str(channels["root_url_template"], "channels.root_url_template")
    require_str(channels["revocations_url_template"], "channels.revocations_url_template")
    require_str(channels["release_index_url_template"], "channels.release_index_url_template")
    rekor = require_dict(policy["rekor"], "trust policy.rekor")
    exact_object(rekor, ("base_url", "entries_path", "entry_url_template"), "trust policy.rekor")
    require_str(rekor["base_url"], "rekor.base_url")
    require_str(rekor["entries_path"], "rekor.entries_path")
    entry_template = require_str(rekor["entry_url_template"], "rekor.entry_url_template")
    if "{entry_uuid}" not in entry_template:
        raise PolicyError("rekor.entry_url_template must contain {entry_uuid}")
    require_int(
        policy["revocations_default_expiry_days"],
        "trust policy.revocations_default_expiry_days",
        minimum=1,
    )
    return policy


def policy_channel_url(policy: dict, name: str, **kwargs: str) -> str:
    template = policy["channels"][name]
    return template.format(**kwargs)


# ---------------------------------------------------------------------------
# Filesystem primitives shared by every trust component
# ---------------------------------------------------------------------------


_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
_WINDOWS_RESERVED.update("COM{}".format(i) for i in range(1, 10))
_WINDOWS_RESERVED.update("LPT{}".format(i) for i in range(1, 10))


def validate_asset_name(name: str, label: str = "asset name") -> str:
    """Reject paths and Windows-unfriendly components in a flat asset name."""

    if not isinstance(name, str) or not name:
        raise MetadataError("{} must be a non-empty string".format(label))
    if "/" in name or "\\" in name or name in (".", ".."):
        raise MetadataError("{} must be a flat file name, got {!r}".format(label, name))
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise MetadataError("{} contains control characters".format(label))
    if name.endswith((" ", ".")):
        raise MetadataError("{} must not end with a space or dot".format(label))
    if any(ch in name for ch in '<>:"|?*'):
        raise MetadataError("{} contains characters that are unsafe on Windows".format(label))
    stem = name.split(".", 1)[0].upper()
    if stem in _WINDOWS_RESERVED:
        raise MetadataError("{} uses a reserved Windows file name".format(label))
    return name


def reject_symlink_ancestors(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            mode = os.lstat(str(current)).st_mode
        except FileNotFoundError:
            return
        if stat.S_ISLNK(mode):
            raise StateError("path contains a symbolic link: {}".format(current))


def read_regular_file(path: Path) -> bytes:
    target = Path(path)
    try:
        before = os.lstat(str(target))
    except FileNotFoundError as exc:
        raise StateError("required file is missing: {}".format(target)) from exc
    if not stat.S_ISREG(before.st_mode):
        raise StateError("required path is not a regular file: {}".format(target))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(target), flags)
    except OSError as exc:
        raise StateError("cannot open required file {}: {}".format(target, exc)) from exc
    try:
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def ensure_private_directory(path: Path) -> Path:
    target = Path(path)
    reject_symlink_ancestors(target.parent)
    if target.exists():
        mode = os.lstat(str(target)).st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
            raise StateError("trust path is not a directory: {}".format(target))
    else:
        target.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(str(target), 0o700)
    except OSError:
        # POSIX chmod is best effort on Windows ACLs.
        pass
    return target


def atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    target = Path(path)
    ensure_private_directory(target.parent)
    reject_symlink_ancestors(target)
    descriptor: Optional[int] = None
    temp_name: Optional[str] = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".keysmith-trust-", suffix=".tmp", dir=str(target.parent)
        )
        os.write(descriptor, bytes(data))
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.chmod(temp_name, mode)
        os.replace(temp_name, str(target))
        temp_name = None
    except OSError as exc:
        raise StateError("cannot atomically write {}: {}".format(target, exc)) from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temp_name is not None:
            try:
                os.unlink(temp_name)
            except OSError:
                pass


def append_audit_line(path: Path, entry: dict) -> None:
    """Append one canonical JSON audit record; the file is append-only."""

    line = (json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    target = Path(path)
    ensure_private_directory(target.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(str(target), flags, 0o600)
        os.write(descriptor, line)
        os.fsync(descriptor)
    except OSError as exc:
        raise StateError("cannot append audit record {}: {}".format(target, exc)) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        os.chmod(str(target), 0o600)
    except OSError:
        pass


def iter_audit_entries(path: Path) -> Iterable[dict]:
    if not Path(path).exists():
        return
    data = read_regular_file(path)
    for line_number, raw_line in enumerate(data.decode("utf-8").splitlines(), start=1):
        if not raw_line.strip():
            raise StateError("audit log contains a blank line at {}".format(line_number))
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise StateError("audit log line {} is corrupt: {}".format(line_number, exc.msg)) from exc
        if not isinstance(entry, dict) or "event" not in entry:
            raise StateError("audit log line {} is not an event object".format(line_number))
        yield entry


def sha256_file(path: Path) -> Tuple[str, int]:
    target = Path(path)
    try:
        size = os.lstat(str(target)).st_size
    except OSError as exc:
        raise StateError("cannot stat asset {}: {}".format(target, exc)) from exc
    digest = hashlib.sha256()
    seen = 0
    with open(str(target), "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            seen += len(chunk)
            digest.update(chunk)
    if seen != size:
        raise StateError("asset {} changed while hashing".format(target))
    return digest.hexdigest(), size


# ---------------------------------------------------------------------------
# RFC 8032 Ed25519 (standard library only)
#
# Reference formulas follow RFC 8032 sections 5.1 and 6 (the document's
# Python illustration), with two deliberate engineering changes:
#   * every extended coordinate is reduced mod p (the illustration leaves
#     intermediate products unreduced);
#   * base-point multiplication uses a lazily-built 4-bit window table.
# Verification uses the cofactored group equation [8]S*B = [8]R + [8]k*A.
# This is offline-tool grade software: it runs on an air-gapped maintainer
# machine and inside the offline verifier; it is not hardened against
# local side channels.
# ---------------------------------------------------------------------------

_ED_P = 2 ** 255 - 19
_ED_L = 2 ** 252 + 27742317777372353535851937790883648493


def _ed_inv(value: int) -> int:
    return pow(value, _ED_P - 2, _ED_P)


_ED_D = (-121665 * _ed_inv(121666)) % _ED_P
_ED_SQRT_M1 = pow(2, (_ED_P - 1) // 4, _ED_P)
_ED_IDENTITY = (0, 1, 1, 0)


def _ed_point_add(p_point: tuple, q_point: tuple) -> tuple:
    x1, y1, z1, t1 = p_point
    x2, y2, z2, t2 = q_point
    a_mul = ((y1 - x1) * (y2 - x2)) % _ED_P
    b_mul = ((y1 + x1) * (y2 + x2)) % _ED_P
    c_mul = (2 * t1 * t2 * _ED_D) % _ED_P
    d_mul = (2 * z1 * z2) % _ED_P
    e_mul = (b_mul - a_mul) % _ED_P
    f_mul = (d_mul - c_mul) % _ED_P
    g_mul = (d_mul + c_mul) % _ED_P
    h_mul = (b_mul + a_mul) % _ED_P
    return (
        (e_mul * f_mul) % _ED_P,
        (g_mul * h_mul) % _ED_P,
        (f_mul * g_mul) % _ED_P,
        (e_mul * h_mul) % _ED_P,
    )


def _ed_point_double(point: tuple) -> tuple:
    x1, y1, z1, _t1 = point
    a_mul = (x1 * x1) % _ED_P
    b_mul = (y1 * y1) % _ED_P
    c_mul = (2 * z1 * z1) % _ED_P
    h_mul = (a_mul + b_mul) % _ED_P
    e_mul = (h_mul - ((x1 + y1) * (x1 + y1) % _ED_P)) % _ED_P
    g_mul = (a_mul - b_mul) % _ED_P
    f_mul = (c_mul + g_mul) % _ED_P
    return (
        (e_mul * f_mul) % _ED_P,
        (g_mul * h_mul) % _ED_P,
        (f_mul * g_mul) % _ED_P,
        (e_mul * h_mul) % _ED_P,
    )


def _ed_point_mul(scalar: int, point: tuple) -> tuple:
    result = _ED_IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _ed_point_add(result, addend)
        addend = _ed_point_double(addend)
        scalar >>= 1
    return result


def _ed_point_equal(p_point: tuple, q_point: tuple) -> bool:
    if (p_point[0] * q_point[2] - q_point[0] * p_point[2]) % _ED_P != 0:
        return False
    return (p_point[1] * q_point[2] - q_point[1] * p_point[2]) % _ED_P == 0


def _ed_recover_x(y_value: int, sign: int) -> Optional[int]:
    if y_value >= _ED_P:
        return None
    x_squared = ((y_value * y_value - 1) * _ed_inv(_ED_D * y_value * y_value + 1)) % _ED_P
    if x_squared == 0:
        return 0 if sign == 0 else None
    x_value = pow(x_squared, (_ED_P + 3) // 8, _ED_P)
    if (x_value * x_value - x_squared) % _ED_P != 0:
        x_value = (x_value * _ED_SQRT_M1) % _ED_P
    if (x_value * x_value - x_squared) % _ED_P != 0:
        return None
    if (x_value & 1) != sign:
        x_value = _ED_P - x_value
    return x_value


def _ed_point_compress(point: tuple) -> bytes:
    zinv = _ed_inv(point[2])
    x_value = (point[0] * zinv) % _ED_P
    y_value = (point[1] * zinv) % _ED_P
    return int.to_bytes(y_value | ((x_value & 1) << 255), 32, "little")


def _ed_point_decompress(encoded: bytes) -> Optional[tuple]:
    if len(encoded) != 32:
        return None
    y_value = int.from_bytes(encoded, "little")
    sign = y_value >> 255
    y_value &= (1 << 255) - 1
    x_value = _ed_recover_x(y_value, sign)
    if x_value is None:
        return None
    return (x_value, y_value, 1, (x_value * y_value) % _ED_P)


def _ed_base_point() -> tuple:
    g_y = (4 * _ed_inv(5)) % _ED_P
    g_x = _ed_recover_x(g_y, 0)
    assert g_x is not None
    return (g_x, g_y, 1, (g_x * g_y) % _ED_P)


_ED_BASE = _ed_base_point()

# _ED_BASE_WINDOWS[i][j - 1] = j * 16^i * B, i in 0..63, j in 1..15.
_ED_BASE_WINDOWS: Optional[List[List[tuple]]] = None


def _ed_base_table() -> List[List[tuple]]:
    global _ED_BASE_WINDOWS
    if _ED_BASE_WINDOWS is None:
        windows: List[List[tuple]] = []
        factor = _ED_BASE
        for _ in range(64):
            multiples = []
            multiple = _ED_IDENTITY
            for _ in range(15):
                multiple = _ed_point_add(multiple, factor)
                multiples.append(multiple)
            windows.append(multiples)
            for _ in range(4):
                factor = _ed_point_double(factor)
        _ED_BASE_WINDOWS = windows
    return _ED_BASE_WINDOWS


def _ed_base_mul(scalar: int) -> tuple:
    scalar %= _ED_L
    table = _ed_base_table()
    result = _ED_IDENTITY
    index = 0
    while scalar > 0:
        digit = scalar & 15
        if digit:
            result = _ed_point_add(result, table[index][digit - 1])
        scalar >>= 4
        index += 1
    return result


def _ed_secret_expand(seed: bytes) -> Tuple[int, bytes]:
    if len(seed) != 32:
        raise SignatureError("Ed25519 seed must be exactly 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def ed25519_generate_seed() -> bytes:
    """Return 32 fresh random bytes from the operating system CSPRNG."""

    return os.urandom(32)


def ed25519_public_from_seed(seed: bytes) -> bytes:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise SignatureError("Ed25519 seed must be exactly 32 bytes")
    scalar, _prefix = _ed_secret_expand(bytes(seed))
    return _ed_point_compress(_ed_base_mul(scalar))


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise SignatureError("Ed25519 seed must be exactly 32 bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise SignatureError("message must be bytes")
    scalar, prefix = _ed_secret_expand(bytes(seed))
    public = _ed_point_compress(_ed_base_mul(scalar))
    r_value = int.from_bytes(hashlib.sha512(prefix + bytes(message)).digest(), "little") % _ED_L
    r_point = _ed_base_mul(r_value)
    r_encoded = _ed_point_compress(r_point)
    k_value = int.from_bytes(
        hashlib.sha512(r_encoded + public + bytes(message)).digest(), "little"
    ) % _ED_L
    s_value = (r_value + k_value * scalar) % _ED_L
    return r_encoded + int.to_bytes(s_value, 32, "little")


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> None:
    """Verify or raise SignatureError. Every malformed input is rejected."""

    if not isinstance(public, (bytes, bytearray)) or len(public) != 32:
        raise SignatureError("Ed25519 public key must be exactly 32 bytes")
    if not isinstance(message, (bytes, bytearray)):
        raise SignatureError("message must be bytes")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise SignatureError("Ed25519 signature must be exactly 64 bytes")
    a_point = _ed_point_decompress(bytes(public))
    if a_point is None:
        raise SignatureError("public key is not a valid curve point encoding")
    r_point = _ed_point_decompress(bytes(signature[:32]))
    if r_point is None:
        raise SignatureError("signature R is not a valid curve point encoding")
    s_value = int.from_bytes(signature[32:], "little")
    if s_value >= _ED_L:
        raise SignatureError("signature scalar S is out of range")
    k_value = int.from_bytes(
        hashlib.sha512(bytes(signature[:32]) + bytes(public) + bytes(message)).digest(), "little"
    ) % _ED_L
    # Cofactored check: [8]S*B == [8]R + [8]k*A.
    left = _ed_base_mul(8 * s_value)
    right = _ed_point_mul(8 * k_value, a_point)
    r8 = r_point
    for _ in range(3):
        r8 = _ed_point_double(r8)
    right = _ed_point_add(r8, right)
    if not _ed_point_equal(left, right):
        raise SignatureError("Ed25519 signature does not verify")


# ---------------------------------------------------------------------------
# Secret key containers, fingerprints, OpenSSH interop
# ---------------------------------------------------------------------------


def make_secret_container(seed: bytes) -> dict:
    """Build the on-disk secret container (kept only on air-gapped media)."""

    public = ed25519_public_from_seed(seed)
    return {
        "keytype": ED25519_KEYTYPE,
        "seed": bytes(seed).hex(),
        "public": public.hex(),
    }


def load_secret_container(
    container: dict, *, label: str = "secret key container"
) -> Tuple[bytes, bytes]:
    obj = require_object(container, label)
    exact_object(obj, ("keytype", "seed", "public"), label)
    if obj["keytype"] != ED25519_KEYTYPE:
        raise SignatureError("{} has unsupported keytype".format(label))
    seed_hex = require_hex(obj["seed"], "{}.seed".format(label), 32)
    public_hex = require_hex(obj["public"], "{}.public".format(label), 32)
    seed = bytes.fromhex(seed_hex)
    public = bytes.fromhex(public_hex)
    derived = ed25519_public_from_seed(seed)
    if derived != public:
        raise SignatureError("{} public key does not match its seed".format(label))
    return seed, public


def grouped_hex(value: str, group: int = 4) -> str:
    """Return hex grouped for human fingerprint comparison."""

    if group < 1:
        raise ValueError("group must be positive")
    return " ".join(value[index : index + group] for index in range(0, len(value), group))


def openssh_ed25519_blob(public: bytes) -> bytes:
    if len(public) != 32:
        raise SignatureError("Ed25519 public key must be exactly 32 bytes")

    def ssh_string(data: bytes) -> bytes:
        return len(data).to_bytes(4, "big") + data

    return ssh_string(b"ssh-ed25519") + ssh_string(bytes(public))


def openssh_ed25519_line(public: bytes, comment: str = "") -> str:
    encoded = base64.b64encode(openssh_ed25519_blob(public)).decode("ascii")
    if comment:
        if any(ch in comment for ch in "\r\n"):
            raise ValueError("SSH key comment must not contain newlines")
        return "ssh-ed25519 {} {}".format(encoded, comment)
    return "ssh-ed25519 {}".format(encoded)


def openssh_ed25519_fingerprint(public: bytes) -> str:
    digest = hashlib.sha256(openssh_ed25519_blob(public)).digest()
    return "SHA256:" + base64.b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Envelope signing and threshold verification
# ---------------------------------------------------------------------------


def sign_canonical_payload(seed: bytes, payload: bytes) -> Tuple[str, bytes]:
    public = ed25519_public_from_seed(seed)
    signature = ed25519_sign(seed, bytes(payload))
    return ed25519_key_id(public), signature


def seal_envelope(signed: dict, seeds: Sequence[bytes]) -> dict:
    """Sign a metadata document with one or more seeds and return envelope."""

    signatures = []
    for seed in seeds:
        signatures.append(sign_canonical_payload(seed, canonical_json_bytes(signed)))
    return make_envelope(signed, signatures)


def add_envelope_signature(envelope: dict, seed: bytes) -> dict:
    """Return a new envelope with an additional signer (threshold ceremonies)."""

    payload = signed_payload_bytes(envelope)
    keyid, signature = sign_canonical_payload(seed, payload)
    existing = envelope_signatures_by_key(envelope)
    if keyid in existing:
        raise SignatureError("key {} has already signed this document".format(keyid))
    pairs = [
        (entry["keyid"], bytes.fromhex(entry["sig"])) for entry in envelope["signatures"]
    ] + [(keyid, signature)]
    # make_envelope canonicalises signature ordering by keyid.
    return make_envelope(envelope["signed"], pairs)


def verify_role_envelope(envelope: dict, authorized_publics: dict, threshold: int) -> set:
    """Verify an envelope against a role's authorised keys.

    Returns the set of authorised keyids carrying valid signatures. Raises
    SignatureError when fewer than ``threshold`` distinct authorised keys
    validate. Signatures by keyids outside the role are ignored: a rotating
    root document legitimately carries self-signatures by not-yet-authorised
    successor keys in addition to the mandatory previous-root threshold.
    """

    if not isinstance(threshold, int) or threshold < 1:
        raise SignatureError("signature threshold must be a positive integer")
    payload = signed_payload_bytes(envelope)
    valid = set()
    for entry in envelope["signatures"]:
        keyid = entry["keyid"]
        public = authorized_publics.get(keyid)
        if public is None:
            continue
        try:
            ed25519_verify(public, payload, bytes.fromhex(entry["sig"]))
        except SignatureError:
            continue
        valid.add(keyid)
    if len(valid) < threshold:
        raise SignatureError(
            "role threshold not met: {} of {} required valid signature(s)".format(
                len(valid), threshold
            )
        )
    return valid


# ---------------------------------------------------------------------------
# Semantic version comparison (SemVer 2.0 subset used by release metadata)
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


def parse_semver(version: str, *, label: str = "version") -> Tuple[Tuple[int, int, int], Optional[tuple]]:
    text = require_str(version, label)
    match = _SEMVER_RE.match(text)
    if match is None:
        raise MetadataError("{} is not a semantic version: {!r}".format(label, text))
    core = (int(match.group(1)), int(match.group(2)), int(match.group(3)))
    prerelease = None
    if match.group(4) is not None:
        identifiers = []
        for piece in match.group(4).split("."):
            if piece.isdigit():
                if len(piece) > 1 and piece[0] == "0":
                    raise MetadataError("{} has a leading-zero prerelease number".format(label))
                identifiers.append((0, int(piece)))
            else:
                identifiers.append((1, piece))
        prerelease = tuple(identifiers)
    return core, prerelease


def compare_semver(left: str, right: str) -> int:
    left_core, left_pre = parse_semver(left)
    right_core, right_pre = parse_semver(right)
    if left_core < right_core:
        return -1
    if left_core > right_core:
        return 1
    if left_pre == right_pre:
        return 0
    if left_pre is None:
        return 1  # release beats prerelease
    if right_pre is None:
        return -1
    if left_pre < right_pre:
        return -1
    return 1


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# root metadata (FR-2)
# ---------------------------------------------------------------------------

ROOT_FIELDS = ("_type", "spec_version", "version", "expires", "roles", "keys", "rekor_keys")
KEY_FIELDS = ("keytype", "public")
ROLE_FIELDS = ("keyids", "threshold")
REKOR_KEY_FIELDS = ("keyid", "keytype", "public_pem")
REKOR_KEYTYPE = "ecdsa-p256"
REKOR_KEYID_PREFIX = "rekor:"


def make_root_signed(
    *,
    version: int,
    roles: dict,
    keys: dict,
    expires: str,
    rekor_keys: Optional[list] = None,
    spec_version: str = SPEC_VERSION,
) -> dict:
    signed = {
        "_type": ROOT_TYPE,
        "spec_version": spec_version,
        "version": version,
        "expires": expires,
        "roles": roles,
        "keys": keys,
        "rekor_keys": rekor_keys or [],
    }
    validate_root_signed(signed)
    return signed


def validate_root_signed(signed: Any) -> dict:
    obj = require_object(signed, ROOT_TYPE)
    exact_object(obj, ROOT_FIELDS, ROOT_TYPE)
    if obj["_type"] != ROOT_TYPE:
        raise MetadataError("document _type is not root")
    require_str(obj["spec_version"], "root.spec_version")
    require_int(obj["version"], "root.version", minimum=1)
    require_iso8601_utc(obj["expires"], "root.expires")

    roles = require_dict(obj["roles"], "root.roles")
    exact_object(roles, ROLES, "root.roles")
    keys = require_dict(obj["keys"], "root.keys")
    for role_name in ROLES:
        role = require_dict(roles[role_name], "root.roles.{}".format(role_name))
        exact_object(role, ROLE_FIELDS, "root.roles.{}".format(role_name))
        keyids = require_list(role["keyids"], "root.roles.{}.keyids".format(role_name))
        threshold = require_int(
            role["threshold"], "root.roles.{}.threshold".format(role_name), minimum=1
        )
        if not keyids:
            raise MetadataError("root role {} must name at least one key".format(role_name))
        if len(set(keyids)) != len(keyids):
            raise MetadataError("root role {} lists a keyid twice".format(role_name))
        if threshold > len(keyids):
            raise MetadataError("root role {} threshold exceeds its key count".format(role_name))
        for keyid in keyids:
            require_str(keyid, "root.roles.{}.keyids[]".format(role_name))
            if keyid not in keys:
                raise MetadataError(
                    "root role {} references unknown keyid {}".format(role_name, keyid)
                )
    referenced = {keyid for role_name in ROLES for keyid in roles[role_name]["keyids"]}
    for keyid, entry in keys.items():
        require_str(keyid, "root.keys keyid")
        key = require_dict(entry, "root.keys[{}]".format(keyid))
        exact_object(key, KEY_FIELDS, "root.keys[{}]".format(keyid))
        if key["keytype"] != ED25519_KEYTYPE:
            raise MetadataError("root key {} has unsupported keytype".format(keyid))
        public_hex = require_hex(key["public"], "root.keys[{}].public".format(keyid), 32)
        if keyid != key_id_for_hex_public(public_hex):
            raise MetadataError("root keyid {} does not match its public key".format(keyid))
        if not keyid.startswith(ED25519_KEYTYPE + ":"):
            raise MetadataError("root keyid {} has wrong type prefix".format(keyid))
    unreferenced = set(keys) - referenced
    if unreferenced:
        # Every registered key must be usable by at least one role; otherwise
        # stale material could linger in a root without review.
        raise MetadataError(
            "root registers unreferenced key(s): {}".format(", ".join(sorted(unreferenced)))
        )

    rekor_keys = require_list(obj["rekor_keys"], "root.rekor_keys")
    seen_rekor = set()
    for index, entry in enumerate(rekor_keys):
        label = "root.rekor_keys[{}]".format(index)
        rekor = require_dict(entry, label)
        exact_object(rekor, REKOR_KEY_FIELDS, label)
        keyid = require_str(rekor["keyid"], "{}.keyid".format(label))
        if not keyid.startswith(REKOR_KEYID_PREFIX):
            raise MetadataError("{}.keyid must start with rekor:".format(label))
        require_hex(keyid[len(REKOR_KEYID_PREFIX):], "{}.keyid".format(label), 32)
        if keyid in seen_rekor:
            raise MetadataError("{} duplicates a rekor keyid".format(label))
        seen_rekor.add(keyid)
        if rekor["keytype"] != REKOR_KEYTYPE:
            raise MetadataError("{}.keytype must be ecdsa-p256".format(label))
        pem = require_str(rekor["public_pem"], "{}.public_pem".format(label))
        if "BEGIN PUBLIC KEY" not in pem or "END PUBLIC KEY" not in pem:
            raise MetadataError("{}.public_pem must be an X.509 SubjectPublicKeyInfo PEM".format(label))
    return obj


def role_publics(root_signed: dict, role_name: str) -> dict:
    if role_name not in ROLES:
        raise SignatureError("unknown trust role: {}".format(role_name))
    keys = root_signed["keys"]
    return {
        keyid: bytes.fromhex(keys[keyid]["public"])
        for keyid in root_signed["roles"][role_name]["keyids"]
    }


def role_threshold(root_signed: dict, role_name: str) -> int:
    return root_signed["roles"][role_name]["threshold"]


def verify_root_document(envelope: dict, previous_signed: Optional[dict]) -> dict:
    """Validate root schema and the TUF root-rotation signature rule.

    With no previous root this is v1 self-signing bootstrapped material; with
    a previous root the candidate must be exactly one version newer and carry
    the previous root role threshold. Additional self-signatures by successor
    keys are permitted (they simply do not count under the old role table).
    """

    signed = require_object(envelope.get("signed"), "root envelope.signed")
    validate_root_signed(signed)
    if previous_signed is None:
        if signed["version"] != 1:
            raise SignatureError("the first root document must be version 1")
        verify_role_envelope(envelope, role_publics(signed, ROLE_ROOT), role_threshold(signed, ROLE_ROOT))
        return signed
    require_int(previous_signed.get("version"), "previous root.version", minimum=1)
    expected = previous_signed["version"] + 1
    if signed["version"] != expected:
        raise SignatureError(
            "root rotation must advance version from {} to {}, got {}".format(
                previous_signed["version"], expected, signed["version"]
            )
        )
    verify_role_envelope(
        envelope, role_publics(previous_signed, ROLE_ROOT),
        role_threshold(previous_signed, ROLE_ROOT),
    )
    return signed


def ensure_root_not_rolled_back(candidate_version: int, current_version: Optional[int]) -> None:
    if current_version is not None and candidate_version < current_version:
        raise SignatureError(
            "root metadata rollback refused: version {} is below pinned {}".format(
                candidate_version, current_version
            )
        )


def root_fingerprint(signed: dict) -> str:
    """Convenience fingerprint over the canonical root signed document."""

    return canonical_sha256(signed)


# ---------------------------------------------------------------------------
# release manifest (FR-3) and release index (FR-5)
# ---------------------------------------------------------------------------

MANIFEST_FIELDS = (
    "_type",
    "spec_version",
    "product",
    "release_line",
    "version",
    "tag",
    "sequence",
    "issued_at",
    "source",
    "builder",
    "artifacts",
    "sboms",
    "required_root_version",
    "required_revocations_version",
)
SOURCE_FIELDS = ("repo", "commit", "tag_object")
BUILDER_FIELDS = (
    "workflow_name",
    "workflow_ref",
    "workflow_sha",
    "runner",
    "python_version",
    "node_version",
    "rust_version",
    "pyinstaller_version",
    "build_manifests",
)
ARTIFACT_RECORD_FIELDS = ("sha256", "size")


def expected_tag_for(line: str, version: str) -> str:
    if line == STABLE_LINE:
        return "v" + version
    if line == DESKTOP_BETA_LINE:
        return "desktop-v" + version
    raise MetadataError("unknown release line: {!r}".format(line))


def _validate_artifact_map(value: Any, label: str, *, allow_empty: bool) -> dict:
    mapping = require_dict(value, label)
    if not allow_empty and not mapping:
        raise MetadataError("{} must list at least one file".format(label))
    for name, record in mapping.items():
        validate_asset_name(name, label + " name")
        entry = require_dict(record, "{}.{}".format(label, name))
        exact_object(entry, ARTIFACT_RECORD_FIELDS, "{}.{}".format(label, name))
        require_hex(entry["sha256"], "{}.{}.sha256".format(label, name), 32)
        require_int(entry["size"], "{}.{}.size".format(label, name), minimum=0)
    return mapping


def validate_release_manifest(signed: Any) -> dict:
    obj = require_object(signed, RELEASE_TYPE)
    exact_object(obj, MANIFEST_FIELDS, RELEASE_TYPE)
    if obj["_type"] != RELEASE_TYPE:
        raise MetadataError("document _type is not release")
    require_str(obj["spec_version"], "release.spec_version")
    if obj["product"] != PRODUCT:
        raise MetadataError("release product is not {!r}".format(PRODUCT))
    line = require_str(obj["release_line"], "release.release_line")
    if line not in RELEASE_LINES:
        raise MetadataError("release.release_line must be one of {}".format(RELEASE_LINES))
    parse_semver(obj["version"], label="release.version")
    tag = require_str(obj["tag"], "release.tag")
    if tag != expected_tag_for(line, obj["version"]):
        raise MetadataError(
            "release.tag {!r} does not match line/version (expected {!r})".format(
                tag, expected_tag_for(line, obj["version"])
            )
        )
    require_int(obj["sequence"], "release.sequence", minimum=1)
    require_iso8601_utc(obj["issued_at"], "release.issued_at")
    require_int(obj["required_root_version"], "release.required_root_version", minimum=1)
    require_int(
        obj["required_revocations_version"],
        "release.required_revocations_version",
        minimum=0,
    )

    source = require_dict(obj["source"], "release.source")
    exact_object(source, SOURCE_FIELDS, "release.source")
    require_str(source["repo"], "release.source.repo")
    commit = require_str(source["commit"], "release.source.commit")
    if len(commit) not in (40, 64) or any(c not in "0123456789abcdef" for c in commit):
        raise MetadataError("release.source.commit must be 40 or 64 lowercase hex chars")
    require_hex(source["tag_object"], "release.source.tag_object", 20)

    builder = require_dict(obj["builder"], "release.builder")
    exact_object(builder, BUILDER_FIELDS, "release.builder")
    for field in ("workflow_name", "workflow_ref", "workflow_sha", "runner", "python_version"):
        require_str(builder[field], "release.builder.{}".format(field))
    require_hex(builder["workflow_sha"], "release.builder.workflow_sha")
    if len(builder["workflow_sha"]) not in (40, 64):
        raise MetadataError("release.builder.workflow_sha must be 40 or 64 hex chars")
    for field in ("node_version", "rust_version", "pyinstaller_version"):
        if not isinstance(builder[field], str):
            raise MetadataError("release.builder.{} must be a string".format(field))
    build_manifests = require_dict(
        builder["build_manifests"], "release.builder.build_manifests"
    )
    if line == DESKTOP_BETA_LINE and not build_manifests:
        raise MetadataError("desktop-beta releases must bind platform build manifests")
    for name, digest in build_manifests.items():
        validate_asset_name(name, "build manifest name")
        require_hex(digest, "release.builder.build_manifests.{}".format(name), 32)

    _validate_artifact_map(obj["artifacts"], "release.artifacts", allow_empty=False)
    sboms = _validate_artifact_map(obj["sboms"], "release.sboms", allow_empty=False)
    if len(sboms) != 2:
        raise MetadataError("release.sboms must bind exactly two SBOM documents (SPDX + CDX)")
    return obj


INDEX_FIELDS = ("_type", "spec_version", "version", "issued_at", "lines")
INDEX_ENTRY_FIELDS = ("version", "sequence", "manifest_hash", "rekor_uuid", "log_index")


def empty_release_index(version: int, issued_at: str, *, spec_version: str = SPEC_VERSION) -> dict:
    index = {
        "_type": RELEASE_INDEX_TYPE,
        "spec_version": spec_version,
        "version": version,
        "issued_at": issued_at,
        "lines": {line: [] for line in RELEASE_LINES},
    }
    validate_release_index(index)
    return index


def validate_release_index(signed: Any) -> dict:
    obj = require_object(signed, RELEASE_INDEX_TYPE)
    exact_object(obj, INDEX_FIELDS, RELEASE_INDEX_TYPE)
    if obj["_type"] != RELEASE_INDEX_TYPE:
        raise MetadataError("document _type is not release-index")
    require_str(obj["spec_version"], "release-index.spec_version")
    require_int(obj["version"], "release-index.version", minimum=1)
    require_iso8601_utc(obj["issued_at"], "release-index.issued_at")
    lines = require_dict(obj["lines"], "release-index.lines")
    exact_object(lines, RELEASE_LINES, "release-index.lines")
    for line in RELEASE_LINES:
        entries = require_list(lines[line], "release-index.lines.{}".format(line))
        seen_versions = set()
        seen_hashes = set()
        expected_sequence = 1
        for index, entry in enumerate(entries):
            label = "release-index.lines.{}[{}]".format(line, index)
            item = require_dict(entry, label)
            exact_object(item, INDEX_ENTRY_FIELDS, label)
            parse_semver(item["version"], label=label + ".version")
            require_int(item["sequence"], label + ".sequence", minimum=1)
            if item["sequence"] != expected_sequence:
                raise MetadataError(
                    "{}: sequence must be contiguous (expected {}, got {})".format(
                        label, expected_sequence, item["sequence"]
                    )
                )
            expected_sequence += 1
            require_hex(item["manifest_hash"], label + ".manifest_hash", 32)
            if item["version"] in seen_versions:
                raise MetadataError("{}: version {} listed twice".format(label, item["version"]))
            if item["manifest_hash"] in seen_hashes:
                raise MetadataError("{}: manifest hash listed twice".format(label))
            seen_versions.add(item["version"])
            seen_hashes.add(item["manifest_hash"])
            uuid_value = item["rekor_uuid"]
            log_index = item["log_index"]
            if uuid_value is not None:
                require_str(uuid_value, label + ".rekor_uuid")
                if not isinstance(log_index, int) or isinstance(log_index, bool) or log_index < 0:
                    raise MetadataError(
                        "{}: log_index must accompany rekor_uuid as a non-negative int".format(label)
                    )
            elif log_index is not None:
                raise MetadataError("{}: log_index present without rekor_uuid".format(label))
    return obj


def index_entry_for(index_signed: dict, line: str, version: str) -> Optional[dict]:
    if line not in RELEASE_LINES:
        raise MetadataError("unknown release line: {!r}".format(line))
    for entry in index_signed["lines"][line]:
        if entry["version"] == version:
            return entry
    return None


def index_entry_for_sequence(index_signed: dict, line: str, sequence: int) -> Optional[dict]:
    if line not in RELEASE_LINES:
        raise MetadataError("unknown release line: {!r}".format(line))
    for entry in index_signed["lines"][line]:
        if entry["sequence"] == sequence:
            return entry
    return None


def last_sequence(index_signed: dict, line: str) -> int:
    entries = index_signed["lines"][line]
    return entries[-1]["sequence"] if entries else 0


def append_index_entry(
    old_index: Optional[dict],
    manifest_envelope: dict,
    *,
    issued_at: str,
    rekor_uuid: Optional[str] = None,
    log_index: Optional[int] = None,
) -> dict:
    """Return a new validated index containing one more manifest."""

    manifest = require_object(manifest_envelope.get("signed"), "manifest envelope.signed")
    validate_release_manifest(manifest)
    line = manifest["release_line"]
    manifest_hash = canonical_sha256(manifest)
    if old_index is None:
        new_index = empty_release_index(1, issued_at)
    else:
        validate_release_index(old_index)
        new_index = json.loads(json.dumps(old_index))
        new_index["version"] = old_index["version"] + 1
        new_index["issued_at"] = issued_at
    entries = new_index["lines"][line]
    expected_sequence = len(entries) + 1
    if manifest["sequence"] != expected_sequence:
        raise MetadataError(
            "{}: next sequence must be {}, manifest declares {}".format(
                line, expected_sequence, manifest["sequence"]
            )
        )
    if any(entry["version"] == manifest["version"] for entry in entries):
        raise MetadataError("{}: version {} is already indexed".format(line, manifest["version"]))
    if any(entry["manifest_hash"] == manifest_hash for entry in entries):
        raise MetadataError("{}: identical manifest is already indexed".format(line))
    entries.append(
        {
            "version": manifest["version"],
            "sequence": manifest["sequence"],
            "manifest_hash": manifest_hash,
            "rekor_uuid": rekor_uuid,
            "log_index": log_index,
        }
    )
    return validate_release_index(new_index)


def ensure_index_extends(new_signed: dict, old_signed: dict) -> None:
    """Reject a newer release-index that rewrites or drops pinned history.

    Release indexes are append-only channel anchors: every entry already
    pinned locally must appear verbatim (same position, same fields) in a
    newer document. A version bump alone is not evidence of freshness.
    """

    new = validate_release_index(new_signed)
    old = validate_release_index(old_signed)
    if new["version"] <= old["version"]:
        raise MetadataError(
            "release-index version must advance beyond pinned v{}, got v{}".format(
                old["version"], new["version"]
            )
        )
    for line in RELEASE_LINES:
        old_entries = old["lines"][line]
        new_entries = new["lines"][line]
        if len(new_entries) < len(old_entries):
            raise SignatureError(
                "new release-index v{} drops pinned entr(y/ies) on line {}".format(
                    new["version"], line
                )
            )
        for position, old_entry in enumerate(old_entries):
            if new_entries[position] != old_entry:
                raise SignatureError(
                    "new release-index rewrites pinned history on line {} at sequence {}".format(
                        line, old_entry["sequence"]
                    )
                )


def verify_index_against_manifest(index_signed: dict, manifest_envelope: dict) -> dict:
    """Assert the index pins exactly this manifest on its line; return entry."""

    manifest = require_object(manifest_envelope.get("signed"), "manifest envelope.signed")
    validate_release_manifest(manifest)
    entry = index_entry_for(index_signed, manifest["release_line"], manifest["version"])
    if entry is None:
        raise MetadataError(
            "release-index has no entry for {} {}".format(
                manifest["release_line"], manifest["version"]
            )
        )
    if entry["sequence"] != manifest["sequence"]:
        raise MetadataError(
            "release-index sequence {} disagrees with manifest sequence {}".format(
                entry["sequence"], manifest["sequence"]
            )
        )
    manifest_hash = canonical_sha256(manifest)
    if entry["manifest_hash"] != manifest_hash:
        raise DigestError(
            "release-index pins {} but the manifest canonical hash is {}".format(
                entry["manifest_hash"], manifest_hash
            )
        )
    return entry


def verify_index_signature(index_envelope: dict, root_signed: dict) -> set:
    validate_release_index(require_object(index_envelope.get("signed"), "index envelope"))
    return verify_role_envelope(
        index_envelope, role_publics(root_signed, ROLE_RELEASE),
        role_threshold(root_signed, ROLE_RELEASE),
    )


# ---------------------------------------------------------------------------
# revocations (FR-6)
# ---------------------------------------------------------------------------

REVOCATIONS_FIELDS = (
    "_type",
    "spec_version",
    "version",
    "issued_at",
    "expires",
    "revoked_keys",
    "revoked_releases",
    "revoked_artifacts",
)
REVOKED_KEY_FIELDS = ("keyid", "reason", "revoked_at")
REVOKED_RELEASE_FIELDS = (
    "release_line",
    "version",
    "to_version",
    "severity",
    "reason",
    "fixed_version",
    "security_exception_allowed",
    "revoked_at",
)
REVOKED_ARTIFACT_FIELDS = ("sha256", "reason", "revoked_at")
REVOCATION_SEVERITIES = ("critical", "high", "medium", "low")


def _validate_timestamp(value: Any, label: str) -> str:
    return require_iso8601_utc(value, label)


def validate_revocations(signed: Any) -> dict:
    obj = require_object(signed, REVOCATIONS_TYPE)
    exact_object(obj, REVOCATIONS_FIELDS, REVOCATIONS_TYPE)
    if obj["_type"] != REVOCATIONS_TYPE:
        raise MetadataError("document _type is not revocations")
    require_str(obj["spec_version"], "revocations.spec_version")
    require_int(obj["version"], "revocations.version", minimum=1)
    _validate_timestamp(obj["issued_at"], "revocations.issued_at")
    _validate_timestamp(obj["expires"], "revocations.expires")

    keys = require_list(obj["revoked_keys"], "revocations.revoked_keys")
    seen = set()
    for index, entry in enumerate(keys):
        label = "revocations.revoked_keys[{}]".format(index)
        item = require_dict(entry, label)
        exact_object(item, REVOKED_KEY_FIELDS, label)
        require_str(item["keyid"], label + ".keyid")
        require_str(item["reason"], label + ".reason")
        _validate_timestamp(item["revoked_at"], label + ".revoked_at")
        if item["keyid"] in seen:
            raise MetadataError("{}: keyid revoked twice".format(label))
        seen.add(item["keyid"])

    artifacts = require_list(obj["revoked_artifacts"], "revocations.revoked_artifacts")
    seen_artifacts = set()
    for index, entry in enumerate(artifacts):
        label = "revocations.revoked_artifacts[{}]".format(index)
        item = require_dict(entry, label)
        exact_object(item, REVOKED_ARTIFACT_FIELDS, label)
        require_hex(item["sha256"], label + ".sha256", 32)
        require_str(item["reason"], label + ".reason")
        _validate_timestamp(item["revoked_at"], label + ".revoked_at")
        if item["sha256"] in seen_artifacts:
            raise MetadataError("{}: artifact revoked twice".format(label))
        seen_artifacts.add(item["sha256"])

    releases = require_list(obj["revoked_releases"], "revocations.revoked_releases")
    intervals = {line: [] for line in RELEASE_LINES}
    for index, entry in enumerate(releases):
        label = "revocations.revoked_releases[{}]".format(index)
        item = require_dict(entry, label)
        exact_object(item, REVOKED_RELEASE_FIELDS, label)
        line = require_str(item["release_line"], label + ".release_line")
        if line not in RELEASE_LINES:
            raise MetadataError("{}: unknown release line".format(label))
        low = item["version"]
        parse_semver(low, label=label + ".version")
        high = item["to_version"]
        if high is not None:
            parse_semver(high, label=label + ".to_version")
            if compare_semver(high, low) < 0:
                raise MetadataError("{}: to_version is below version".format(label))
        if item["severity"] not in REVOCATION_SEVERITIES:
            raise MetadataError("{}: severity must be one of {}".format(label, REVOCATION_SEVERITIES))
        require_str(item["reason"], label + ".reason")
        fixed = item["fixed_version"]
        if fixed is not None:
            parse_semver(fixed, label=label + ".fixed_version")
        if not isinstance(item["security_exception_allowed"], bool):
            raise MetadataError("{}: security_exception_allowed must be boolean".format(label))
        _validate_timestamp(item["revoked_at"], label + ".revoked_at")
        intervals[line].append((low, high or low))
    for line, ranges in intervals.items():
        ordered = sorted(ranges, key=lambda pair: parse_semver(pair[0])[0])
        for previous, current in zip(ordered, ordered[1:]):
            if compare_semver(previous[1], current[0]) >= 0:
                raise MetadataError(
                    "revocations on {} contain overlapping ranges {}..{} and {}..{}".format(
                        line, previous[0], previous[1], current[0], current[1]
                    )
                )
    return obj


def revoked_key_entry(revocations_signed: dict, keyid: str) -> Optional[dict]:
    for entry in revocations_signed["revoked_keys"]:
        if entry["keyid"] == keyid:
            return entry
    return None


def revoked_artifact_entry(revocations_signed: dict, artifact_sha256: str) -> Optional[dict]:
    for entry in revocations_signed["revoked_artifacts"]:
        if entry["sha256"] == artifact_sha256:
            return entry
    return None


def revoked_release_entry(revocations_signed: dict, line: str, version: str) -> Optional[dict]:
    if line not in RELEASE_LINES:
        raise MetadataError("unknown release line: {!r}".format(line))
    for entry in revocations_signed["revoked_releases"]:
        if entry["release_line"] != line:
            continue
        high = entry["to_version"] or entry["version"]
        if compare_semver(entry["version"], version) <= 0 <= compare_semver(high, version):
            return entry
    return None


def revocations_is_expired(revocations_signed: dict, now_iso: str) -> bool:
    """Return True when the document expiry timestamp has passed (UTC compare)."""

    expires = revocations_signed["expires"].replace("Z", "+00:00")
    now_text = now_iso.replace("Z", "+00:00")
    expires_dt = datetime.fromisoformat(expires)
    now_dt = datetime.fromisoformat(now_text)
    if expires_dt.tzinfo is None or now_dt.tzinfo is None:
        raise MetadataError("revocation timestamps must carry UTC timezone")
    return now_dt > expires_dt


def _release_identity(entry: dict) -> tuple:
    return (
        entry["release_line"],
        entry["version"],
        entry["to_version"],
        entry["severity"],
        entry["reason"],
        entry["fixed_version"],
        entry["security_exception_allowed"],
    )


def ensure_revocations_cumulative(new_signed: dict, old_signed: Optional[dict]) -> None:
    """Reject a new revocation document that silently drops live revocations.

    When the previous document is still within its validity window, every
    historical entry must be reproduced. Expiry never *removes* a revocation
    by itself, but once the previous copy has expired it may be refreshed
    without the full superset (the caller reports that situation).
    """

    if old_signed is None:
        if new_signed["version"] != 1:
            raise SignatureError("the first revocations document must be version 1")
        return
    if new_signed["version"] != old_signed["version"] + 1:
        raise SignatureError(
            "revocations version must advance from {} to {}, got {}".format(
                old_signed["version"], old_signed["version"] + 1, new_signed["version"]
            )
        )
    new_keys = {entry["keyid"] for entry in new_signed["revoked_keys"]}
    for entry in old_signed["revoked_keys"]:
        if entry["keyid"] not in new_keys:
            raise RevocationError(
                "new revocations drop still-live revoked key {}".format(entry["keyid"])
            )
    new_artifacts = {entry["sha256"] for entry in new_signed["revoked_artifacts"]}
    for entry in old_signed["revoked_artifacts"]:
        if entry["sha256"] not in new_artifacts:
            raise RevocationError(
                "new revocations drop still-live revoked artifact {}".format(entry["sha256"])
            )
    new_releases = {_release_identity(entry) for entry in new_signed["revoked_releases"]}
    for entry in old_signed["revoked_releases"]:
        identity = _release_identity(entry)
        if identity not in new_releases:
            raise RevocationError(
                "new revocations drop revoked release {} on line {}".format(
                    entry["version"], entry["release_line"]
                )
            )


def verify_revocations_signature(envelope: dict, root_signed: dict) -> dict:
    signed = require_object(envelope.get("signed"), "revocations envelope")
    validate_revocations(signed)
    verify_role_envelope(
        envelope, role_publics(root_signed, ROLE_REVOCATION),
        role_threshold(root_signed, ROLE_REVOCATION),
    )
    return signed


# ---------------------------------------------------------------------------
# Local trust state store (FR-7, FR-9 / AC-6, AC-12, AC-14)
#
# The state directory holds cached signed metadata (root/revocations/
# release-index envelopes), one strict state.json water-mark document and an
# append-only audit.jsonl. All judgment helpers are pure functions; the IO
# wrappers persist their results with the atomic primitives above.
# ---------------------------------------------------------------------------

STATE_FILENAME = "state.json"
AUDIT_FILENAME = "audit.jsonl"
STATE_SCHEMA_VERSION_VALUE = 1

_CACHED_DOCUMENT_FILES = {
    ROOT_TYPE: "root.json",
    REVOCATIONS_TYPE: "revocations.json",
    RELEASE_INDEX_TYPE: "release-index.json",
}

STATE_TOP_FIELDS = ("schema_version", "lines")
LINE_STATE_FIELDS = ("accepted", "rekor_tree_size", "security_exceptions")
ACCEPTED_RECORD_FIELDS = ("version", "sequence", "manifest_hash", "accepted_at")
SECURITY_EXCEPTION_FIELDS = ("version", "manifest_hash", "reason", "granted_at")

ACTION_TOFU = "tofu"
ACTION_UPGRADE = "upgrade"
ACTION_REINSTALL = "reinstall"
ACTION_DOWNGRADE_OVERRIDE = "downgrade-override"
ACTION_SECURITY_EXCEPTION = "security-exception"
ACTION_DOWNGRADE_SECURITY_EXCEPTION = "downgrade-security-exception"


def trust_state_path(trust_dir: Path) -> Path:
    return Path(trust_dir) / STATE_FILENAME


def trust_audit_path(trust_dir: Path) -> Path:
    return Path(trust_dir) / AUDIT_FILENAME


def ensure_trust_layout(trust_dir: Path) -> Path:
    target = Path(trust_dir)
    reject_symlink_ancestors(target)
    return ensure_private_directory(target)


def empty_state() -> dict:
    return {
        "schema_version": STATE_SCHEMA_VERSION_VALUE,
        "lines": {
            line: {"accepted": None, "rekor_tree_size": 0, "security_exceptions": []}
            for line in RELEASE_LINES
        },
    }


def _validate_accepted_record(value: Any, label: str) -> dict:
    record = require_dict(value, label)
    exact_object(record, ACCEPTED_RECORD_FIELDS, label)
    parse_semver(record["version"], label=label + ".version")
    require_int(record["sequence"], label + ".sequence", minimum=1)
    require_hex(record["manifest_hash"], label + ".manifest_hash", 32)
    require_iso8601_utc(record["accepted_at"], label + ".accepted_at")
    return record


def validate_state(value: Any) -> dict:
    """Strict state-document validation; every defect is a StateError.

    State files are local tamper/breakage surface, so structural metadata
    errors are normalised onto StateError: callers only need one fail-closed
    branch with an actionable message.
    """

    try:
        return _validate_state(value)
    except MetadataError as exc:
        raise StateError(str(exc)) from exc


def _validate_state(value: Any) -> dict:
    obj = require_object(value, "trust state")
    exact_object(obj, STATE_TOP_FIELDS, "trust state")
    if obj["schema_version"] != STATE_SCHEMA_VERSION_VALUE:
        raise StateError(
            "trust state schema_version is {}, expected {}".format(
                obj["schema_version"], STATE_SCHEMA_VERSION_VALUE
            )
        )
    lines = require_dict(obj["lines"], "trust state.lines")
    exact_object(lines, RELEASE_LINES, "trust state.lines")
    for line in RELEASE_LINES:
        label = "trust state.lines.{}".format(line)
        line_state = require_dict(lines[line], label)
        exact_object(line_state, LINE_STATE_FIELDS, label)
        accepted = line_state["accepted"]
        if accepted is not None:
            _validate_accepted_record(accepted, label + ".accepted")
        require_int(line_state["rekor_tree_size"], label + ".rekor_tree_size", minimum=0)
        exceptions = require_list(line_state["security_exceptions"], label + ".security_exceptions")
        seen = set()
        for index, entry in enumerate(exceptions):
            entry_label = "{}.security_exceptions[{}]".format(label, index)
            item = require_dict(entry, entry_label)
            exact_object(item, SECURITY_EXCEPTION_FIELDS, entry_label)
            parse_semver(item["version"], label=entry_label + ".version")
            require_hex(item["manifest_hash"], entry_label + ".manifest_hash", 32)
            require_str(item["reason"], entry_label + ".reason")
            require_iso8601_utc(item["granted_at"], entry_label + ".granted_at")
            identity = (item["version"], item["manifest_hash"])
            if identity in seen:
                raise StateError("{} lists the same security exception twice".format(entry_label))
            seen.add(identity)
    return obj


def load_state(trust_dir: Path) -> dict:
    """Return validated state; a missing state document means a fresh TOFU."""

    path = trust_state_path(trust_dir)
    if not path.exists():
        return empty_state()
    data = read_regular_file(path)
    try:
        parsed = parse_json_document(data, "trust state")
        return validate_state(parsed)
    except MetadataError as exc:
        raise StateError("trust state at {} is unusable: {}".format(path, exc)) from exc


def save_state(trust_dir: Path, state: dict) -> None:
    validate_state(state)
    ensure_trust_layout(trust_dir)
    atomic_write(
        trust_state_path(trust_dir),
        canonical_json_bytes(state),
    )


def write_cached_envelope(trust_dir: Path, kind: str, envelope: dict) -> None:
    if kind not in _CACHED_DOCUMENT_FILES:
        raise StateError("unknown cached metadata kind: {!r}".format(kind))
    # load_envelope performs the full structural envelope validation.
    load_envelope(canonical_json_bytes(envelope), "cached {}".format(kind))
    ensure_trust_layout(trust_dir)
    atomic_write(Path(trust_dir) / _CACHED_DOCUMENT_FILES[kind], canonical_json_bytes(envelope))


def read_cached_envelope(trust_dir: Path, kind: str) -> Optional[dict]:
    if kind not in _CACHED_DOCUMENT_FILES:
        raise StateError("unknown cached metadata kind: {!r}".format(kind))
    path = Path(trust_dir) / _CACHED_DOCUMENT_FILES[kind]
    if not path.exists():
        return None
    envelope = load_envelope(read_regular_file(path), "cached {}".format(kind))
    signed = envelope["signed"]
    if signed.get("_type") != kind:
        raise MetadataError("cached {} envelope has _type {!r}".format(kind, signed.get("_type")))
    return envelope


ROOT_HISTORY_PREFIX = "root.v"
ROOT_HISTORY_SUFFIX = ".json"


def root_history_path(trust_dir: Path, version: int) -> Path:
    return Path(trust_dir) / "{}{}{}".format(
        ROOT_HISTORY_PREFIX, version, ROOT_HISTORY_SUFFIX
    )


def write_root_history(trust_dir: Path, envelope: dict) -> None:
    """Archive an accepted root envelope under its immutable version name.

    Retained roots let verifiers validate manifests signed under previous
    root roles after a rotation, without accepting a rolled-back root feed.
    """

    load_envelope(canonical_json_bytes(envelope), "cached root")
    signed = envelope["signed"]
    if signed.get("_type") != ROOT_TYPE:
        raise StateError("root history envelope has _type {!r}".format(signed.get("_type")))
    version = signed.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise StateError("root history envelope carries an invalid version")
    ensure_trust_layout(trust_dir)
    atomic_write(root_history_path(trust_dir, version), canonical_json_bytes(envelope))


def read_root_history(trust_dir: Path, version: int) -> Optional[dict]:
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise StateError("root history version must be a positive int")
    path = root_history_path(trust_dir, version)
    if not path.exists():
        return None
    envelope = load_envelope(read_regular_file(path), "cached root history")
    signed = envelope["signed"]
    if signed.get("_type") != ROOT_TYPE or signed.get("version") != version:
        raise MetadataError("root history file {} has a mismatched identity".format(path.name))
    return envelope


def accepted_manifest_path(trust_dir: Path, manifest_hash: str) -> Path:
    """Content-addressed location of an accepted release manifest envelope."""

    require_hex(manifest_hash, "accepted manifest hash", 32)
    return Path(trust_dir) / MANIFESTS_DIRNAME / "{}.json".format(manifest_hash)


def write_accepted_manifest(trust_dir: Path, manifest_envelope: dict) -> Path:
    """Persist a verified release manifest envelope under its canonical hash.

    Local standalone tools (the distributed codex-instruct single file) use
    the cached document to self-check their own bytes against the accepted
    artifact record without re-running signature verification: the trust
    state's accepted manifest_hash pins the document, and the file name pins
    the same hash.
    """

    load_envelope(canonical_json_bytes(manifest_envelope), "accepted release manifest")
    signed = manifest_envelope["signed"]
    if signed.get("_type") != RELEASE_TYPE:
        raise StateError(
            "accepted manifest envelope has _type {!r}".format(signed.get("_type"))
        )
    manifest_hash = canonical_sha256(signed)
    path = accepted_manifest_path(trust_dir, manifest_hash)
    ensure_trust_layout(trust_dir)
    atomic_write(path, canonical_json_bytes(manifest_envelope))
    return path


def read_accepted_manifest(trust_dir: Path, manifest_hash: str) -> Optional[dict]:
    """Return the cached accepted manifest envelope, or None when absent."""

    path = accepted_manifest_path(trust_dir, manifest_hash)
    if not path.exists():
        return None
    envelope = load_envelope(read_regular_file(path), "accepted release manifest")
    signed = envelope["signed"]
    if signed.get("_type") != RELEASE_TYPE:
        raise MetadataError(
            "cached accepted manifest has _type {!r}".format(signed.get("_type"))
        )
    if canonical_sha256(signed) != manifest_hash:
        raise MetadataError(
            "cached accepted manifest {} does not hash to its file name".format(path.name)
        )
    return envelope


def find_security_exception(
    state: dict, line: str, version: str, manifest_hash: str
) -> Optional[dict]:
    for entry in state["lines"][line]["security_exceptions"]:
        if entry["version"] == version and entry["manifest_hash"] == manifest_hash:
            return entry
    return None


def _require_reason(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RevocationError("{} requires a non-empty written reason".format(label))
    return value.strip()


def evaluate_acceptance(
    state: dict,
    manifest: dict,
    *,
    now_iso: str,
    allow_downgrade: Optional[str] = None,
    downgrade_reason: Optional[str] = None,
    revoked_entry: Optional[dict] = None,
    accept_revoked: Optional[str] = None,
    revoked_reason: Optional[str] = None,
) -> dict:
    """Decide whether accepting this manifest violates any water-mark rule.

    Returns a pure decision record. Raises DowngradeError/RevocationError on
    a denied acceptance; callers persist the decision with commit_acceptance
    and audit it with decision_audit_entry.
    """

    validate_state(state)
    validate_release_manifest(manifest)
    line = manifest["release_line"]
    version = manifest["version"]
    sequence = manifest["sequence"]
    manifest_hash = canonical_sha256(manifest)
    line_state = state["lines"][line]
    prior = line_state["accepted"]

    exception_granted = False
    exception_previous = False
    if revoked_entry is not None:
        if not isinstance(revoked_entry, dict) or not isinstance(
            revoked_entry.get("security_exception_allowed"), bool
        ):
            raise RevocationError("internal error: malformed revocation record supplied")
        if not revoked_entry["security_exception_allowed"]:
            fixed = revoked_entry.get("fixed_version")
            raise RevocationError(
                "{} {} is revoked ({}); no security exception is permitted; upgrade to {}".format(
                    line, version, revoked_entry.get("reason", "unspecified"), fixed or "a fixed release"
                )
            )
        if accept_revoked != version:
            raise RevocationError(
                "revoked release {} requires an explicit --accept-revoked {}".format(version, version)
            )
        _require_reason(revoked_reason, "accepting revoked release {}".format(version))
        exception_granted = True
        if find_security_exception(state, line, version, manifest_hash) is not None:
            exception_previous = True

    downgrade_requested = False
    if prior is None:
        action = ACTION_TOFU
    else:
        prior_version = prior["version"]
        prior_sequence = prior["sequence"]
        version_order = compare_semver(version, prior_version)
        if version_order == 0:
            if sequence != prior_sequence:
                raise DowngradeError(
                    "manifest sequence {} disagrees with previously accepted sequence {} "
                    "for {}".format(sequence, prior_sequence, version)
                )
            if prior["manifest_hash"] != manifest_hash:
                raise StateError(
                    "{} was already accepted with a different manifest hash; refusing an "
                    "unindexed replacement of {}".format(version, version)
                )
            action = ACTION_REINSTALL
        elif sequence < prior_sequence or (sequence > prior_sequence and version_order < 0):
            downgrade_requested = True
            action = ACTION_DOWNGRADE_OVERRIDE
        elif sequence <= prior_sequence:
            # A newer version arriving on a stale/older sequence is an
            # inconsistency that downgrade overrides must not paper over.
            raise DowngradeError(
                "{} sequence {} does not advance the accepted sequence {} on {}".format(
                    version, sequence, prior_sequence, line
                )
            )
        else:
            action = ACTION_UPGRADE

    downgrade_reason_text = None
    if downgrade_requested:
        if allow_downgrade != version:
            raise DowngradeError(
                "downgrade from {} to {} on {} refused; pass --allow-downgrade {} with a reason".format(
                    prior["version"], version, line, version
                )
            )
        downgrade_reason_text = _require_reason(
            downgrade_reason, "downgrade to {}".format(version)
        )
        # Revocation override and downgrade override compose: both required.
        if exception_granted:
            action = ACTION_DOWNGRADE_SECURITY_EXCEPTION
    elif exception_granted:
        action = ACTION_SECURITY_EXCEPTION

    return {
        "action": action,
        "line": line,
        "version": version,
        "sequence": sequence,
        "manifest_hash": manifest_hash,
        "from_version": None if prior is None else prior["version"],
        "from_sequence": None if prior is None else prior["sequence"],
        "downgrade_reason": downgrade_reason_text,
        "security_exception": exception_granted,
        "previously_granted": exception_previous,
        "revoked_reason": revoked_reason.strip() if exception_granted and revoked_reason else None,
        "time": require_iso8601_utc(now_iso, "decision time"),
    }


def commit_acceptance(state: dict, decision: dict) -> dict:
    """Apply a decision to a fresh copy of the state document and validate it."""

    validate_state(state)
    updated = json.loads(json.dumps(state))
    line_state = updated["lines"][decision["line"]]
    line_state["accepted"] = {
        "version": decision["version"],
        "sequence": decision["sequence"],
        "manifest_hash": decision["manifest_hash"],
        "accepted_at": decision["time"],
    }
    if decision["security_exception"] and not decision["previously_granted"]:
        line_state["security_exceptions"].append(
            {
                "version": decision["version"],
                "manifest_hash": decision["manifest_hash"],
                "reason": decision["revoked_reason"],
                "granted_at": decision["time"],
            }
        )
    return validate_state(updated)


def record_tree_size(state: dict, line: str, tree_size: int) -> dict:
    validate_state(state)
    if line not in RELEASE_LINES:
        raise RekorError("unknown release line: {!r}".format(line))
    require_int(tree_size, "rekor tree size", minimum=0)
    previous = state["lines"][line]["rekor_tree_size"]
    if tree_size < previous:
        raise RekorError(
            "rekor tree size rollback refused: {} is below pinned {} on {}".format(
                tree_size, previous, line
            )
        )
    updated = json.loads(json.dumps(state))
    updated["lines"][line]["rekor_tree_size"] = tree_size
    return validate_state(updated)


_DECISION_AUDIT_EVENTS = {
    ACTION_TOFU: "tofu",
    ACTION_UPGRADE: "accept-upgrade",
    ACTION_REINSTALL: "accept-reinstall",
    ACTION_DOWNGRADE_OVERRIDE: "accept-downgrade",
    ACTION_SECURITY_EXCEPTION: "security-exception",
    ACTION_DOWNGRADE_SECURITY_EXCEPTION: "security-exception-downgrade",
}


def decision_audit_entry(decision: dict) -> dict:
    entry = {
        "time": decision["time"],
        "event": _DECISION_AUDIT_EVENTS[decision["action"]],
        "line": decision["line"],
        "to_version": decision["version"],
        "to_sequence": decision["sequence"],
        "manifest_hash": decision["manifest_hash"],
    }
    if decision["from_version"] is not None:
        entry["from_version"] = decision["from_version"]
        entry["from_sequence"] = decision["from_sequence"]
    if decision["downgrade_reason"]:
        entry["reason"] = decision["downgrade_reason"]
    if decision["security_exception"]:
        entry["security_exception"] = True
        entry["previously_granted"] = decision["previously_granted"]
        entry["revoked_reason"] = decision["revoked_reason"]
    return entry


def legacy_onboarding_audit_entry(
    *, line: str, legacy_version: str, target_version: str, time_iso: str, source: str
) -> dict:
    require_str(legacy_version, "legacy version")
    parse_semver(target_version, label="target version")
    require_iso8601_utc(time_iso, "onboarding time")
    require_str(source, "legacy onboarding source")
    return {
        "time": time_iso,
        "event": "legacy-onboarding",
        "line": line,
        "legacy_version": legacy_version,
        "to_version": target_version,
        "source": source,
    }


def record_trust_event(trust_dir: Path, event: str, *, time_iso: Optional[str] = None, **fields) -> None:
    require_str(event, "audit event")
    entry = {"time": time_iso or utc_now_iso(), "event": event}
    for name, value in fields.items():
        if value is not None:
            entry[name] = value
    append_audit_line(trust_audit_path(trust_dir), entry)


# ---------------------------------------------------------------------------
# Minimal DER / PEM reading (SubjectPublicKeyInfo and ECDSA signatures)
# ---------------------------------------------------------------------------

_PEM_BEGIN = "-----BEGIN PUBLIC KEY-----"
_PEM_END = "-----END PUBLIC KEY-----"
_OID_EC_PUBLIC_KEY = bytes.fromhex("06072a8648ce3d0201")
# secp256r1 / prime256v1 has two assigned named-curve OIDs; real-world keys
# (OpenSSL, Sigstore Rekor) use the ANSI X9.62 arc 1.2.840.10045.3.1.7 while
# the SECG arc 1.3.132.0.34 also appears. Both name the same curve.
_OID_P256_CURVE_ANSI = bytes.fromhex("06082a8648ce3d030107")
_OID_P256_CURVE_SECG = bytes.fromhex("06052b81040022")
_P256_CURVE_OIDS = (_OID_P256_CURVE_ANSI, _OID_P256_CURVE_SECG)


def _der_tlv(data: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset >= len(data) or (data[offset] & 0x1F) == 0x1F:
        raise SignatureError("unsupported DER tag in cryptographic material")
    tag = data[offset]
    index = offset + 1
    if index >= len(data):
        raise SignatureError("truncated DER length")
    length_byte = data[index]
    index += 1
    if length_byte & 0x80:
        length_bytes = length_byte & 0x7F
        if length_bytes == 0 or length_bytes > 4 or index + length_bytes > len(data):
            raise SignatureError("invalid DER long-form length")
        length = int.from_bytes(data[index:index + length_bytes], "big")
        index += length_bytes
    else:
        length = length_byte
    end = index + length
    if end > len(data):
        raise SignatureError("DER content overruns its container")
    return tag, bytes(data[index:end]), end


def _der_children(content: bytes) -> list:
    items = []
    offset = 0
    while offset < len(content):
        tag, child, offset = _der_tlv(content, offset)
        items.append((tag, child))
    return items


def _pem_to_der(pem_or_der: bytes) -> bytes:
    if isinstance(pem_or_der, str):
        pem_or_der = pem_or_der.encode("ascii")
    data = bytes(pem_or_der)
    if data[:1] == b"\x30":
        return data
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise SignatureError("cryptographic material is neither DER nor an ASCII PEM") from exc
    if _PEM_BEGIN not in text or _PEM_END not in text:
        raise SignatureError("expected an X.509 SubjectPublicKeyInfo PEM block")
    middle = text.split(_PEM_BEGIN, 1)[1].split(_PEM_END, 1)[0]
    return base64.b64decode("".join(middle.split()), validate=True)


# ---------------------------------------------------------------------------
# ECDSA P-256 verification (RFC 4754 / SEC1; verification only, no signing)
# ---------------------------------------------------------------------------

_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def p256_public_from_spki(pem_or_der) -> Tuple[int, int]:
    der = _pem_to_der(pem_or_der)
    tag, root, end = _der_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise SignatureError("SPKI is not a single DER SEQUENCE")
    root_children = _der_children(root)
    if len(root_children) != 2:
        raise SignatureError("SPKI must contain algorithm and bit string")
    algorithm_tag, algorithm = root_children[0]
    bit_tag, bit_string = root_children[1]
    if algorithm_tag != 0x30 or bit_tag != 0x03:
        raise SignatureError("SPKI has unexpected member tags")
    alg_children = _der_children(algorithm)
    if [tag for tag, _ in alg_children[:2]] != [0x06, 0x06]:
        raise SignatureError("SPKI algorithm identifier is malformed")
    der_alg = bytes([0x06, len(alg_children[0][1])]) + alg_children[0][1]
    der_curve = bytes([0x06, len(alg_children[1][1])]) + alg_children[1][1]
    if der_alg != _OID_EC_PUBLIC_KEY or der_curve not in _P256_CURVE_OIDS:
        raise SignatureError("only id-ecPublicKey on secp256r1 (P-256) is supported")
    if not bit_string or bit_string[0] != 0x00:
        raise SignatureError("EC point bit string must have zero unused bits")
    point = bit_string[1:]
    if len(point) != 65 or point[0] != 0x04:
        raise SignatureError("only uncompressed P-256 points (65 bytes) are supported")
    x_coord = int.from_bytes(point[1:33], "big")
    y_coord = int.from_bytes(point[33:65], "big")
    if not p256_on_curve(x_coord, y_coord) or (x_coord, y_coord) == (0, 0):
        raise SignatureError("P-256 public key is not a valid curve point")
    return x_coord, y_coord


def p256_spki_der(pem_or_der) -> bytes:
    return _pem_to_der(pem_or_der)


def rekor_log_id_from_pem(pem_or_der) -> str:
    return hashlib.sha256(_pem_to_der(pem_or_der)).hexdigest()


def p256_on_curve(x_coord: int, y_coord: int) -> bool:
    if not (0 < x_coord < _P256_P and 0 < y_coord < _P256_P):
        return False
    return (y_coord * y_coord - x_coord * x_coord * x_coord - _P256_A * x_coord - _P256_B) % _P256_P == 0


def _p256_inverse(value: int) -> int:
    return pow(value % _P256_P, _P256_P - 2, _P256_P)


def _p256_point_add(p_point: Tuple[int, int], q_point: Tuple[int, int]) -> Tuple[int, int]:
    if p_point is None:
        return q_point
    if q_point is None:
        return p_point
    x1, y1 = p_point
    x2, y2 = q_point
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if p_point == q_point:
        slope = ((3 * x1 * x1 + _P256_A) * _p256_inverse(2 * y1 % _P256_P)) % _P256_P
    else:
        slope = ((y2 - y1) * _p256_inverse((x2 - x1) % _P256_P)) % _P256_P
    x3 = (slope * slope - x1 - x2) % _P256_P
    y3 = (slope * (x1 - x3) - y1) % _P256_P
    return x3, y3


def _p256_scalar_mul(scalar: int, point: Tuple[int, int]) -> Optional[Tuple[int, int]]:
    if scalar % _P256_N == 0 or point is None:
        return None
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _p256_point_add(result, addend)
        addend = _p256_point_add(addend, addend)
        scalar >>= 1
    return result


def p256_parse_signature(signature: bytes) -> Tuple[int, int]:
    if not isinstance(signature, (bytes, bytearray)):
        raise SignatureError("ECDSA signature must be bytes")
    raw = bytes(signature)
    if len(raw) == 64:
        r_value = int.from_bytes(raw[:32], "big")
        s_value = int.from_bytes(raw[32:], "big")
    else:
        tag, content, end = _der_tlv(raw, 0)
        if tag != 0x30 or end != len(raw):
            raise SignatureError("ECDSA signature is not a DER SEQUENCE")
        children = _der_children(content)
        if len(children) != 2 or children[0][0] != 0x02 or children[1][0] != 0x02:
            raise SignatureError("ECDSA signature must contain two INTEGERs")
        r_value = int.from_bytes(children[0][1], "big", signed=True)
        s_value = int.from_bytes(children[1][1], "big", signed=True)
        if r_value < 0 or s_value < 0:
            raise SignatureError("ECDSA signature integers must be positive")
    if not (1 <= r_value < _P256_N and 1 <= s_value < _P256_N):
        raise SignatureError("ECDSA signature values are out of range")
    return r_value, s_value


def p256_verify_digest(public_pem_or_der, digest: bytes, signature: bytes) -> None:
    """Verify a P-256 ECDSA signature against an already-computed hash.

    hashedrekord ECDSA signatures are validated by the public Rekor instance
    against the raw 32-byte artifact digest directly (the digest is the ECDSA
    ``e`` value, not re-hashed); this entry point implements that path.
    """

    if not isinstance(digest, (bytes, bytearray)) or len(digest) != 32:
        raise SignatureError("ECDSA digest must be 32 bytes")
    e_value = int.from_bytes(bytes(digest), "big")
    x_q, y_q = p256_public_from_spki(public_pem_or_der)
    r_value, s_value = p256_parse_signature(signature)
    w_value = pow(s_value, _P256_N - 2, _P256_N)
    u1 = (e_value * w_value) % _P256_N
    u2 = (r_value * w_value) % _P256_N
    point = _p256_point_add(
        _p256_scalar_mul(u1, (_P256_GX, _P256_GY)),
        _p256_scalar_mul(u2, (x_q, y_q)),
    )
    if point is None:
        raise SignatureError("ECDSA verification produced the point at infinity")
    if point[0] % _P256_N != r_value:
        raise SignatureError("ECDSA signature does not verify against the P-256 key")


def p256_verify(public_pem_or_der, message: bytes, signature: bytes) -> None:
    """Verify a P-256 ECDSA signature over message with SHA-256.

    Accepts DER or raw r||s signatures. Raises SignatureError on any defect;
    returns None on success.
    """

    if not isinstance(message, (bytes, bytearray)):
        raise SignatureError("ECDSA message must be bytes")
    p256_verify_digest(
        public_pem_or_der, hashlib.sha256(bytes(message)).digest(), signature
    )


# ---------------------------------------------------------------------------
# RFC 6962 Merkle inclusion proofs
# ---------------------------------------------------------------------------


def rfc6962_leaf_hash(leaf_data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + bytes(leaf_data)).digest()


def _rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise RekorError("Merkle node children must be 32 bytes each")
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_rfc6962_inclusion(
    leaf_hash: bytes, leaf_index: int, tree_size: int, proof_hashes: Sequence[bytes]
) -> bytes:
    """Return the recomputed root hash or raise RekorError.

    Follows the RFC 6962 section 2.1.2 generalised inclusion algorithm.
    """

    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise RekorError("leaf_index must be an integer")
    if not isinstance(tree_size, int) or isinstance(tree_size, bool):
        raise RekorError("tree_size must be an integer")
    if leaf_index < 0 or tree_size <= 0 or leaf_index >= tree_size:
        raise RekorError(
            "inclusion bounds invalid: leaf {} outside tree of size {}".format(
                leaf_index, tree_size
            )
        )
    if len(leaf_hash) != 32:
        raise RekorError("leaf hash must be 32 bytes")
    fn_index = leaf_index
    sn_index = tree_size - 1
    computed = bytes(leaf_hash)
    for step, node in enumerate(proof_hashes):
        if not isinstance(node, (bytes, bytearray)) or len(node) != 32:
            raise RekorError("inclusion proof hash {} is not 32 bytes".format(step))
        if sn_index == 0:
            raise RekorError("inclusion proof contains an unexpected extra hash")
        if (fn_index & 1) == 1 or fn_index == sn_index:
            computed = _rfc6962_node_hash(bytes(node), computed)
            if (fn_index & 1) == 0:
                # fn == sn and even: this node joins a complete right subtree.
                while fn_index != 0 and (fn_index & 1) == 0:
                    fn_index >>= 1
                    sn_index >>= 1
        else:
            computed = _rfc6962_node_hash(computed, bytes(node))
        fn_index >>= 1
        sn_index >>= 1
    if sn_index != 0:
        raise RekorError("inclusion proof is too short for the claimed tree size")
    return computed


# ---------------------------------------------------------------------------
# Rekor hashedrekord v0.0.1 entries (offline verification, zero sockets)
# ---------------------------------------------------------------------------

REKOR_HASHEDREKORD_API_VERSION = "0.0.1"
REKOR_HASHEDREKORD_KIND = "hashedrekord"
REKOR_BODY_FIELD = "body"
REKOR_INTEGRATED_TIME_FIELD = "integratedTime"
REKOR_LOG_ID_FIELD = "logID"
REKOR_LOG_INDEX_FIELD = "logIndex"
REKOR_VERIFICATION_FIELD = "verification"
REKOR_INCLUSION_FIELD = "inclusionProof"
REKOR_SET_FIELD = "signedEntryTimestamp"
REKOR_CHECKPOINT_FIELD = "checkpoint"
REKOR_PROOF_HASHES_FIELD = "hashes"
REKOR_TREE_SIZE_FIELD = "treeSize"
REKOR_ROOT_SIZE_FIELD = "rootSize"
REKOR_ROOT_HASH_FIELD = "rootHash"

# Artifact signature schemes accepted inside hashedrekord v0.0.1 bodies.
# Ed25519 (RFC 8032) remains the offline manifest signature; the public
# Sigstore deployment anchors hashedrekord entries with ECDSA P-256/SHA-256
# (its verifier rejects plain Ed25519 keys as Ed25519ph/SHA-512), so both are
# required for interoperability with the live log.
REKOR_ARTIFACT_SCHEME_ED25519 = "ed25519"
REKOR_ARTIFACT_SCHEME_P256 = "ecdsa-p256-sha256"
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def hashedrekord_key_scheme(public_pem: str) -> str:
    """Identify the artifact signature scheme from the SPKI PEM public key."""

    der = _pem_to_der(public_pem)
    if der.startswith(_ED25519_SPKI_PREFIX) and len(der) == 44:
        return REKOR_ARTIFACT_SCHEME_ED25519
    # Raises SignatureError unless this is a P-256 ecPublicKey SPKI.
    p256_public_from_spki(der)
    return REKOR_ARTIFACT_SCHEME_P256


def rekor_b64_decode(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise RekorError("{} must be base64 text".format(label))
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise RekorError("{} is not valid base64".format(label)) from exc


def rekor_b64_encode(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def decode_hashedrekord_body(body: bytes) -> dict:
    """Parse and strictly validate a hashedrekord v0.0.1 entry body."""

    document = require_object(parse_json_document(bytes(body), "hashedrekord body"),
                              "hashedrekord body")
    exact_object(document, ("apiVersion", "kind", "spec"), "hashedrekord body")
    if document["apiVersion"] != REKOR_HASHEDREKORD_API_VERSION:
        raise RekorError("unsupported hashedrekord apiVersion")
    if document["kind"] != REKOR_HASHEDREKORD_KIND:
        raise RekorError("entry body is not a hashedrekord")
    spec = require_dict(document["spec"], "hashedrekord.spec")
    exact_object(spec, ("data", "signature"), "hashedrekord.spec")
    data = require_dict(spec["data"], "hashedrekord.spec.data")
    exact_object(data, ("hash",), "hashedrekord.spec.data")
    hash_obj = require_dict(data["hash"], "hashedrekord.spec.data.hash")
    exact_object(hash_obj, ("algorithm", "value"), "hashedrekord.spec.data.hash")
    if hash_obj["algorithm"] != "sha256":
        raise RekorError("only sha256 hashedrekord entries are supported")
    digest_hex = require_hex(hash_obj["value"], "hashedrekord digest", 32)

    signature = require_dict(spec["signature"], "hashedrekord.spec.signature")
    exact_object(signature, ("content", "publicKey"), "hashedrekord.spec.signature")
    signature_bytes = rekor_b64_decode(signature["content"], "hashedrekord signature")
    if not signature_bytes:
        raise RekorError("hashedrekord signature must not be empty")
    public_key = require_dict(signature["publicKey"], "hashedrekord.spec.signature.publicKey")
    exact_object(public_key, ("content",), "hashedrekord.spec.signature.publicKey")
    pem_bytes = rekor_b64_decode(public_key["content"], "hashedrekord public key")
    try:
        pem_text = pem_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise RekorError("hashedrekord public key must be an ASCII PEM block") from exc
    try:
        scheme = hashedrekord_key_scheme(pem_text)
    except SignatureError as exc:
        raise RekorError(
            "hashedrekord public key must be an Ed25519 or P-256 SPKI PEM"
        ) from exc
    if scheme == REKOR_ARTIFACT_SCHEME_ED25519 and len(signature_bytes) != 64:
        raise RekorError("hashedrekord Ed25519 signature must be 64 bytes")
    if scheme == REKOR_ARTIFACT_SCHEME_P256 and not (
        len(signature_bytes) == 64 or signature_bytes[:1] == b"\x30"
    ):
        raise RekorError(
            "hashedrekord P-256 signature must be 64 raw bytes or a DER SEQUENCE"
        )
    return {
        "digest_hex": digest_hex,
        "signature": signature_bytes,
        "public_pem": pem_text,
        "key_scheme": scheme,
    }


def hashedrekord_verify_artifact_signature(decoded_body: dict) -> Tuple[str, str]:
    """Verify the embedded artifact signature over the ASCII hex digest.

    hashedrekord v0.0.1 defines the signed message as the lower-case hex
    digest text the entry carries. Supports Ed25519 (RFC 8032) and ECDSA
    P-256/SHA-256 (DER or raw signatures); the public Sigstore log accepts
    the latter for SHA-256 digests. Returns (scheme, public key hex) where the
    hex is the 32-byte Ed25519 key or the 65-byte uncompressed P-256 point.
    """

    payload = decoded_body["digest_hex"].encode("ascii")
    scheme = decoded_body["key_scheme"]
    if scheme == REKOR_ARTIFACT_SCHEME_ED25519:
        der = _pem_to_der(decoded_body["public_pem"])
        if len(der) != 44:
            raise SignatureError("unexpected Ed25519 SPKI length")
        public = der[-32:]
        ed25519_verify(public, payload, decoded_body["signature"])
        return scheme, public.hex()

    x_coord, y_coord = p256_public_from_spki(decoded_body["public_pem"])
    # ECDSA hashedrekord signatures commit to the raw 32-byte digest (verified
    # empirically against the public Rekor instance, 201/400 cross-check).
    p256_verify_digest(
        decoded_body["public_pem"],
        bytes.fromhex(decoded_body["digest_hex"]),
        decoded_body["signature"],
    )
    point = b"\x04" + x_coord.to_bytes(32, "big") + y_coord.to_bytes(32, "big")
    return scheme, point.hex()


def _rekor_set_payload(body_b64: str, integrated_time: int, log_id: str, log_index: int) -> bytes:
    # Rekor signs a compact JSON document with keys in lexicographic order.
    payload = {
        REKOR_BODY_FIELD: body_b64,
        REKOR_INTEGRATED_TIME_FIELD: integrated_time,
        REKOR_LOG_ID_FIELD: log_id,
        REKOR_LOG_INDEX_FIELD: log_index,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


_CHECKPOINT_SIG_MARKER = "\u2014 "  # em dash + space, per the Go note format


def _parse_checkpoint_note(
    checkpoint: str, trusted_log_pem: bytes, expected_log_id: str
) -> Tuple[int, bytes]:
    """Parse and authenticate an RFC 9162 checkpoint note.

    Returns (tree size, root hash). The note must carry at least one
    signature line produced by the trusted transparency log key. Sigstore
    note signatures encode ``<4-byte keyID prefix><DER ECDSA P-256 signature>``
    where the keyID prefix is the first four bytes of the SHA-256 logID and
    the signed message is the three header lines plus one trailing newline.
    """

    if not isinstance(checkpoint, str) or not checkpoint:
        raise RekorError("inclusion proof must carry a checkpoint note")
    # RFC 9162 note layout: origin line, tree size line, base64 root line,
    # an empty separator line, then one or more signature lines.
    lines = checkpoint.split("\n")
    if len(lines) < 5 or lines[3] != "" or not lines[0]:
        raise RekorError("checkpoint note is malformed")
    note_size_text = lines[1]
    note_root_b64 = lines[2]
    try:
        note_size = int(note_size_text)
    except ValueError as exc:
        raise RekorError("checkpoint tree size is not an integer") from exc
    if note_size <= 0:
        raise RekorError("checkpoint tree size must be positive")
    try:
        note_root = base64.b64decode(
            note_root_b64 + "=" * (-len(note_root_b64) % 4), validate=True
        )
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise RekorError("checkpoint root hash is not valid base64") from exc
    if len(note_root) != 32:
        raise RekorError("checkpoint root hash must decode to 32 bytes")

    signed_note = (lines[0] + "\n" + lines[1] + "\n" + lines[2] + "\n").encode("utf-8")
    key_id_prefix = bytes.fromhex(expected_log_id[:8])
    origin_name = lines[0].split(" - ", 1)[0].strip()
    trusted_signature_found = False
    for signature_line in lines[4:]:
        if signature_line == "":
            continue
        if not signature_line.startswith(_CHECKPOINT_SIG_MARKER):
            raise RekorError("checkpoint signature line is malformed")
        parts = signature_line[len(_CHECKPOINT_SIG_MARKER):].split(" ")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise RekorError("checkpoint signature line is malformed")
        signer_name, signature_b64 = parts
        if signer_name != origin_name:
            raise RekorError("checkpoint signer does not match the note origin")
        blob = rekor_b64_decode(signature_b64, "checkpoint signature")
        if len(blob) <= 4 or blob[:4] != key_id_prefix:
            continue  # a co-signer we do not trust; the trusted key must also sign
        p256_verify(trusted_log_pem, signed_note, blob[4:])
        trusted_signature_found = True
    if not trusted_signature_found:
        raise RekorError("checkpoint note is not signed by the trusted transparency log key")
    return note_size, note_root


def verify_hashedrekord_entry(entry: dict, trusted_log_pem) -> dict:
    """Offline verification of one Rekor log entry against a trusted log key.

    Performs SET verification, body/Ed25519 binding, RFC 6962 inclusion and
    checkpoint cross-check. Performs no network IO. Returns the parsed body
    binding; raises RekorError/SignatureError on any inconsistency.
    """

    obj = require_object(entry, "rekor entry")
    for field in (REKOR_BODY_FIELD, REKOR_INTEGRATED_TIME_FIELD, REKOR_LOG_ID_FIELD,
                  REKOR_LOG_INDEX_FIELD, REKOR_VERIFICATION_FIELD):
        if field not in obj:
            raise RekorError("rekor entry is missing {!r}".format(field))
    body_b64 = require_str(obj[REKOR_BODY_FIELD], "rekor entry.body")
    body = rekor_b64_decode(body_b64, "rekor entry.body")
    integrated_time = require_int(
        obj[REKOR_INTEGRATED_TIME_FIELD], "rekor entry.integratedTime", minimum=0
    )
    log_id = require_str(obj[REKOR_LOG_ID_FIELD], "rekor entry.logID")
    log_index = require_int(obj[REKOR_LOG_INDEX_FIELD], "rekor entry.logIndex", minimum=0)

    expected_log_id = rekor_log_id_from_pem(trusted_log_pem)
    if log_id != expected_log_id:
        raise RekorError(
            "logID {} is not signed by the trusted Rekor key {}".format(log_id, expected_log_id)
        )

    decoded = decode_hashedrekord_body(body)
    artifact_scheme, public_hex = hashedrekord_verify_artifact_signature(decoded)

    verification = require_dict(obj[REKOR_VERIFICATION_FIELD], "rekor entry.verification")
    verifier_fields = set(verification.keys())
    if verifier_fields - {REKOR_INCLUSION_FIELD, REKOR_SET_FIELD}:
        raise MetadataError("rekor entry.verification contains unsupported field(s)")
    if REKOR_INCLUSION_FIELD not in verification:
        raise RekorError("rekor entry.verification must contain an inclusionProof")
    proof = require_dict(verification[REKOR_INCLUSION_FIELD], "rekor inclusion proof")
    allowed_proof_fields = {
        REKOR_PROOF_HASHES_FIELD,
        REKOR_LOG_INDEX_FIELD,
        REKOR_TREE_SIZE_FIELD,
        REKOR_CHECKPOINT_FIELD,
        REKOR_ROOT_HASH_FIELD,
        REKOR_ROOT_SIZE_FIELD,
        REKOR_SET_FIELD,
    }
    if set(proof.keys()) - allowed_proof_fields:
        raise MetadataError("rekor inclusion proof contains unsupported field(s)")
    for required in (
        REKOR_PROOF_HASHES_FIELD,
        REKOR_LOG_INDEX_FIELD,
        REKOR_TREE_SIZE_FIELD,
        REKOR_CHECKPOINT_FIELD,
    ):
        if required not in proof:
            raise RekorError("inclusion proof is missing {!r}".format(required))

    # Current sharded Rekor serves SET at verification level; legacy responses
    # embedded it inside the proof. Exactly one location is accepted.
    set_in_verification = REKOR_SET_FIELD in verification
    set_in_proof = REKOR_SET_FIELD in proof
    if set_in_verification and set_in_proof:
        raise RekorError("signedEntryTimestamp appears in two locations")
    if not (set_in_verification or set_in_proof):
        raise RekorError("entry is missing the signedEntryTimestamp")
    set_source = verification if set_in_verification else proof
    set_bytes = rekor_b64_decode(set_source[REKOR_SET_FIELD], "signedEntryTimestamp")
    p256_verify(
        trusted_log_pem,
        _rekor_set_payload(body_b64, integrated_time, log_id, log_index),
        set_bytes,
    )

    # The inclusion proof leaf index is scoped to the (possibly sharded) tree
    # the checkpoint commits to, so it need not equal the top-level logIndex.
    proof_leaf_index = require_int(proof[REKOR_LOG_INDEX_FIELD], "inclusion proof logIndex",
                                   minimum=0)
    tree_size = require_int(proof[REKOR_TREE_SIZE_FIELD], "inclusion proof treeSize", minimum=1)
    root_size, checkpoint_root = _parse_checkpoint_note(
        proof[REKOR_CHECKPOINT_FIELD], trusted_log_pem, log_id
    )
    if REKOR_ROOT_SIZE_FIELD in proof:
        explicit_root_size = require_int(
            proof[REKOR_ROOT_SIZE_FIELD], "inclusion proof rootSize", minimum=1
        )
        if explicit_root_size != root_size:
            raise RekorError("inclusion proof rootSize disagrees with the checkpoint")
    if REKOR_ROOT_HASH_FIELD in proof:
        advertised_root = require_hex(proof[REKOR_ROOT_HASH_FIELD], "inclusion proof rootHash", 32)
    else:
        advertised_root = None
    if not (proof_leaf_index < root_size <= tree_size):
        raise RekorError("inclusion proof size ordering is invalid")
    hashes = require_list(proof[REKOR_PROOF_HASHES_FIELD], "inclusion proof hashes")
    proof_hashes = [require_hex(value, "inclusion proof hash", 32) and bytes.fromhex(value)
                    for value in hashes]
    # Rekor's Merkle leaf is RFC 6962 leaf-hash over the canonical entry body
    # bytes directly (empirically cross-checked against the live log).
    leaf_hash = rfc6962_leaf_hash(body)
    root_hash = verify_rfc6962_inclusion(leaf_hash, proof_leaf_index, root_size, proof_hashes)
    if checkpoint_root != root_hash:
        raise RekorError("checkpoint root does not match the recomputed Merkle root")
    if advertised_root is not None and bytes.fromhex(advertised_root) != root_hash:
        raise RekorError("inclusion proof rootHash disagrees with the checkpoint")

    return {
        "digest_hex": decoded["digest_hex"],
        "artifact_scheme": artifact_scheme,
        "public_hex": public_hex,
        "log_id": log_id,
        "log_index": log_index,
        "inclusion_log_index": proof_leaf_index,
        "integrated_time": integrated_time,
        "root_size": root_size,
        "tree_size": tree_size,
        "root_hash": root_hash.hex(),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }


def rekor_entry_from_api_response(response: Any, entry_uuid: str) -> dict:
    """Normalise a GET /log/entries/{uuid} response into one entry object."""

    document = require_object(response, "rekor api response")
    entry = document.get(entry_uuid)
    if entry is None and len(document) == 1:
        entry = next(iter(document.values()))
    if entry is None:
        raise RekorError("rekor response does not contain entry {}".format(entry_uuid))
    if not isinstance(entry, dict):
        raise RekorError("rekor entry payload must be an object")
    return entry
