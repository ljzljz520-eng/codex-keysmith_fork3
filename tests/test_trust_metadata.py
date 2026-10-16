"""Tests for the trust engine foundation: canonical JSON, policy, envelopes."""

from __future__ import annotations

import ast
import json
import sysconfig
from pathlib import Path

import pytest

from scripts import keysmith_trust as trust

REPO_ROOT = Path(__file__).resolve().parents[1]

DISTRIBUTABLE_MODULES = [
    REPO_ROOT / "scripts" / "keysmith_trust.py",
]


def _stdlib_top_level():
    # Python 3.9-compatible equivalent of sys.stdlib_module_names.
    names = set(__import__("sys").builtin_module_names)
    paths = sysconfig.get_paths()
    directories = [paths["stdlib"]]
    shared = sysconfig.get_config_var("DESTSHARED")
    if shared:
        directories.append(shared)
    for directory in directories:
        root = Path(directory)
        if not root.is_dir():
            continue
        for entry in root.iterdir():
            if entry.name.startswith(("site-", "dist-")):
                continue
            if entry.is_file() and entry.suffix == ".py":
                names.add(entry.stem)
            elif entry.is_dir() and (entry / "__init__.py").is_file():
                names.add(entry.name)
            elif entry.is_file() and entry.suffix in (".so", ".pyd", ".dylib"):
                names.add(entry.name.split(".")[0])
    return names


STDLIB_TOP_LEVEL = _stdlib_top_level()


def _distributable_imports(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                imported.add(node.module.split(".")[0])
    return imported


def test_canonical_json_is_deterministic():
    value = {"b": 2, "a": [1, {"z": 0, "y": "中"}], "c": None}
    first = trust.canonical_json_bytes(value)
    second = trust.canonical_json_bytes({"c": None, "a": [1, {"y": "中", "z": 0}], "b": 2})
    assert first == second
    assert first.endswith(b"\n")
    assert "中".encode("utf-8") in first
    parsed = json.loads(first.decode("utf-8"))
    assert parsed == value


def test_canonical_json_key_order_changes_bytes():
    ordered = trust.canonical_json_bytes({"a": 1, "b": 2})
    assert ordered.index(b'"a"') < ordered.index(b'"b"')
    # Whitespace and number encoding stay fixed.
    assert trust.canonical_json_bytes({"a": 1}) != trust.canonical_json_bytes({"a": "1"})
    assert trust.canonical_json_bytes({"a": 1}) != trust.canonical_json_bytes({"a": 1, "x": 0})


def test_canonical_json_rejects_non_json_types():
    with pytest.raises(trust.MetadataError):
        trust.canonical_json_bytes({"a": b"bytes"})
    with pytest.raises(trust.MetadataError):
        trust.canonical_json_bytes({1: "x"})
    with pytest.raises(trust.MetadataError):
        trust.canonical_json_bytes(float("nan"))


def test_canonical_sha256_matches_manual_serialization():
    value = {"_type": "root", "version": 1}
    expected = trust.hashlib.sha256(trust.canonical_json_bytes(value)).hexdigest()
    assert trust.canonical_sha256(value) == expected


def test_shipped_policy_loads():
    policy = trust.load_policy()
    assert policy["product"] == "codex-keysmith"
    assert policy["first_signed_version"] is None
    assert set(policy["release_lines"]) == set(trust.RELEASE_LINES)


def test_shipped_trust_directories_hold_no_signed_material():
    # The real trust/ tree must never contain root/revocation/release secrets
    # or live signed material; fixtures live under tests/fixtures/trust only.
    for relative in ("trust/root", "trust/revocations", "trust/releases"):
        entries = sorted(path.name for path in (REPO_ROOT / relative).iterdir())
        assert entries == [".gitkeep"], relative


def test_policy_rejects_unknown_fields_and_bad_values(tmp_path):
    good = json.loads(trust.read_regular_file(trust.default_policy_path()))

    def write_policy(**changes):
        value = dict(good)
        value.update(changes)
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(unknown=1))
    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(schema_version=2))
    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(product="other"))
    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(first_signed_version="v1.0.0"))
    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(first_signed_version="01.0.0"))
    with pytest.raises(trust.PolicyError):
        trust.load_policy(write_policy(release_lines=["stable"]))
    broken = tmp_path / "missing.json"
    with pytest.raises(trust.StateError):
        trust.load_policy(broken)
    malformed = tmp_path / "bad.json"
    malformed.write_text("{not json", encoding="utf-8")
    with pytest.raises(trust.PolicyError):
        trust.load_policy(malformed)


def test_policy_accepts_semantic_first_signed_version(tmp_path):
    good = json.loads(trust.read_regular_file(trust.default_policy_path()))
    good["first_signed_version"] = "0.7.0"
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(good), encoding="utf-8")
    policy = trust.load_policy(path)
    assert policy["first_signed_version"] == "0.7.0"


def test_envelope_round_trip_and_validation():
    signed = {"_type": "release", "version": 1}
    keyid = "ed25519:" + "a" * 64
    envelope = trust.make_envelope(signed, [(keyid, b"\x11" * 64)])
    raw = trust.canonical_json_bytes(envelope)
    parsed = trust.load_envelope(raw)
    assert parsed["signed"]["_type"] == "release"
    assert parsed["signatures"][0]["sig"] == "11" * 64
    assert trust.signed_payload_bytes(parsed) == trust.canonical_json_bytes(signed)


def test_envelope_rejects_bad_shapes():
    good_signed = {"_type": "root", "version": 1}
    keyid = "ed25519:" + "a" * 64
    raw_cases = [
        trust.canonical_json_bytes({"signed": good_signed}),
        trust.canonical_json_bytes({"signatures": []}),
        trust.canonical_json_bytes({"signed": {"_type": "mystery"}, "signatures": []}),
        trust.canonical_json_bytes(
            {"signed": good_signed, "signatures": [{"keyid": keyid, "sig": "zz"}]}
        ),
        trust.canonical_json_bytes(
            {"signed": good_signed, "signatures": [{"keyid": keyid, "sig": "g" * 128}]}
        ),
        trust.canonical_json_bytes(
            {"signed": good_signed, "signatures": [{"keyid": "", "sig": "a" * 128}]}
        ),
        trust.canonical_json_bytes(
            {
                "signed": good_signed,
                "signatures": [
                    {"keyid": keyid, "sig": "a" * 128},
                    {"keyid": keyid, "sig": "b" * 128},
                ],
            }
        ),
    ]
    for raw in raw_cases:
        with pytest.raises(trust.MetadataError):
            trust.load_envelope(raw)


def test_make_envelope_rejects_bad_signature_material():
    signed = {"_type": "root", "version": 1}
    with pytest.raises(trust.SignatureError):
        trust.make_envelope(signed, [("ed25519:x", b"\x00" * 32)])
    with pytest.raises(trust.SignatureError):
        trust.make_envelope(signed, [("", b"\x00" * 64)])


def test_key_id_is_stable_and_typed():
    public = bytes(range(32))
    first = trust.ed25519_key_id(public)
    second = trust.ed25519_key_id(bytes(public))
    assert first == second
    assert first.startswith("ed25519:")
    assert len(first) == len("ed25519:") + 64
    assert trust.ed25519_key_id(b"\x00" * 32) != first
    with pytest.raises(trust.SignatureError):
        trust.ed25519_key_id(b"short")
    assert trust.key_id_for_hex_public(public.hex()) == first


def test_asset_name_validation():
    trust.validate_asset_name("codex-instruct-v0.7.0.py")
    trust.validate_asset_name("SHA256SUMS")
    for bad in ("../x", "a/b", "a\\b", ".", "..", "CON", "NUL.txt", "x ", "x.", 'a:b', "a|b", "\x00"):
        with pytest.raises(trust.MetadataError):
            trust.validate_asset_name(bad)


def test_private_directory_and_atomic_write(tmp_path):
    target_dir = tmp_path / "trust"
    trust.ensure_private_directory(target_dir)
    assert target_dir.is_dir()
    path = target_dir / "state.json"
    trust.atomic_write(path, b'{"a": 1}')
    assert trust.read_regular_file(path) == b'{"a": 1}'
    # Overwrite replaces atomically; no temp files remain.
    trust.atomic_write(path, b'{"a": 2}')
    assert trust.read_regular_file(path) == b'{"a": 2}'
    assert list(target_dir.glob(".keysmith-trust-*.tmp")) == []
    # Symlink ancestor is rejected.
    link = tmp_path / "link"
    link.symlink_to(target_dir, target_is_directory=True)
    with pytest.raises(trust.StateError):
        trust.atomic_write(link / "x.json", b"x")


def test_audit_log_append_and_iterate(tmp_path):
    log = tmp_path / "audit.jsonl"
    trust.append_audit_line(log, {"event": "tofu", "version": "0.7.0"})
    trust.append_audit_line(log, {"event": "accept", "version": "0.8.0"})
    events = list(trust.iter_audit_entries(log))
    assert [event["event"] for event in events] == ["tofu", "accept"]
    raw = log.read_text(encoding="utf-8").splitlines()
    assert len(raw) == 2 and all(line.startswith("{") for line in raw)
    # Corruption fails closed.
    log.write_text(raw[0] + "\nnot json\n", encoding="utf-8")
    with pytest.raises(trust.StateError):
        list(trust.iter_audit_entries(log))


def test_sha256_file_reports_size(tmp_path):
    path = tmp_path / "asset.bin"
    path.write_bytes(b"abcd" * 1000)
    digest, size = trust.sha256_file(path)
    assert size == 4000
    assert digest == trust.hashlib.sha256(b"abcd" * 1000).hexdigest()


@pytest.mark.parametrize("module_path", DISTRIBUTABLE_MODULES)
def test_distributable_modules_use_stdlib_only(module_path):
    imported = _distributable_imports(module_path)
    third_party = {name for name in imported if name not in STDLIB_TOP_LEVEL}
    assert third_party == set()


# ---------------------------------------------------------------------------
# TR-3.1 root role metadata and rotation matrix
# ---------------------------------------------------------------------------


def _deterministic_seed(name: str) -> bytes:
    return trust.hashlib.sha256(("keysmith-tr-test:" + name).encode("utf-8")).digest()


def _key_pair(name: str):
    seed = _deterministic_seed(name)
    public = trust.ed25519_public_from_seed(seed)
    return seed, trust.key_id_for_hex_public(public.hex()), public.hex()


def _root_keys(*names: str):
    pairs = {name: _key_pair(name) for name in names}
    keyids = {name: pairs[name][1] for name in names}
    keys = {
        pairs[name][1]: {"keytype": trust.ED25519_KEYTYPE, "public": pairs[name][2]}
        for name in names
    }
    return pairs, keyids, keys


def _root_signed(version, keys, roles, *, expires="2031-01-01T00:00:00Z", rekor_keys=None):
    return trust.make_root_signed(
        version=version, roles=roles, keys=keys, expires=expires, rekor_keys=rekor_keys
    )


def _roles(keyids, root_threshold=1, release_threshold=1, revocation_threshold=1):
    return {
        trust.ROLE_ROOT: {"keyids": [keyids[name] for name in keyids if name.startswith("root")],
                          "threshold": root_threshold},
        trust.ROLE_RELEASE: {"keyids": [keyids[name] for name in keyids if name.startswith("release")],
                             "threshold": release_threshold},
        trust.ROLE_REVOCATION: {"keyids": [keyids[name] for name in keyids
                                           if name.startswith("revocation")],
                                "threshold": revocation_threshold},
    }


_REKOR_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0000000000000000000000000000\n"
    "0000000000000000000000000000000000000000000000000000000000000000\n"
    "0000000000000000000000000000000000000000000000000000000000000000\n"
    "-----END PUBLIC KEY-----\n"
)


def test_root_v1_self_signature_bootstraps():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "revocation-a")
    roles = _roles(keyids)
    signed = _root_signed(1, keys, roles, rekor_keys=[
        {"keyid": "rekor:" + "c" * 64, "keytype": trust.REKOR_KEYTYPE, "public_pem": _REKOR_PEM},
    ])
    envelope = trust.seal_envelope(signed, [pairs["root-a"][0]])
    assert trust.verify_root_document(envelope, None) is signed


def test_root_v1_requires_version_one_and_threshold():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "revocation-a")
    roles = _roles(keyids)
    signed = _root_signed(2, keys, roles)
    envelope = trust.seal_envelope(signed, [pairs["root-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(envelope, None)
    # An unsigned / wrongly-signed v1 fails closed.
    signed_v1 = _root_signed(1, keys, roles)
    unsigned = trust.make_envelope(signed_v1, [])
    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(unsigned, None)
    other_seed = _deterministic_seed("outsider")
    forged = trust.seal_envelope(signed_v1, [other_seed])
    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(forged, None)


def test_root_rotation_requires_previous_root_threshold():
    old_pairs, old_keyids, old_keys = _root_keys("root-a", "release-a", "revocation-a")
    old_roles = _roles(old_keyids)
    old_signed = _root_signed(1, old_keys, old_roles)

    new_pairs, new_keyids, new_keys = _root_keys("root-b", "release-b", "revocation-b")
    new_roles = _roles(new_keyids)
    new_signed = _root_signed(2, new_keys, new_roles)

    # Signed only by the successor key: not enough.
    successor_only = trust.seal_envelope(new_signed, [new_pairs["root-b"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(successor_only, old_signed)
    # Signed by the previous root: accepted even without a self-signature.
    previous = trust.seal_envelope(new_signed, [old_pairs["root-a"][0]])
    assert trust.verify_root_document(previous, old_signed) is new_signed
    # Previous root plus a harmless extra self-signature is also accepted.
    both = trust.seal_envelope(new_signed, [old_pairs["root-a"][0], new_pairs["root-b"][0]])
    assert trust.verify_root_document(both, old_signed) is new_signed


def test_root_rotation_threshold_matrix_with_three_root_keys():
    _, old_keyids, old_keys = _root_keys("root-a", "root-b", "root-c", "release-a", "revocation-a")
    old_roles = _roles(old_keyids, root_threshold=2)
    old_signed = _root_signed(1, old_keys, old_roles)

    _, new_keyids, new_keys = _root_keys("root-d", "root-e", "root-f", "release-b", "revocation-b")
    new_roles = _roles(new_keyids, root_threshold=2)
    new_signed = _root_signed(2, new_keys, new_roles)
    seeds = {name: _key_pair(name)[0] for name in ("root-a", "root-b", "root-c", "root-d")}

    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(trust.seal_envelope(new_signed, [seeds["root-a"]]), old_signed)
    with pytest.raises(trust.SignatureError):
        # One old key plus one new key is still below the old threshold of two.
        trust.verify_root_document(
            trust.seal_envelope(new_signed, [seeds["root-a"], seeds["root-d"]]), old_signed
        )
    verified = trust.verify_root_document(
        trust.seal_envelope(new_signed, [seeds["root-a"], seeds["root-c"]]), old_signed
    )
    assert verified is new_signed


def test_root_rotation_rejects_skips_and_rollbacks():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "revocation-a")
    roles = _roles(keyids)
    v1 = _root_signed(1, keys, roles)
    v3 = _root_signed(3, keys, roles)
    envelope = trust.seal_envelope(v3, [pairs["root-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_root_document(envelope, v1)
    trust.ensure_root_not_rolled_back(2, 2)
    trust.ensure_root_not_rolled_back(3, 2)
    with pytest.raises(trust.SignatureError):
        trust.ensure_root_not_rolled_back(1, 2)


def test_root_schema_rejects_inconsistent_role_and_key_tables():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "revocation-a")
    base_roles = _roles(keyids)

    good = _root_signed(1, keys, base_roles)
    good.pop("rekor_keys")
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(good)

    bad_threshold = _roles(keyids)
    bad_threshold[trust.ROLE_ROOT]["threshold"] = 2
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(_root_signed(1, keys, bad_threshold))

    unknown_reference = _roles(keyids)
    unknown_reference[trust.ROLE_RELEASE]["keyids"].append("ed25519:" + "9" * 64)
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(_root_signed(1, keys, unknown_reference))

    duplicate_role = _roles(keyids)
    duplicate_role[trust.ROLE_ROOT]["keyids"].append(keyids["root-a"])
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(_root_signed(1, keys, duplicate_role))

    # Registering a key that no role references is rejected.
    extra_keys = dict(keys)
    stray_seed = _deterministic_seed("stray")
    stray_public = trust.ed25519_public_from_seed(stray_seed).hex()
    extra_keys[trust.key_id_for_hex_public(stray_public)] = {
        "keytype": trust.ED25519_KEYTYPE,
        "public": stray_public,
    }
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(_root_signed(1, extra_keys, base_roles))

    # A keyid that does not derive from its claimed public key is rejected.
    mismatched = {name: dict(entry) for name, entry in keys.items()}
    first = sorted(mismatched)[0]
    mismatched[first]["public"] = trust.ed25519_public_from_seed(
        _deterministic_seed("different")
    ).hex()
    with pytest.raises(trust.MetadataError):
        trust.validate_root_signed(_root_signed(1, mismatched, base_roles))


def test_root_schema_rejects_bad_rekor_entries():
    _, keyids, keys = _root_keys("root-a", "release-a", "revocation-a")
    roles = _roles(keyids)
    base = {
        "keyid": "rekor:" + "c" * 64,
        "keytype": trust.REKOR_KEYTYPE,
        "public_pem": _REKOR_PEM,
    }
    trust.validate_root_signed(_root_signed(1, keys, roles, rekor_keys=[dict(base)]))
    for mutated in (
        {"keyid": "sigstore:" + "c" * 64},
        {"keyid": "rekor:" + "z" * 64},
        {"keyid": "rekor:" + "c" * 63},
        {"keytype": "ecdsa-p384"},
        {"public_pem": "not a pem"},
    ):
        bad_entry = dict(base)
        bad_entry.update(mutated)
        with pytest.raises(trust.MetadataError):
            trust.validate_root_signed(_root_signed(1, keys, roles, rekor_keys=[bad_entry]))


# ---------------------------------------------------------------------------
# TR-3.2 revocations: schema, matching, cumulative, signing role
# ---------------------------------------------------------------------------


def _revocations_signed(
    *,
    version=1,
    issued_at="2026-02-01T00:00:00Z",
    expires="2026-03-03T00:00:00Z",
    revoked_keys=None,
    revoked_releases=None,
    revoked_artifacts=None,
):
    value = {
        "_type": trust.REVOCATIONS_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "version": version,
        "issued_at": issued_at,
        "expires": expires,
        "revoked_keys": revoked_keys or [],
        "revoked_releases": revoked_releases or [],
        "revoked_artifacts": revoked_artifacts or [],
    }
    return trust.validate_revocations(value)


def _revoked_key(keyid, *, reason="compromise", revoked_at="2026-02-01T00:00:00Z"):
    return {"keyid": keyid, "reason": reason, "revoked_at": revoked_at}


def _revoked_artifact(digest, *, reason="tampered", revoked_at="2026-02-01T00:00:00Z"):
    return {"sha256": digest, "reason": reason, "revoked_at": revoked_at}


def _revoked_release(
    line="stable",
    version="0.7.0",
    *,
    to_version=None,
    severity="critical",
    reason="RCE in bundled dependency",
    fixed_version="0.7.1",
    security_exception_allowed=False,
    revoked_at="2026-02-01T00:00:00Z",
):
    return {
        "release_line": line,
        "version": version,
        "to_version": to_version,
        "severity": severity,
        "reason": reason,
        "fixed_version": fixed_version,
        "security_exception_allowed": security_exception_allowed,
        "revoked_at": revoked_at,
    }


def test_revocations_valid_document_round_trip():
    _, keyids, _ = _root_keys("root-a", "release-a", "revocation-a")
    signed = _revocations_signed(
        revoked_keys=[_revoked_key(keyids["release-a"])],
        revoked_releases=[
            _revoked_release("stable", "0.7.0", to_version="0.7.2", fixed_version="0.7.3"),
            _revoked_release("desktop-beta", "0.6.0-beta.2", severity="high",
                             fixed_version="0.6.0-beta.3"),
        ],
        revoked_artifacts=[_revoked_artifact("ab" * 32)],
    )
    assert signed["version"] == 1
    assert trust.revoked_key_entry(signed, keyids["release-a"])["reason"] == "compromise"
    assert trust.revoked_key_entry(signed, "ed25519:" + "0" * 64) is None
    assert trust.revoked_artifact_entry(signed, "ab" * 32) is not None
    assert trust.revoked_artifact_entry(signed, "cd" * 32) is None


def test_revocations_schema_rejects_bad_shapes():
    _, keyids, _ = _root_keys("root-a", "release-a", "revocation-a")
    good = _revocations_signed(
        revoked_keys=[_revoked_key(keyids["release-a"])],
        revoked_releases=[_revoked_release()],
        revoked_artifacts=[_revoked_artifact("ab" * 32)],
    )
    with pytest.raises(trust.MetadataError):
        trust.validate_revocations(dict(good, version=0))
    dup_keys = dict(good)
    dup_keys["revoked_keys"] = [_revoked_key("ed25519:1"), _revoked_key("ed25519:1")]
    with pytest.raises(trust.MetadataError):
        trust.validate_revocations(dup_keys)
    dup_artifacts = dict(good)
    dup_artifacts["revoked_artifacts"] = [_revoked_artifact("ab" * 32),
                                          _revoked_artifact("ab" * 32)]
    with pytest.raises(trust.MetadataError):
        trust.validate_revocations(dup_artifacts)

    bad_release_cases = [
        {"release_line": "nightly"},
        {"version": "not-semver"},
        {"to_version": "0.6.0"},
        {"severity": "apocalyptic"},
        {"fixed_version": "0.7"},
        {"security_exception_allowed": "yes"},
    ]
    for change in bad_release_cases:
        broken_release = _revoked_release()
        broken_release.update(change)
        with pytest.raises(trust.MetadataError):
            _revocations_signed(revoked_releases=[broken_release])

    overlap_a = _revoked_release("stable", "0.7.0", to_version="0.7.5")
    overlap_b = _revoked_release("stable", "0.7.3", to_version="0.7.9", reason="other")
    with pytest.raises(trust.MetadataError):
        _revocations_signed(revoked_releases=[overlap_a, overlap_b])
    # Adjacent, non-overlapping ranges on the same line are fine.
    adjacent = _revoked_release("stable", "0.7.6", to_version="0.7.9", reason="other")
    trust.validate_revocations(_revocations_signed(revoked_releases=[overlap_a, adjacent]))
    # The same versions on a different line never overlap.
    cross_line = _revoked_release("desktop-beta", "0.7.0", to_version="0.7.5", reason="other")
    trust.validate_revocations(_revocations_signed(revoked_releases=[overlap_a, cross_line]))


def test_revoked_release_matches_exact_and_range_boundaries():
    signed = _revocations_signed(
        revoked_releases=[
            _revoked_release("stable", "0.7.0", to_version="0.7.2"),
            _revoked_release("desktop-beta", "0.6.0-beta.2"),
        ]
    )
    assert trust.revoked_release_entry(signed, "stable", "0.7.0") is not None
    assert trust.revoked_release_entry(signed, "stable", "0.7.1") is not None
    assert trust.revoked_release_entry(signed, "stable", "0.7.2") is not None
    assert trust.revoked_release_entry(signed, "stable", "0.6.9") is None
    assert trust.revoked_release_entry(signed, "stable", "0.7.3") is None
    # Prerelease of the range's lower bound sorts below it and is not covered.
    assert trust.revoked_release_entry(signed, "stable", "0.7.0-beta.1") is None
    beta_hit = trust.revoked_release_entry(signed, "desktop-beta", "0.6.0-beta.2")
    assert beta_hit is not None
    assert trust.revoked_release_entry(signed, "desktop-beta", "0.6.0-beta.3") is None


def test_semver_prerelease_ordering():
    ordered = ["0.6.0-alpha", "0.6.0-alpha.2", "0.6.0-beta.1", "0.6.0-beta.2",
               "0.6.0-rc.1", "0.6.0", "0.6.1"]
    for earlier, later in zip(ordered, ordered[1:]):
        assert trust.compare_semver(earlier, later) < 0
        assert trust.compare_semver(later, earlier) > 0
    assert trust.compare_semver("0.7.0", "0.7.0") == 0
    with pytest.raises(trust.MetadataError):
        trust.parse_semver("01.0.0")


def test_revocations_expiry_is_a_soft_signal():
    signed = _revocations_signed(expires="2026-03-03T00:00:00Z")
    assert not trust.revocations_is_expired(signed, "2026-03-02T23:59:59Z")
    assert trust.revocations_is_expired(signed, "2026-03-03T00:00:01Z")


def test_revocations_must_be_cumulative_and_monotonic():
    key_entry = _revoked_key("ed25519:1111")
    artifact_entry = _revoked_artifact("ab" * 32)
    release_entry = _revoked_release("stable", "0.7.0")
    v1 = _revocations_signed(
        revoked_keys=[key_entry],
        revoked_releases=[release_entry],
        revoked_artifacts=[artifact_entry],
    )
    # The first document must start at version 1.
    with pytest.raises(trust.SignatureError):
        trust.ensure_revocations_cumulative(_revocations_signed(version=2), None)
    # Version skips are rejected.
    v3 = _revocations_signed(version=3, revoked_keys=[key_entry],
                             revoked_releases=[release_entry],
                             revoked_artifacts=[artifact_entry])
    with pytest.raises(trust.SignatureError):
        trust.ensure_revocations_cumulative(v3, v1)

    v2 = _revocations_signed(
        version=2,
        revoked_keys=[key_entry, _revoked_key("ed25519:2222", reason="rotate")],
        revoked_releases=[release_entry],
        revoked_artifacts=[artifact_entry],
    )
    trust.ensure_revocations_cumulative(v2, v1)

    for field in ("revoked_keys", "revoked_artifacts", "revoked_releases"):
        dropped = json.loads(json.dumps(v1))
        dropped["version"] = 2
        dropped[field] = []
        trust.validate_revocations(dropped)
        with pytest.raises(trust.RevocationError):
            trust.ensure_revocations_cumulative(dropped, v1)

    # Rewriting the reason silently drops the historical entry (full identity).
    rewritten = _revoked_release("stable", "0.7.0", reason="changed story")
    with pytest.raises(trust.RevocationError):
        trust.ensure_revocations_cumulative(
            _revocations_signed(version=2, revoked_keys=[key_entry],
                                 revoked_artifacts=[artifact_entry],
                                 revoked_releases=[rewritten]),
            v1,
        )


def test_revocations_are_signed_by_the_root_revocation_role():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "revocation-a", "revocation-b")
    roles = _roles(keyids, revocation_threshold=2)
    root = _root_signed(1, keys, roles)
    signed = _revocations_signed()

    good = trust.seal_envelope(signed, [pairs["revocation-a"][0], pairs["revocation-b"][0]])
    assert trust.verify_revocations_signature(good, root) is signed
    only_one = trust.seal_envelope(signed, [pairs["revocation-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_revocations_signature(only_one, root)
    # Release keys must never authorize revocations.
    wrong_role = trust.seal_envelope(signed, [pairs["release-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_revocations_signature(wrong_role, root)


# ---------------------------------------------------------------------------
# TR-3.3 release index: build/append/verify/signing role
# ---------------------------------------------------------------------------


def _manifest_signed(
    *,
    line="stable",
    version="0.7.0",
    sequence=1,
    issued_at="2026-02-01T00:00:00Z",
    digest_prefix="aa",
    desktop=False,
):
    if desktop or line == "desktop-beta":
        line = "desktop-beta"
        build_manifests = {
            "codex-keysmith-0.6.0-beta.2-macos-build-manifest.json": "de" * 32,
            "codex-keysmith-0.6.0-beta.2-windows-build-manifest.json": "df" * 32,
        }
    else:
        build_manifests = {}
    tag = trust.expected_tag_for(line, version)
    return trust.validate_release_manifest({
        "_type": trust.RELEASE_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": line,
        "version": version,
        "tag": tag,
        "sequence": sequence,
        "issued_at": issued_at,
        "source": {
            "repo": "Jia-Ethan/codex-keysmith",
            "commit": "0123456789abcdef0123456789abcdef01234567",
            "tag_object": "fedcba9876543210fedcba9876543210fedcba98",
        },
        "builder": {
            "workflow_name": "release.yml",
            "workflow_ref": "refs/heads/main",
            "workflow_sha": "abcdef0123456789abcdef0123456789abcdef01",
            "runner": "github-hosted",
            "python_version": "3.9.6",
            "node_version": "",
            "rust_version": "",
            "pyinstaller_version": "",
            "build_manifests": build_manifests,
        },
        "artifacts": {
            "codex-instruct-v{}.py".format(version): {
                "sha256": digest_prefix * 32,
                "size": 1234,
            },
        },
        "sboms": {
            "codex-keysmith-v{}.spdx.json".format(version): {
                "sha256": "11" * 32,
                "size": 42,
            },
            "codex-keysmith-v{}.cdx.json".format(version): {
                "sha256": "22" * 32,
                "size": 43,
            },
        },
        "required_root_version": 1,
        "required_revocations_version": 0,
    })


def test_release_manifest_schema_and_tag_rules():
    stable = _manifest_signed()
    assert stable["tag"] == "v0.7.0"
    desktop = _manifest_signed(line="desktop-beta", version="0.6.0-beta.2", sequence=1,
                               digest_prefix="bb")
    assert desktop["tag"] == "desktop-v0.6.0-beta.2"
    bad = json.loads(json.dumps(stable))
    bad["tag"] = "wrong-tag"
    with pytest.raises(trust.MetadataError):
        trust.validate_release_manifest(bad)
    bad_product = json.loads(json.dumps(stable))
    bad_product["product"] = "something-else"
    with pytest.raises(trust.MetadataError):
        trust.validate_release_manifest(bad_product)
    short_commit = json.loads(json.dumps(stable))
    short_commit["source"]["commit"] = "abc"
    with pytest.raises(trust.MetadataError):
        trust.validate_release_manifest(short_commit)
    # Desktop-beta without build manifests is rejected.
    bare_desktop = json.loads(json.dumps(desktop))
    bare_desktop["builder"]["build_manifests"] = {}
    with pytest.raises(trust.MetadataError):
        trust.validate_release_manifest(bare_desktop)


def test_release_index_append_per_line_sequence_and_version():
    envelope_one = {"signed": _manifest_signed(version="0.7.0", sequence=1, digest_prefix="aa")}
    index_one = trust.append_index_entry(None, envelope_one, issued_at="2026-02-01T00:00:00Z")
    assert index_one["version"] == 1
    assert trust.last_sequence(index_one, "stable") == 1
    assert trust.last_sequence(index_one, "desktop-beta") == 0
    entry = trust.index_entry_for(index_one, "stable", "0.7.0")
    assert entry["manifest_hash"] == trust.canonical_sha256(envelope_one["signed"])
    assert entry["rekor_uuid"] is None and entry["log_index"] is None

    envelope_two = {"signed": _manifest_signed(version="0.7.1", sequence=2, digest_prefix="bb")}
    index_two = trust.append_index_entry(
        index_one, envelope_two, issued_at="2026-02-05T00:00:00Z",
        rekor_uuid="242960cdeadbeef", log_index=12345,
    )
    assert index_two["version"] == 2
    assert trust.last_sequence(index_two, "stable") == 2
    assert trust.index_entry_for(index_two, "stable", "0.7.1")["log_index"] == 12345

    # Sequences are independent per release line.
    beta = {"signed": _manifest_signed(line="desktop-beta", version="0.6.0-beta.2",
                                       sequence=1, digest_prefix="cc")}
    index_three = trust.append_index_entry(index_two, beta, issued_at="2026-02-06T00:00:00Z")
    assert trust.last_sequence(index_three, "desktop-beta") == 1
    assert trust.last_sequence(index_three, "stable") == 2


def test_release_index_rejects_duplicates_and_sequence_gaps():
    first = {"signed": _manifest_signed(version="0.7.0", sequence=1, digest_prefix="aa")}
    index = trust.append_index_entry(None, first, issued_at="2026-02-01T00:00:00Z")
    duplicate_version = {"signed": _manifest_signed(version="0.7.0", sequence=2,
                                                    digest_prefix="dd")}
    with pytest.raises(trust.MetadataError):
        trust.append_index_entry(index, duplicate_version, issued_at="2026-02-02T00:00:00Z")
    gap = {"signed": _manifest_signed(version="0.7.1", sequence=3, digest_prefix="ee")}
    with pytest.raises(trust.MetadataError):
        trust.append_index_entry(index, gap, issued_at="2026-02-02T00:00:00Z")
    # A tampered index that lists the same manifest hash under a different
    # sequence is rejected directly by the index schema validator.
    tampered_index = json.loads(json.dumps(index))
    tampered_index["lines"]["stable"].append(
        {
            "version": "0.7.2",
            "sequence": 1,
            "manifest_hash": trust.canonical_sha256(first["signed"]),
            "rekor_uuid": None,
            "log_index": None,
        }
    )
    with pytest.raises(trust.MetadataError):
        trust.validate_release_index(tampered_index)


def test_release_index_validator_rejects_bad_shapes():
    first = {"signed": _manifest_signed(version="0.7.0", sequence=1)}
    good = trust.append_index_entry(None, first, issued_at="2026-02-01T00:00:00Z")
    with pytest.raises(trust.MetadataError):
        trust.validate_release_index(dict(good, version=0))
    missing_line = dict(good)
    missing_line["lines"] = {"stable": good["lines"]["stable"]}
    with pytest.raises(trust.MetadataError):
        trust.validate_release_index(missing_line)
    bad = json.loads(json.dumps(good))
    bad["lines"]["stable"][0]["rekor_uuid"] = "uuid-x"
    with pytest.raises(trust.MetadataError):
        trust.validate_release_index(bad)
    bad2 = json.loads(json.dumps(good))
    bad2["lines"]["stable"][0]["log_index"] = -3
    with pytest.raises(trust.MetadataError):
        trust.validate_release_index(bad2)


def test_index_verifies_against_manifest_and_detects_tampering():
    signed = _manifest_signed(version="0.7.0", sequence=1)
    envelope = {"signed": signed}
    index = trust.append_index_entry(None, envelope, issued_at="2026-02-01T00:00:00Z")
    assert trust.verify_index_against_manifest(index, envelope)["version"] == "0.7.0"

    with pytest.raises(trust.MetadataError):
        trust.verify_index_against_manifest(
            index, {"signed": _manifest_signed(version="0.8.0", sequence=2)}
        )
    tampered = json.loads(json.dumps(signed))
    tampered["source"]["commit"] = "f" * 40
    with pytest.raises(trust.DigestError):
        trust.verify_index_against_manifest(index, {"signed": tampered})
    sequence_mismatch = json.loads(json.dumps(signed))
    sequence_mismatch["sequence"] = 2
    with pytest.raises(trust.MetadataError):
        trust.verify_index_against_manifest(index, {"signed": sequence_mismatch})


def test_release_index_is_signed_by_the_release_role():
    pairs, keyids, keys = _root_keys("root-a", "release-a", "release-b", "revocation-a")
    roles = _roles(keyids, release_threshold=2)
    root = _root_signed(1, keys, roles)
    envelope = {"signed": _manifest_signed(version="0.7.0", sequence=1)}
    index_signed = trust.append_index_entry(None, envelope, issued_at="2026-02-01T00:00:00Z")

    good = trust.seal_envelope(index_signed, [pairs["release-a"][0], pairs["release-b"][0]])
    assert trust.verify_index_signature(good, root)
    single = trust.seal_envelope(index_signed, [pairs["release-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_index_signature(single, root)
    # A revocation key must not be able to publish an index.
    wrong_role = trust.seal_envelope(index_signed, [pairs["revocation-a"][0]])
    with pytest.raises(trust.SignatureError):
        trust.verify_index_signature(wrong_role, root)
