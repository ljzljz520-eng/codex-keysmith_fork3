"""TR-10: verify_release.py full fail-closed pipeline and standalone form."""

import ast
import hashlib
import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import keysmith_trust as trust
from scripts import verify_release as verifier

REPO_ROOT = Path(__file__).resolve().parents[1]
ISSUED = "2026-07-18T10:00:00Z"
ROOT_EXPIRES = "2027-07-18T10:00:00Z"
REV_ISSUED = "2026-09-01T10:00:00Z"
REV_EXPIRES = "2026-12-31T10:00:00Z"
REV_EXPIRED = "2026-10-01T10:00:00Z"


def _seed(label):
    return hashlib.sha256(label.encode("ascii")).digest()


def _keyid(label):
    return trust.ed25519_key_id(trust.ed25519_public_from_seed(_seed(label)))


def _rekor_helpers():
    helper_path = REPO_ROOT / "tests" / "test_rekor_verify.py"
    spec = importlib.util.spec_from_file_location("trv_verify_helpers", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------
# Metadata ceremony helpers
# ---------------------------------------------------------------------------


def _role(label):
    return {"keyids": [_keyid(label)], "threshold": 1}


def _root_envelope(
    *,
    version=1,
    root_labels=("root1",),
    release_labels=("rel1",),
    revocation_labels=("rev1",),
    rekor_pems=(),
):
    all_labels = set(root_labels) | set(release_labels) | set(revocation_labels)
    keys = {
        _keyid(label): {
            "keytype": trust.ED25519_KEYTYPE,
            "public": trust.ed25519_public_from_seed(_seed(label)).hex(),
        }
        for label in all_labels
    }
    roles = {
        trust.ROLE_ROOT: {
            "keyids": [_keyid(label) for label in root_labels],
            "threshold": 1,
        },
        trust.ROLE_RELEASE: {
            "keyids": [_keyid(label) for label in release_labels],
            "threshold": 1,
        },
        trust.ROLE_REVOCATION: {
            "keyids": [_keyid(label) for label in revocation_labels],
            "threshold": 1,
        },
    }
    rekor_keys = [
        {
            "keyid": trust.REKOR_KEYID_PREFIX
            + trust.rekor_log_id_from_pem(pem.encode("ascii")),
            "keytype": trust.REKOR_KEYTYPE,
            "public_pem": pem,
        }
        for pem in rekor_pems
    ]
    signed = trust.make_root_signed(
        version=version,
        roles=roles,
        keys=keys,
        expires=ROOT_EXPIRES,
        rekor_keys=rekor_keys,
    )
    return trust.seal_envelope(
        signed, [_seed(label) for label in root_labels]
    )


def _revocations_envelope(
    *,
    version=1,
    root_labels=("rev1",),
    revoked_keys=(),
    revoked_releases=(),
    revoked_artifacts=(),
    expires=REV_EXPIRES,
):
    signed = {
        "_type": trust.REVOCATIONS_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "version": version,
        "issued_at": REV_ISSUED,
        "expires": expires,
        "revoked_keys": list(revoked_keys),
        "revoked_releases": list(revoked_releases),
        "revoked_artifacts": list(revoked_artifacts),
    }
    trust.validate_revocations(signed)
    return trust.seal_envelope(signed, [_seed(label) for label in root_labels])


def _revoked_key(label, reason="compromise"):
    return {
        "keyid": _keyid(label),
        "reason": reason,
        "revoked_at": REV_ISSUED,
    }


def _revoked_release(
    version,
    *,
    line=trust.STABLE_LINE,
    to_version=None,
    severity="high",
    reason="known-vulnerable",
    fixed_version=None,
    security_exception_allowed=False,
):
    return {
        "release_line": line,
        "version": version,
        "to_version": to_version,
        "severity": severity,
        "reason": reason,
        "fixed_version": fixed_version,
        "security_exception_allowed": security_exception_allowed,
        "revoked_at": REV_ISSUED,
    }


def _revoked_artifact(digest, reason="malicious"):
    return {"sha256": digest, "reason": reason, "revoked_at": REV_ISSUED}


# ---------------------------------------------------------------------------
# Release directory factory
# ---------------------------------------------------------------------------


def _core_names(tag):
    return (
        "codex-keysmith-{}.zip".format(tag),
        "codex-keysmith-{}.tar.gz".format(tag),
        "codex-instruct-{}.py".format(tag),
        "codex-keysmith-scenarios-{}.bundle".format(tag),
    )


def _valid_spdx():
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "codex-keysmith",
    }


def _valid_cdx():
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}


@pytest.fixture()
def factory(tmp_path):
    created = []

    def make(
        *,
        version="0.7.0",
        sequence=1,
        line=trust.STABLE_LINE,
        signer="rel1",
        root_env=None,
        previous_index_signed=None,
        revocations_env=None,
        include_root=True,
        rekor=False,
        spdx_doc=None,
        cdx_doc=None,
        build_manifest_docs=None,
        source_repo="local",
        source_commit="a" * 40,
        required_root_version=1,
        required_revocations_version=0,
        release_dir_name="release",
        skip_files=(),
        extra_files=None,
    ):
        root_env = root_env or _root_envelope()
        tag = trust.expected_tag_for(line, version)
        release_dir = tmp_path / release_dir_name
        trust_dir = tmp_path / "trust"
        release_dir.mkdir(parents=True, exist_ok=True)

        core = _core_names(tag)
        contents = {name: "{}:{}:content\n".format(name, sequence).encode() for name in core}
        for name, data in contents.items():
            (release_dir / name).write_bytes(data)
        checksum_lines = [
            "{}  {}".format(hashlib.sha256(contents[name]).hexdigest(), name)
            for name in sorted(contents)
        ]
        checksums = ("\n".join(checksum_lines) + "\n").encode("ascii")
        (release_dir / "SHA256SUMS").write_bytes(checksums)

        verifier_name = "verify-release-{}.py".format(tag)
        (release_dir / verifier_name).write_text(
            "#!/usr/bin/env python3\n# standalone verifier for {}\n".format(tag)
        )

        spdx_name = "codex-keysmith-{}-sbom.spdx.json".format(tag)
        cdx_name = "codex-keysmith-{}-sbom.cdx.json".format(tag)
        (release_dir / spdx_name).write_bytes(
            json.dumps(spdx_doc or _valid_spdx(), sort_keys=True).encode() + b"\n"
        )
        (release_dir / cdx_name).write_bytes(
            json.dumps(cdx_doc or _valid_cdx(), sort_keys=True).encode() + b"\n"
        )

        build_manifests = {}
        for name, document in (build_manifest_docs or {}).items():
            data = json.dumps(document, sort_keys=True).encode() + b"\n"
            (release_dir / name).write_bytes(data)
            build_manifests[name] = hashlib.sha256(data).hexdigest()

        def record(name):
            data = (release_dir / name).read_bytes()
            return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

        artifacts = {name: record(name) for name in list(core) + ["SHA256SUMS", verifier_name]}
        sboms = {spdx_name: record(spdx_name), cdx_name: record(cdx_name)}

        manifest = {
            "_type": trust.RELEASE_TYPE,
            "spec_version": trust.SPEC_VERSION,
            "product": trust.PRODUCT,
            "release_line": line,
            "version": version,
            "tag": tag,
            "sequence": sequence,
            "issued_at": ISSUED,
            "source": {
                "repo": source_repo,
                "commit": source_commit,
                "tag_object": "b" * 40,
            },
            "builder": {
                "workflow_name": "release.yml",
                "workflow_ref": "refs/tags/{}".format(tag),
                "workflow_sha": "c" * 40,
                "runner": "ubuntu-24.04",
                "python_version": "3.11.9",
                "node_version": "",
                "rust_version": "",
                "pyinstaller_version": "",
                "build_manifests": build_manifests,
            },
            "artifacts": artifacts,
            "sboms": sboms,
            "required_root_version": required_root_version,
            "required_revocations_version": required_revocations_version,
        }
        trust.validate_release_manifest(manifest)
        manifest_env = trust.seal_envelope(manifest, [_seed(signer)])

        helpers = _rekor_helpers()
        entry = None
        rekor_uuid = None
        log_index = None
        if rekor:
            payload = trust.signed_payload_bytes(manifest_env)
            entry, log_pem, _pem, _root_hash = helpers.make_entry(
                artifact=payload, artifact_scheme="p256"
            )
            root_env = _root_envelope(rekor_pems=[log_pem])
            rekor_uuid = "1" * 64 + "2" * 16
            log_index = entry["logIndex"]
            (release_dir / verifier.REKOR_ENTRY_NAME).write_bytes(
                json.dumps(entry, sort_keys=True).encode()
            )

        index_signed = trust.append_index_entry(
            previous_index_signed,
            manifest_env,
            issued_at=ISSUED,
            rekor_uuid=rekor_uuid,
            log_index=log_index,
        )
        index_env = trust.seal_envelope(index_signed, [_seed(signer)])

        if include_root:
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
        for name in skip_files:
            (release_dir / name).unlink()
        for name, data in (extra_files or {}).items():
            (release_dir / name).write_bytes(data)

        bundle = {
            "release_dir": release_dir,
            "trust_dir": trust_dir,
            "manifest_env": manifest_env,
            "manifest": manifest,
            "index_env": index_env,
            "index_signed": index_signed,
            "root_env": root_env,
            "entry": entry,
            "tag": tag,
            "names": {
                "core": core,
                "verifier": verifier_name,
                "spdx": spdx_name,
                "cdx": cdx_name,
            },
        }
        created.append(bundle)
        return bundle

    yield make


def _verify(bundle, **overrides):
    kwargs = dict(
        release_dir=bundle["release_dir"],
        trust_dir=bundle["trust_dir"],
    )
    kwargs.update(overrides)
    return verifier.verify_release(**kwargs)


def _expect_rejected(bundle, exit_code, stage=None, **overrides):
    with pytest.raises(verifier.VerificationError) as info:
        _verify(bundle, **overrides)
    assert info.value.exit_code == exit_code, info.value
    if stage is not None:
        assert info.value.stage == stage
    return info.value


# ---------------------------------------------------------------------------
# TR-10.1 happy path and tamper matrix (AC-1)
# ---------------------------------------------------------------------------


def test_baseline_tofu_accepts_and_persists_state(factory):
    bundle = factory()
    result = _verify(bundle)
    assert result["ok"] is True
    assert result["action"] == trust.ACTION_TOFU
    assert result["root_version"] == 1
    assert result["tofu"] is True
    state = trust.load_state(bundle["trust_dir"])
    accepted = state["lines"][trust.STABLE_LINE]["accepted"]
    assert accepted["version"] == "0.7.0"
    assert accepted["sequence"] == 1
    assert accepted["manifest_hash"] == result["manifest_hash"]
    audit = list(trust.iter_audit_entries(bundle["trust_dir"] / "audit.jsonl"))
    events = {entry["event"] for entry in audit}
    assert "tofu" in events
    assert "root-tofu" in events
    assert any("fingerprint" in warning for warning in result["warnings"])


def test_tamper_matrix_flips_or_drops_every_bound_input(factory):
    cases = []
    bundle = factory()
    core_name = bundle["names"]["core"][0]
    sbom_name = bundle["names"]["spdx"]

    # Flip a byte in a core artifact.
    b = factory(release_dir_name="r-core")
    path = b["release_dir"] / core_name
    path.write_bytes(path.read_bytes() + b"X")
    cases.append((b, trust.EXIT_DIGEST))

    # Replace SHA256SUMS (the manifest binds its digest).
    b = factory(release_dir_name="r-sums")
    path = b["release_dir"] / "SHA256SUMS"
    path.write_bytes(path.read_bytes() + b"0" * 64 + b"  spoof\n")
    cases.append((b, trust.EXIT_DIGEST))

    # Tamper a signed manifest field without re-signing.
    b = factory(release_dir_name="r-man")
    env = json.loads((b["release_dir"] / "release-manifest.json").read_text())
    env["signed"]["sequence"] = 99
    (b["release_dir"] / "release-manifest.json").write_bytes(
        trust.canonical_json_bytes(env)
    )
    cases.append((b, trust.EXIT_SIGNATURE))

    # Tamper the index without re-signing.
    b = factory(release_dir_name="r-idx")
    env = json.loads((b["release_dir"] / "release-index.json").read_text())
    env["signed"]["version"] = 99
    (b["release_dir"] / "release-index.json").write_bytes(
        trust.canonical_json_bytes(env)
    )
    cases.append((b, trust.EXIT_SIGNATURE))

    # Flip a byte in an SBOM.
    b = factory(release_dir_name="r-sbom")
    path = b["release_dir"] / sbom_name
    path.write_bytes(path.read_bytes() + b" ")
    cases.append((b, trust.EXIT_DIGEST))

    # Drop a bound file.
    b = factory(release_dir_name="r-missing", skip_files=(b["names"]["verifier"],))
    cases.append((b, trust.EXIT_DIGEST))

    # An unlisted file appears in the directory.
    b = factory(
        release_dir_name="r-extra",
        extra_files={"evil-extra.zip": b"unlisted content"},
    )
    cases.append((b, trust.EXIT_DIGEST))

    # A symlink in the release directory is refused at the artifact layer.
    b = factory(release_dir_name="r-link")
    (b["release_dir"] / "link.zip").symlink_to(
        b["release_dir"] / core_name
    )
    cases.append((b, trust.EXIT_DIGEST))

    for b, expected in cases:
        exc = _expect_rejected(b, expected)
        # No failure may advance the water-mark.
        assert not (b["trust_dir"] / "state.json").exists()
        assert "water-mark" not in str(exc) or expected == trust.EXIT_DOWNGRADE


def test_sbom_shape_mismatch_rejected_after_hash_matches(factory):
    # The manifest honestly binds a document that is not a valid SPDX 2.3 doc:
    # the digest matches, so only the structural binding can catch it.
    bundle = factory(spdx_doc={"spdxVersion": "SPDX-2.2", "SPDXID": "SPDXRef-DOCUMENT"})
    exc = _expect_rejected(bundle, trust.EXIT_DIGEST)
    assert "SPDX-2.3" in str(exc)


def test_sha256sums_internal_disagreement_rejected(factory):
    bundle = factory()
    path = bundle["release_dir"] / "SHA256SUMS"
    lines = path.read_text().splitlines()
    name = bundle["names"]["core"][0]
    lines = [
        ("0" * 64 + "  " + name) if line.endswith(name) else line for line in lines
    ]
    # Rebind SHA256SUMS itself so the outer digest layer passes and only the
    # internal cross-check can fail.
    path.write_text("\n".join(lines) + "\n")
    env = json.loads((bundle["release_dir"] / "release-manifest.json").read_text())
    env["signed"]["artifacts"]["SHA256SUMS"] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": len(path.read_bytes()),
    }
    resealed = trust.seal_envelope(env["signed"], [_seed("rel1")])
    (bundle["release_dir"] / "release-manifest.json").write_bytes(
        trust.canonical_json_bytes(resealed)
    )
    index_signed = trust.append_index_entry(None, resealed, issued_at=ISSUED)
    (bundle["release_dir"] / "release-index.json").write_bytes(
        trust.canonical_json_bytes(trust.seal_envelope(index_signed, [_seed("rel1")]))
    )
    exc = _expect_rejected(bundle, trust.EXIT_DIGEST)
    assert "signed manifest" in str(exc)


def test_desktop_build_manifest_digest_binding(factory):
    document = {"target": "x86_64-apple-darwin", "source_commit": "a" * 40}
    bundle = factory(
        line=trust.DESKTOP_BETA_LINE,
        version="0.6.0-beta.3",
        build_manifest_docs={"build-manifest-macos.json": document},
    )
    result = _verify(bundle)
    assert result["line"] == trust.DESKTOP_BETA_LINE
    tampered = factory(
        line=trust.DESKTOP_BETA_LINE,
        version="0.6.0-beta.3",
        release_dir_name="desktop-bad",
        build_manifest_docs={"build-manifest-macos.json": document},
    )
    target = tampered["release_dir"] / "build-manifest-macos.json"
    target.write_bytes(target.read_bytes() + b" ")
    _expect_rejected(tampered, trust.EXIT_DIGEST)


# ---------------------------------------------------------------------------
# TR-10.2 rotation, revocation, water-mark and override branches
# ---------------------------------------------------------------------------


def test_upgrade_path_and_reinstall(factory):
    first = factory(version="0.7.0", sequence=1)
    _verify(first)
    second = factory(
        version="0.7.1",
        sequence=2,
        previous_index_signed=first["index_signed"],
        release_dir_name="release2",
    )
    result = _verify(second, trust_dir=first["trust_dir"])
    assert result["action"] == trust.ACTION_UPGRADE
    # Re-verifying the same release is a reinstall, not an upgrade/downgrade.
    again = _verify(second, trust_dir=first["trust_dir"])
    assert again["action"] == trust.ACTION_REINSTALL


def test_downgrade_requires_explicit_override_and_records_reason(factory):
    older = factory(version="0.7.0", sequence=1, release_dir_name="old")
    _verify(older)
    newer = factory(
        version="0.7.1",
        sequence=2,
        previous_index_signed=older["index_signed"],
        release_dir_name="new",
    )
    _verify(newer, trust_dir=older["trust_dir"])
    # The older release directory carries its stale index v1; the verifier
    # pins against the freshest cached index and leaves the decision to the
    # water-mark layer.
    _expect_rejected(
        older, trust.EXIT_DOWNGRADE, trust_dir=older["trust_dir"]
    )
    # Wrong version token in the override does not authorise it.
    _expect_rejected(
        older,
        trust.EXIT_DOWNGRADE,
        trust_dir=older["trust_dir"],
        allow_downgrade="9.9.9",
        downgrade_reason="testing rollback",
    )
    result = _verify(
        older,
        trust_dir=older["trust_dir"],
        allow_downgrade="0.7.0",
        downgrade_reason="bisecting a regression",
    )
    assert result["action"] == trust.ACTION_DOWNGRADE_OVERRIDE
    audit = list(trust.iter_audit_entries(older["trust_dir"] / "audit.jsonl"))
    downgrade_entries = [e for e in audit if e["event"] == "accept-downgrade"]
    assert len(downgrade_entries) == 1
    entry = downgrade_entries[0]
    assert entry["from_version"] == "0.7.1"
    assert entry["to_version"] == "0.7.0"
    assert entry["manifest_hash"] == result["manifest_hash"]
    assert entry["reason"] == "bisecting a regression"
    assert entry["time"].endswith("Z")


def test_revoked_release_plain_downgrade_override_is_insufficient(factory):
    revoked = _revocations_envelope(
        revoked_releases=[
            _revoked_release(
                "0.7.0",
                fixed_version="0.7.1",
                security_exception_allowed=True,
            )
        ]
    )
    bundle = factory(revocations_env=revoked, release_dir_name="revoked")
    _expect_rejected(bundle, trust.EXIT_REVOKED)
    _expect_rejected(
        bundle,
        trust.EXIT_REVOKED,
        allow_downgrade="0.7.0",
        downgrade_reason="rollback",
    )
    # Exact-version security exception with a written reason is accepted.
    result = _verify(
        bundle,
        accept_revoked="0.7.0",
        revoked_reason="isolated offline lab, no network exposure",
    )
    assert result["action"] == trust.ACTION_SECURITY_EXCEPTION
    state = trust.load_state(bundle["trust_dir"])
    exceptions = state["lines"][trust.STABLE_LINE]["security_exceptions"]
    assert len(exceptions) == 1
    assert any("active security exception" in w for w in result["warnings"])
    # A second verification reuses the persisted exception (no duplicate).
    again = _verify(
        bundle,
        accept_revoked="0.7.0",
        revoked_reason="isolated offline lab, no network exposure",
    )
    assert again["action"] == trust.ACTION_SECURITY_EXCEPTION
    state = trust.load_state(bundle["trust_dir"])
    assert len(state["lines"][trust.STABLE_LINE]["security_exceptions"]) == 1


def test_revoked_release_without_exception_remains_closed(factory):
    revoked = _revocations_envelope(
        revoked_releases=[
            _revoked_release("0.7.0", fixed_version="0.7.1")
        ]
    )
    bundle = factory(revocations_env=revoked, release_dir_name="noexception")
    _expect_rejected(bundle, trust.EXIT_REVOKED)
    _expect_rejected(
        bundle,
        trust.EXIT_REVOKED,
        accept_revoked="0.7.0",
        revoked_reason="please",
    )


def test_revoked_signing_key_rejected(factory):
    root = _root_envelope(release_labels=("rel1", "rel2"))
    revoked = _revocations_envelope(revoked_keys=[_revoked_key("rel1")])
    bundle = factory(
        root_env=root,
        signer="rel1",
        revocations_env=revoked,
        release_dir_name="revokedkey",
    )
    exc = _expect_rejected(bundle, trust.EXIT_REVOKED)
    assert "revoked release key" in str(exc)


def test_revoked_artifact_digest_rejected(factory):
    bundle = factory(release_dir_name="seed")
    target_name = bundle["names"]["core"][0]
    digest = bundle["manifest"]["artifacts"][target_name]["sha256"]
    revoked = _revocations_envelope(
        revoked_artifacts=[_revoked_artifact(digest)]
    )
    victim = factory(revocations_env=revoked, release_dir_name="revart")
    _expect_rejected(victim, trust.EXIT_REVOKED)


def test_expired_revocations_warn_but_still_revoke(factory):
    expired = _revocations_envelope(
        expires=REV_EXPIRED,
        revoked_releases=[_revoked_release("0.7.0")],
    )
    bundle = factory(revocations_env=expired, release_dir_name="expired")
    exc = _expect_rejected(bundle, trust.EXIT_REVOKED)
    assert "revoked" in str(exc)
    # Expiry without a matching revocation is only a warning.
    harmless = _revocations_envelope(expires=REV_EXPIRED)
    ok = factory(revocations_env=harmless, release_dir_name="expired-warn")
    result = _verify(ok)
    assert any("expired" in w for w in result["warnings"])


def test_root_rotation_accepts_old_and_new_then_refuses_rollback(factory):
    root1 = _root_envelope(version=1, root_labels=("root1",))
    first = factory(version="0.7.0", sequence=1, root_env=root1)
    _verify(first)

    root2 = _root_envelope(
        version=2,
        root_labels=("root1", "root2"),
        release_labels=("rel2",),
    )
    # root2 is sealed by the old root key (threshold 1) and self-signed too.
    second = factory(
        version="0.7.1",
        sequence=2,
        root_env=root2,
        signer="rel2",
        previous_index_signed=first["index_signed"],
        required_root_version=2,
        release_dir_name="rotated",
    )
    result = _verify(second, trust_dir=first["trust_dir"])
    assert result["root_version"] == 2

    # Feeding the stale v1 root again must not silently replace the pin.
    stale = factory(
        version="0.7.0",
        sequence=1,
        root_env=root1,
        release_dir_name="rollback",
    )
    _expect_rejected(stale, trust.EXIT_SIGNATURE, trust_dir=first["trust_dir"])


def test_pre_rotation_release_verifies_via_retained_root_history(factory):
    root1 = _root_envelope(version=1, root_labels=("root1",))
    first = factory(version="0.7.0", sequence=1, root_env=root1)
    _verify(first)

    root2 = _root_envelope(
        version=2,
        root_labels=("root1", "root2"),
        release_labels=("rel2",),
    )
    second = factory(
        version="0.7.1",
        sequence=2,
        root_env=root2,
        signer="rel2",
        previous_index_signed=first["index_signed"],
        required_root_version=2,
        release_dir_name="rotated",
    )
    _verify(second, trust_dir=first["trust_dir"])

    # Every accepted root version is retained immutably.
    assert (first["trust_dir"] / "root.v1.json").exists()
    assert (first["trust_dir"] / "root.v2.json").exists()
    audit = list(trust.iter_audit_entries(first["trust_dir"] / "audit.jsonl"))
    events = {entry["event"] for entry in audit}
    assert "root-rotated" in events

    # The rel1-signed 0.7.0 directory no longer feeds root.json: no rolled-back
    # root is accepted, yet its release-era signature still validates via the
    # retained root v1 role table. Signature/index/artifacts all pass; only
    # the water-mark layer stands in the way.
    (first["release_dir"] / verifier.ROOT_BUNDLE_NAME).unlink()
    _expect_rejected(first, trust.EXIT_DOWNGRADE, trust_dir=first["trust_dir"])
    result = _verify(
        first,
        trust_dir=first["trust_dir"],
        allow_downgrade="0.7.0",
        downgrade_reason="archived release audit",
    )
    assert result["action"] == trust.ACTION_DOWNGRADE_OVERRIDE
    assert any("retained root v1" in warning for warning in result["warnings"])

    # Losing the retained history fails closed at the root layer.
    (first["trust_dir"] / "root.v1.json").unlink()
    _expect_rejected(
        first,
        trust.EXIT_SIGNATURE,
        trust_dir=first["trust_dir"],
        allow_downgrade="0.7.0",
        downgrade_reason="archived release audit",
    )


def test_root_rotation_requires_old_threshold_signature(factory):
    root1 = _root_envelope(version=1)
    # v2 self-signed only by the brand-new root2 key: invalid rotation.
    forged = _root_envelope(
        version=2, root_labels=("root2",), release_labels=("rel1",)
    )
    bundle = factory(root_env=forged, release_dir_name="badrotate")
    _expect_rejected(bundle, trust.EXIT_SIGNATURE)
    # Pinned v1 survives untouched.
    good = factory(root_env=root1, release_dir_name="still-good")
    assert _verify(good)["root_version"] == 1


def test_manifest_required_root_version_enforced(factory):
    root1 = _root_envelope(version=1)
    bundle = factory(root_env=root1, required_root_version=2)
    _expect_rejected(bundle, trust.EXIT_SIGNATURE)


def test_index_pinning_detects_manifest_replacement(factory):
    # Two same-version manifests with different signed content; the index
    # pins exactly one canonical hash.
    root = _root_envelope(release_labels=("rel1", "rel2"))
    factory(root_env=root, signer="rel1", release_dir_name="a")
    bundle_b = factory(
        root_env=root,
        signer="rel2",
        source_commit="d" * 40,
        release_dir_name="b",
    )
    # A's directory but B's manifest: the index from A pins A's hash.
    merged = factory(root_env=root, signer="rel1", release_dir_name="merged")
    (merged["release_dir"] / verifier.SIGNED_MANIFEST_NAME).write_bytes(
        trust.canonical_json_bytes(bundle_b["manifest_env"])
    )
    exc = _expect_rejected(merged, trust.EXIT_DIGEST)
    assert exc.stage == "index"


def test_tag_and_line_cross_checks(factory):
    bundle = factory()
    _expect_rejected(bundle, trust.EXIT_SIGNATURE, expected_tag="v9.9.9")
    _expect_rejected(
        bundle, trust.EXIT_SIGNATURE, expected_line=trust.DESKTOP_BETA_LINE
    )
    result = _verify(bundle, expected_tag="v0.7.0", expected_line=trust.STABLE_LINE)
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# TR-10.3 online surfaces: injection fakes, never real network
# ---------------------------------------------------------------------------


def test_refresh_online_verifies_remote_tag_and_uses_channel_metadata(factory):
    bundle = factory(
        source_repo="https://github.com/example/codex-keysmith.git"
    )
    calls = []

    def fetch(url):
        calls.append(url)
        if url.endswith("root.1.json"):
            return trust.canonical_json_bytes(bundle["root_env"])
        if url.endswith("release-index.json"):
            return trust.canonical_json_bytes(bundle["index_env"])
        raise verifier.OnlineNotFound(url)

    def git_ls_remote(repo, tag):
        calls.append((repo, tag))
        return "b" * 40, "a" * 40

    result = _verify(
        bundle,
        refresh_online=True,
        online={"fetch": fetch, "git_ls_remote": git_ls_remote},
    )
    assert result["ok"] is True
    assert any(isinstance(c, tuple) for c in calls)

    def bad_remote(repo, tag):
        return "f" * 40, "a" * 40

    victim = factory(
        source_repo="https://github.com/example/codex-keysmith.git",
        release_dir_name="online-bad",
    )
    _expect_rejected(
        victim,
        trust.EXIT_SIGNATURE,
        refresh_online=True,
        online={"fetch": fetch, "git_ls_remote": bad_remote},
    )


def test_rekor_entry_offline_verification_and_tree_watermark(factory):
    bundle = factory(rekor=True, release_dir_name="rekor-ok")
    result = _verify(bundle, use_rekor=True)
    assert result["rekor"]["status"] == "verified"
    assert result["rekor"]["log_index"] == bundle["entry"]["logIndex"]
    state = trust.load_state(bundle["trust_dir"])
    assert (
        state["lines"][trust.STABLE_LINE]["rekor_tree_size"] == 7
    )  # synthetic tree size from make_entry default

    # A second release presenting a smaller tree is refused (TR-5 binding).
    second = factory(
        version="0.7.1",
        sequence=2,
        rekor=True,
        previous_index_signed=bundle["index_signed"],
        release_dir_name="rekor-small",
    )
    helpers = _rekor_helpers()
    small_entry, _log_pem, _pem, _root = helpers.make_entry(
        artifact=trust.signed_payload_bytes(second["manifest_env"]),
        artifact_scheme="p256",
        tree_size=3,
        leaf_index=1,
    )
    # Re-pin the index log_index to the small entry and re-sign.
    index_signed = trust.append_index_entry(
        bundle["index_signed"],
        second["manifest_env"],
        issued_at=ISSUED,
        rekor_uuid="1" * 80,
        log_index=small_entry["logIndex"],
    )
    (second["release_dir"] / verifier.INDEX_NAME).write_bytes(
        trust.canonical_json_bytes(trust.seal_envelope(index_signed, [_seed("rel1")]))
    )
    (second["release_dir"] / verifier.REKOR_ENTRY_NAME).write_bytes(
        json.dumps(small_entry, sort_keys=True).encode()
    )
    _expect_rejected(
        second, trust.EXIT_REKOR, use_rekor=True, trust_dir=bundle["trust_dir"]
    )


def test_rekor_flag_without_entry_is_rekor_layer_failure(factory):
    bundle = factory(rekor=False)
    _expect_rejected(bundle, trust.EXIT_REKOR, use_rekor=True)


def test_default_path_opens_no_sockets(factory, monkeypatch):
    bundle = factory()

    def refuse(*args, **kwargs):
        raise AssertionError("verification must not open sockets offline")

    monkeypatch.setattr(socket, "socket", refuse)
    for name in list(sys.modules):
        if name.startswith(("urllib", "http", "ssl")):
            monkeypatch.setitem(sys.modules, name, None)
    result = _verify(bundle)
    assert result["rekor"]["status"] == "skipped"
    assert any("transparency log was not checked" in w for w in result["warnings"])


def test_verifier_has_no_top_level_network_imports():
    source = (REPO_ROOT / "scripts" / "verify_release.py").read_text("utf-8")
    tree = ast.parse(source)
    top_level = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level.add(node.module.split(".")[0])
    assert not (top_level & {"urllib", "socket", "http", "ssl", "subprocess"})
    for forbidden in ("import requests",):
        assert forbidden not in source


# ---------------------------------------------------------------------------
# TR-10.4 standalone single-file form
# ---------------------------------------------------------------------------


def _compose_standalone():
    spec = importlib.util.spec_from_file_location(
        "build_release_standalone", REPO_ROOT / "scripts" / "build_release.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module._verifier_standalone_bytes(
        (REPO_ROOT / "scripts" / "verify_release.py").read_bytes(),
        (REPO_ROOT / "scripts" / "keysmith_trust.py").read_bytes(),
        (REPO_ROOT / "LICENSE").read_bytes(),
    )


def test_standalone_runs_version_outside_source_tree(tmp_path, factory):
    bundle = factory()
    standalone_dir = tmp_path / "standalone-dist"
    standalone_dir.mkdir()
    standalone = standalone_dir / "verify-release-v0.7.0.py"
    standalone.write_bytes(_compose_standalone())
    cwd = tmp_path / "isolated-cwd"
    cwd.mkdir()
    env = dict(PATH="/usr/bin:/bin", HOME=str(tmp_path / "home"))
    version_run = subprocess.run(
        [sys.executable, str(standalone), "--version"],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert version_run.returncode == 0
    assert b"verify-release" in version_run.stdout
    assert b"embedded" in version_run.stdout

    run = subprocess.run(
        [
            sys.executable,
            str(standalone),
            "--release-dir",
            str(bundle["release_dir"]),
            "--trust-dir",
            str(bundle["trust_dir"]),
            "--json",
        ],
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert run.returncode == 0, run.stderr.decode()
    record = json.loads(run.stdout.decode())
    assert record["ok"] is True
    assert record["action"] == "tofu"


# ---------------------------------------------------------------------------
# TR-10.6 CLI ergonomics: machine output and argument misuse
# ---------------------------------------------------------------------------


def test_cli_json_success_and_failure(factory, capsys, tmp_path):
    bundle = factory()
    rc = verifier.main(
        [
            "--json",
            "--release-dir",
            str(bundle["release_dir"]),
            "--trust-dir",
            str(bundle["trust_dir"]),
        ]
    )
    assert rc == 0
    record = json.loads(capsys.readouterr().out)
    assert record["version"] == "0.7.0"

    victim = factory(release_dir_name="cli-bad")
    (victim["release_dir"] / "evil.zip").write_bytes(b"x")
    rc = verifier.main(
        [
            "--json",
            "--release-dir",
            str(victim["release_dir"]),
            "--trust-dir",
            str(victim["trust_dir"]),
        ]
    )
    assert rc == trust.EXIT_DIGEST
    record = json.loads(capsys.readouterr().out)
    assert record["ok"] is False
    assert record["exit_code"] == trust.EXIT_DIGEST
    assert "evil.zip" in record["error"]


def test_cli_override_argument_misuse(factory, capsys):
    bundle = factory()
    rc = verifier.main(
        [
            "--release-dir",
            str(bundle["release_dir"]),
            "--trust-dir",
            str(bundle["trust_dir"]),
            "--reason",
            "no override flag",
        ]
    )
    assert rc == trust.EXIT_GENERIC

    older = factory(version="0.7.0", sequence=1, release_dir_name="misuse-old")
    assert verifier.main(
        [
            "--release-dir",
            str(older["release_dir"]),
            "--trust-dir",
            str(older["trust_dir"]),
        ]
    ) == 0
    newer = factory(
        version="0.7.1",
        sequence=2,
        previous_index_signed=older["index_signed"],
        release_dir_name="misuse-new",
    )
    assert verifier.main(
        [
            "--release-dir",
            str(newer["release_dir"]),
            "--trust-dir",
            str(older["trust_dir"]),
        ]
    ) == 0
    rc = verifier.main(
        [
            "--release-dir",
            str(older["release_dir"]),
            "--trust-dir",
            str(older["trust_dir"]),
            "--allow-downgrade",
            "0.7.0",
        ]
    )
    assert rc == trust.EXIT_DOWNGRADE
