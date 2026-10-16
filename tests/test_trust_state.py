"""Tests for the local trust state store: water marks, audit, persistence."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from scripts import keysmith_trust as trust

NOW = "2026-02-10T00:00:00Z"


def _manifest(version="0.7.0", sequence=1, line="stable", *, digest_prefix="aa",
              issued_at="2026-02-01T00:00:00Z"):
    build_manifests = {}
    if line == "desktop-beta":
        build_manifests = {
            "codex-keysmith-{}-macos-build-manifest.json".format(version): "de" * 32,
            "codex-keysmith-{}-windows-build-manifest.json".format(version): "ef" * 32,
        }
    return trust.validate_release_manifest({
        "_type": trust.RELEASE_TYPE,
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": line,
        "version": version,
        "tag": trust.expected_tag_for(line, version),
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
            "codex-keysmith-v{}.spdx.json".format(version): {"sha256": "11" * 32, "size": 42},
            "codex-keysmith-v{}.cdx.json".format(version): {"sha256": "22" * 32, "size": 43},
        },
        "required_root_version": 1,
        "required_revocations_version": 0,
    })


def _accept(trust_dir, state, manifest, **kwargs):
    decision = trust.evaluate_acceptance(state, manifest, now_iso=NOW, **kwargs)
    trust.append_audit_line(
        trust.trust_audit_path(trust_dir), trust.decision_audit_entry(decision)
    )
    new_state = trust.commit_acceptance(state, decision)
    trust.save_state(trust_dir, new_state)
    return decision, new_state


# ---------------------------------------------------------------------------
# TR-4.1 water-mark matrix
# ---------------------------------------------------------------------------


def test_tofu_records_full_audit_trail(tmp_path):
    state = trust.empty_state()
    manifest = _manifest()
    decision, committed = _accept(tmp_path, state, manifest)
    assert decision["action"] == trust.ACTION_TOFU
    assert decision["from_version"] is None
    assert committed["lines"]["stable"]["accepted"]["version"] == "0.7.0"
    assert committed["lines"]["stable"]["accepted"]["manifest_hash"] == decision["manifest_hash"]

    events = list(trust.iter_audit_entries(trust.trust_audit_path(tmp_path)))
    assert len(events) == 1
    entry = events[0]
    assert entry["event"] == "tofu"
    assert entry["time"] == NOW
    assert entry["line"] == "stable"
    assert entry["to_version"] == "0.7.0"
    assert entry["to_sequence"] == 1
    assert len(entry["manifest_hash"]) == 64
    assert "from_version" not in entry


def test_upgrade_and_reinstall_paths(tmp_path):
    state = trust.empty_state()
    _, state = _accept(tmp_path, state, _manifest("0.7.0", 1, digest_prefix="aa"))
    decision, state = _accept(tmp_path, state, _manifest("0.7.1", 2, digest_prefix="bb"))
    assert decision["action"] == trust.ACTION_UPGRADE
    assert decision["from_version"] == "0.7.0"

    # Re-running the exact same manifest is a reinstall, not a downgrade.
    decision, _ = _accept(tmp_path, state, _manifest("0.7.1", 2, digest_prefix="bb"))
    assert decision["action"] == trust.ACTION_REINSTALL

    # Same version with a different hash is a forbidden in-place replacement.
    with pytest.raises(trust.StateError):
        trust.evaluate_acceptance(
            state, _manifest("0.7.1", 2, digest_prefix="cc"), now_iso=NOW
        )
    # A newer version riding on an older sequence is inconsistent and denied
    # even though semver looks like an upgrade.
    with pytest.raises(trust.DowngradeError):
        trust.evaluate_acceptance(
            state, _manifest("0.8.0", 1, digest_prefix="dd"), now_iso=NOW
        )


def test_downgrade_matrix(tmp_path):
    state = trust.empty_state()
    _, state = _accept(tmp_path, state, _manifest("0.7.1", 2, digest_prefix="bb"))
    older = _manifest("0.7.0", 1, digest_prefix="aa")

    with pytest.raises(trust.DowngradeError):
        trust.evaluate_acceptance(state, older, now_iso=NOW)
    # The failed attempt is auditable through the generic event writer.
    trust.record_trust_event(
        tmp_path, "deny-downgrade", time_iso=NOW, line="stable", to_version="0.7.0"
    )

    with pytest.raises(trust.DowngradeError):
        trust.evaluate_acceptance(
            state, older, now_iso=NOW, allow_downgrade="0.7.1",
            downgrade_reason="pin for compatibility audit",
        )
    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(
            state, older, now_iso=NOW, allow_downgrade="0.7.0", downgrade_reason="   "
        )
    decision, committed = _accept(
        tmp_path, state, older, allow_downgrade="0.7.0",
        downgrade_reason="pin for compatibility audit",
    )
    assert decision["action"] == trust.ACTION_DOWNGRADE_OVERRIDE
    assert committed["lines"]["stable"]["accepted"]["version"] == "0.7.0"
    events = list(trust.iter_audit_entries(trust.trust_audit_path(tmp_path)))
    downgrade_events = [event for event in events if event["event"] == "accept-downgrade"]
    assert len(downgrade_events) == 1
    assert downgrade_events[0]["reason"] == "pin for compatibility audit"
    assert downgrade_events[0]["from_version"] == "0.7.1"
    deny_events = [event for event in events if event["event"] == "deny-downgrade"]
    assert len(deny_events) == 1


def test_security_exception_persists_and_is_continuously_marked(tmp_path):
    state = trust.empty_state()
    manifest = _manifest("0.7.0", 1, digest_prefix="aa")
    allowed = {
        "release_line": "stable",
        "version": "0.7.0",
        "to_version": None,
        "severity": "high",
        "reason": "known CVE with a documented workaround",
        "fixed_version": "0.7.1",
        "security_exception_allowed": True,
        "revoked_at": "2026-02-02T00:00:00Z",
    }
    forbidden = dict(allowed, security_exception_allowed=False)

    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(state, manifest, now_iso=NOW, revoked_entry=allowed)
    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(
            state, manifest, now_iso=NOW, revoked_entry=allowed,
            accept_revoked="0.7.1", revoked_reason="workaround in place",
        )
    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(
            state, manifest, now_iso=NOW, revoked_entry=allowed,
            accept_revoked="0.7.0", revoked_reason="  ",
        )
    # A release whose policy forbids exceptions can never be accepted.
    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(
            state, manifest, now_iso=NOW, revoked_entry=forbidden,
            accept_revoked="0.7.0", revoked_reason="workaround in place",
        )

    decision, state = _accept(
        tmp_path, state, manifest, revoked_entry=allowed,
        accept_revoked="0.7.0", revoked_reason="air-gapped mitigation ticket INC-42",
    )
    assert decision["action"] == trust.ACTION_SECURITY_EXCEPTION
    assert not decision["previously_granted"]
    marker = trust.find_security_exception(
        state, "stable", "0.7.0", decision["manifest_hash"]
    )
    assert marker is not None and marker["reason"] == "air-gapped mitigation ticket INC-42"

    # Re-accepting requires the explicit flags again, but records that the
    # exception marker was already present and never duplicates it.
    repeat, state = _accept(
        tmp_path, state, manifest, revoked_entry=allowed,
        accept_revoked="0.7.0", revoked_reason="still mitigated per INC-42",
    )
    assert repeat["action"] == trust.ACTION_SECURITY_EXCEPTION
    assert repeat["previously_granted"]
    exceptions = state["lines"]["stable"]["security_exceptions"]
    assert len(exceptions) == 1
    events = list(trust.iter_audit_entries(trust.trust_audit_path(tmp_path)))
    marked = [event for event in events if event.get("security_exception")]
    assert len(marked) == 2
    assert marked[0]["previously_granted"] is False
    assert marked[1]["previously_granted"] is True


def test_downgrade_and_revocation_overrides_compose(tmp_path):
    state = trust.empty_state()
    _, state = _accept(tmp_path, state, _manifest("0.7.1", 2, digest_prefix="bb"))
    older = _manifest("0.7.0", 1, digest_prefix="aa")
    allowed = {
        "release_line": "stable",
        "version": "0.7.0",
        "to_version": None,
        "severity": "high",
        "reason": "mitigatable CVE",
        "fixed_version": "0.7.1",
        "security_exception_allowed": True,
        "revoked_at": "2026-02-02T00:00:00Z",
    }
    # Only the downgrade override is not enough for a revoked target.
    with pytest.raises(trust.RevocationError):
        trust.evaluate_acceptance(
            state, older, now_iso=NOW, allow_downgrade="0.7.0",
            downgrade_reason="compatibility",
            revoked_entry=allowed,
        )
    # Only the revocation override is not enough for the water mark.
    with pytest.raises(trust.DowngradeError):
        trust.evaluate_acceptance(
            state, older, now_iso=NOW, revoked_entry=allowed,
            accept_revoked="0.7.0", revoked_reason="mitigated",
        )
    decision, _ = _accept(
        tmp_path, state, older, allow_downgrade="0.7.0",
        downgrade_reason="compatibility", revoked_entry=allowed,
        accept_revoked="0.7.0", revoked_reason="mitigated",
    )
    assert decision["action"] == trust.ACTION_DOWNGRADE_SECURITY_EXCEPTION


def test_release_lines_have_independent_water_marks(tmp_path):
    state = trust.empty_state()
    _, state = _accept(tmp_path, state, _manifest("0.7.0", 1))
    # First desktop beta is TOFU on its own line, not a downgrade.
    decision, _ = _accept(
        tmp_path, state, _manifest("0.6.0-beta.2", 1, line="desktop-beta", digest_prefix="cc")
    )
    assert decision["action"] == trust.ACTION_TOFU
    assert decision["line"] == "desktop-beta"


# ---------------------------------------------------------------------------
# TR-4.2 atomicity, permissions, recovery
# ---------------------------------------------------------------------------


def test_state_round_trip_is_idempotent_and_private(tmp_path):
    trust_dir = trust.ensure_trust_layout(tmp_path)
    trust.save_state(trust_dir, trust.empty_state())
    first = trust.trust_state_path(trust_dir).read_bytes()
    trust.save_state(trust_dir, trust.load_state(trust_dir))
    second = trust.trust_state_path(trust_dir).read_bytes()
    assert first == second
    assert list(Path(trust_dir).glob(".keysmith-trust-*.tmp")) == []
    if os.name == "posix":
        assert stat.S_IMODE(os.lstat(str(trust_dir)).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(str(trust.trust_state_path(trust_dir))).st_mode) == 0o600


def test_interrupted_state_write_leaves_previous_state_intact(tmp_path, monkeypatch):
    trust.save_state(tmp_path, trust.empty_state())
    # Build the next state in memory without persisting it, then make the
    # atomic replace fail: the previously committed document must survive.
    decision = trust.evaluate_acceptance(
        trust.empty_state(), _manifest("0.7.0", 1), now_iso=NOW
    )
    next_state = trust.commit_acceptance(trust.empty_state(), decision)

    def boom(*_args, **_kwargs):
        raise OSError("simulated crash during replace")

    monkeypatch.setattr(trust.os, "replace", boom)
    with pytest.raises(trust.StateError):
        trust.save_state(tmp_path, next_state)
    monkeypatch.undo()

    loaded = trust.load_state(tmp_path)
    assert loaded["lines"]["stable"]["accepted"] is None
    assert list(Path(tmp_path).glob(".keysmith-trust-*.tmp")) == []


def test_malformed_state_always_fails_closed(tmp_path):
    good = trust.empty_state()
    corruptions = [
        {"schema_version": 2},
        {"lines": {}},
        {"schema_version": 1, "lines": {"stable": good["lines"]["stable"]}},
        {"schema_version": 1, "lines": dict(good["lines"], mystery=good["lines"]["stable"])},
        build_nested(good, accepted={"version": "0.7.0"}),
        build_nested(good, accepted={
            "version": "0.7.0", "sequence": 1,
            "manifest_hash": "zz" * 32, "accepted_at": NOW,
        }),
        build_nested(good, rekor_tree_size=-1),
        build_nested(good, rekor_tree_size=True),
        build_nested(good, security_exceptions=[{"version": "0.7.0"}]),
        build_nested(good, unknown=1),
    ]
    trust.ensure_trust_layout(tmp_path)
    for corrupted in corruptions:
        with pytest.raises(trust.StateError):
            trust.validate_state(corrupted)

    trust.trust_state_path(tmp_path).write_text("{not json", encoding="utf-8")
    with pytest.raises(trust.StateError):
        trust.load_state(tmp_path)


def build_nested(base, **changes):
    value = json.loads(json.dumps(base))
    line = value["lines"]["stable"]
    line.update(changes)
    return value


def test_state_file_symlink_is_rejected(tmp_path):
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(trust.empty_state()), encoding="utf-8")
    trust.save_state(tmp_path, trust.empty_state())
    state_path = trust.trust_state_path(tmp_path)
    state_path.unlink()
    state_path.symlink_to(outside)
    with pytest.raises(trust.StateError):
        trust.load_state(tmp_path)


def test_cached_envelope_round_trip_and_validation(tmp_path):
    signed = {"_type": trust.REVOCATIONS_TYPE, "version": 1, "issued_at": NOW,
              "expires": "2026-03-01T00:00:00Z", "revoked_keys": [],
              "revoked_releases": [], "revoked_artifacts": [],
              "spec_version": trust.SPEC_VERSION}
    envelope = trust.make_envelope(signed, [])
    trust.write_cached_envelope(tmp_path, trust.REVOCATIONS_TYPE, envelope)
    loaded = trust.read_cached_envelope(tmp_path, trust.REVOCATIONS_TYPE)
    assert loaded["signed"]["version"] == 1
    assert trust.read_cached_envelope(tmp_path, trust.ROOT_TYPE) is None
    with pytest.raises(trust.StateError):
        trust.write_cached_envelope(tmp_path, "mystery", envelope)
    mismatched = {"signed": dict(signed, _type=trust.ROOT_TYPE), "signatures": []}
    trust.atomic_write(tmp_path / "revocations.json", trust.canonical_json_bytes(mismatched))
    with pytest.raises(trust.MetadataError):
        trust.read_cached_envelope(tmp_path, trust.REVOCATIONS_TYPE)


def test_trust_dir_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv(trust.TRUST_DIR_ENV, str(tmp_path / "relocated"))
    assert trust.default_trust_dir() == tmp_path / "relocated"


# ---------------------------------------------------------------------------
# TR-4.3 append-only audit
# ---------------------------------------------------------------------------


def test_audit_log_is_append_only_and_prefix_preserved(tmp_path):
    audit = trust.trust_audit_path(tmp_path)
    trust.append_audit_line(audit, {"event": "tofu", "to_version": "0.7.0"})
    prefix = audit.read_bytes()
    trust.append_audit_line(audit, {"event": "accept-upgrade", "from_version": "0.7.0",
                                    "to_version": "0.7.1"})
    full = audit.read_bytes()
    assert full.startswith(prefix)
    events = list(trust.iter_audit_entries(audit))
    assert [event["event"] for event in events] == ["tofu", "accept-upgrade"]

    # Rewriting the historical prefix is visible on replay (the append-only
    # file itself cannot prevent local rewrite; audit replication is the
    # mitigation, surfaced to operators via the anomaly test below).
    audit.write_bytes(full.replace(b"\"tofu\"", b"\"retrofit\"", 1))
    assert list(trust.iter_audit_entries(audit))[0]["event"] == "retrofit"
    audit.write_bytes(prefix + b"not json object\n" + full[len(prefix):])
    with pytest.raises(trust.StateError):
        list(trust.iter_audit_entries(audit))
    audit.write_bytes(prefix + b"\n")
    with pytest.raises(trust.StateError):
        list(trust.iter_audit_entries(audit))


# ---------------------------------------------------------------------------
# TR-4.4 recovery quality: Rekor tree size and legacy onboarding
# ---------------------------------------------------------------------------


def test_rekor_tree_size_is_monotonic_per_line():
    state = trust.empty_state()
    state = trust.record_tree_size(state, "stable", 5)
    state = trust.record_tree_size(state, "stable", 5)
    state = trust.record_tree_size(state, "stable", 9)
    assert state["lines"]["stable"]["rekor_tree_size"] == 9
    assert state["lines"]["desktop-beta"]["rekor_tree_size"] == 0
    with pytest.raises(trust.RekorError):
        trust.record_tree_size(state, "stable", 8)
    with pytest.raises(trust.RekorError):
        trust.record_tree_size(state, "nightly", 10)


def test_legacy_onboarding_audit_entry():
    entry = trust.legacy_onboarding_audit_entry(
        line="stable", legacy_version="0.6.0", target_version="0.7.0",
        time_iso=NOW, source="self-extracted standalone",
    )
    assert entry["event"] == "legacy-onboarding"
    assert entry["legacy_version"] == "0.6.0"
    with pytest.raises(trust.MetadataError):
        trust.legacy_onboarding_audit_entry(
            line="stable", legacy_version="", target_version="0.7.0",
            time_iso=NOW, source="x",
        )
    with pytest.raises(trust.MetadataError):
        trust.legacy_onboarding_audit_entry(
            line="stable", legacy_version="0.6.0", target_version="nonsense",
            time_iso=NOW, source="x",
        )


def test_denied_decisions_do_not_mutate_state(tmp_path):
    state = trust.empty_state()
    _, state = _accept(tmp_path, state, _manifest("0.7.1", 2, digest_prefix="bb"))
    with pytest.raises(trust.DowngradeError):
        trust.evaluate_acceptance(
            state, _manifest("0.7.0", 1, digest_prefix="aa"), now_iso=NOW
        )
    assert state["lines"]["stable"]["accepted"]["version"] == "0.7.1"
    assert trust.load_state(tmp_path)["lines"]["stable"]["accepted"]["version"] == "0.7.1"
