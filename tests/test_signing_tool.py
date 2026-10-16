"""TR-8: offline maintainer signing tool end-to-end and secret handling."""

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from scripts import keysmith_signing as signing
from scripts import keysmith_trust as trust

REPO_ROOT = Path(__file__).resolve().parents[1]
REKOR_PEM = REPO_ROOT / "tests" / "fixtures" / "trust" / "rekor" / "log_public_key.pem"
REKOR_LOG_ID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
ISSUED = "2026-07-18T10:00:00Z"
ROOT_EXPIRES = "2027-07-18T10:00:00Z"


def _seed(label):
    # Derived at runtime so no literal production-shaped seed container ever
    # lands in tracked test sources (see tests/test_trust_secrets.py).
    return hashlib.sha256(label.encode("ascii")).digest()


def _keyid(label):
    return trust.ed25519_key_id(trust.ed25519_public_from_seed(_seed(label)))


@pytest.fixture()
def workspace(tmp_path):
    keys = tmp_path / "airgap" / "keys"
    meta = tmp_path / "meta"
    keys.mkdir(parents=True)
    meta.mkdir()
    generated = {}

    def keygen(role, label):
        rc = signing.main(
            [
                "keygen",
                "--role",
                role,
                "--out",
                str(keys),
                "--name",
                label,
                "--from-seed",
                _seed(label).hex(),
            ]
        )
        assert rc == 0
        generated[label] = {
            "secret": keys / "{}.key.json".format(label),
            "public": keys / "{}.pub.json".format(label),
        }
        return generated[label]

    return {"root": tmp_path, "keys": keys, "meta": meta, "keygen": keygen, "all": generated}


def _load_envelope(path):
    return trust.load_envelope(Path(path).read_bytes(), str(path))


def _unsigned_manifest(version="0.7.0", sequence=1):
    tag = "v{}".format(version)
    return {
        "_type": "release",
        "spec_version": trust.SPEC_VERSION,
        "product": trust.PRODUCT,
        "release_line": trust.STABLE_LINE,
        "version": version,
        "tag": tag,
        "sequence": sequence,
        "issued_at": ISSUED,
        "source": {"repo": "local", "commit": "a" * 40, "tag_object": "b" * 40},
        "builder": {
            "workflow_name": "release.yml",
            "workflow_ref": "refs/tags/{}".format(tag),
            "workflow_sha": "c" * 40,
            "runner": "ubuntu-24.04",
            "python_version": "3.11.9",
            "node_version": "",
            "rust_version": "",
            "pyinstaller_version": "",
            "build_manifests": {},
        },
        "artifacts": {"codex-instruct-{}.py".format(tag): {"sha256": "d" * 64, "size": 1}},
        "sboms": {
            "codex-keysmith-{}-sbom.spdx.json".format(tag): {"sha256": "e" * 64, "size": 2},
            "codex-keysmith-{}-sbom.cdx.json".format(tag): {"sha256": "f" * 64, "size": 3},
        },
        "required_root_version": 1,
        "required_revocations_version": 0,
    }


def _write_json(path, obj):
    Path(path).write_bytes(signing.render_json(obj))


# ---------------------------------------------------------------------------
# TR-8.1 full offline ceremony
# ---------------------------------------------------------------------------


def test_full_ceremony_keygen_root_sign_rotate_revoke(workspace):
    keygen = workspace["keygen"]
    meta = workspace["meta"]
    keygen("root", "root1")
    keygen("root", "root2")
    keygen("root", "root3")
    keygen("release", "rel1")
    keygen("release", "rel2")
    keygen("revocation", "rev1")

    def sec(label):
        return str(workspace["all"][label]["secret"])

    def pub(label):
        return str(workspace["all"][label]["public"])

    # --- root v1 with threshold 2 and the trusted Rekor log ----------------
    rc = signing.main(
        [
            "root-init",
            "--out",
            str(meta / "root1.json"),
            "--root-key",
            sec("root1"),
            "--root-key",
            sec("root2"),
            "--release-key",
            pub("rel1"),
            "--revocation-key",
            pub("rev1"),
            "--threshold-root",
            "2",
            "--rekor-pub",
            str(REKOR_PEM),
            "--issued-at",
            ISSUED,
            "--expires",
            ROOT_EXPIRES,
        ]
    )
    assert rc == 0
    root1_env = _load_envelope(meta / "root1.json")
    root1 = trust.verify_root_document(root1_env, None)
    assert root1["version"] == 1
    assert root1["rekor_keys"][0]["keyid"] == "rekor:" + REKOR_LOG_ID
    assert len(root1_env["signatures"]) == 2

    # --- sign manifest sequence 1 -----------------------------------------
    _write_json(meta / "m1u.json", _unsigned_manifest("0.7.0", 1))
    assert signing.main(
        [
            "sign-manifest",
            "--input",
            str(meta / "m1u.json"),
            "--out",
            str(meta / "m1.json"),
            "--release-key",
            sec("rel1"),
            "--root",
            str(meta / "root1.json"),
        ]
    ) == 0
    m1_env = _load_envelope(meta / "m1.json")
    assert trust.verify_role_envelope(
        m1_env, trust.role_publics(root1, trust.ROLE_RELEASE), 1
    ) == {_keyid("rel1")}

    # --- sign the first release index --------------------------------------
    assert signing.main(
        [
            "sign-index",
            "--manifest",
            str(meta / "m1.json"),
            "--out",
            str(meta / "i1.json"),
            "--release-key",
            sec("rel1"),
            "--root",
            str(meta / "root1.json"),
            "--issued-at",
            "2026-07-18T11:00:00Z",
        ]
    ) == 0
    i1_env = _load_envelope(meta / "i1.json")
    index1 = trust.validate_release_index(i1_env["signed"])
    trust.verify_index_signature(i1_env, root1)
    trust.verify_index_against_manifest(index1, m1_env)
    assert trust.last_sequence(index1, trust.STABLE_LINE) == 1

    # --- adding rel2 must fail with only one old-root signature ------------
    assert (
        signing.main(
            [
                "release-key",
                "add",
                "--current-root",
                str(meta / "root1.json"),
                "--out",
                str(meta / "root2-bad.json"),
                "--key",
                pub("rel2"),
                "--root-signing-key",
                sec("root1"),
            ]
        )
        == 1
    )
    assert not (meta / "root2-bad.json").exists()

    # --- add rel2 with the full root threshold -----------------------------
    assert signing.main(
        [
            "release-key",
            "add",
            "--current-root",
            str(meta / "root1.json"),
            "--out",
            str(meta / "root2.json"),
            "--key",
            pub("rel2"),
            "--root-signing-key",
            sec("root1"),
            "--root-signing-key",
            sec("root2"),
        ]
    ) == 0
    root2_env = _load_envelope(meta / "root2.json")
    root2 = trust.verify_root_document(root2_env, root1)
    assert root2["version"] == 2
    assert _keyid("rel2") in root2["roles"][trust.ROLE_RELEASE]["keyids"]
    # The previous root remains independently verifiable (no forced upgrade).
    trust.verify_root_document(root1_env, None)

    # --- rotate the root membership to root2+root3 -------------------------
    assert signing.main(
        [
            "root-rotate",
            "--current-root",
            str(meta / "root2.json"),
            "--out",
            str(meta / "root3.json"),
            "--root-key",
            pub("root2"),
            "--root-key",
            pub("root3"),
            "--root-signing-key",
            sec("root1"),
            "--root-signing-key",
            sec("root2"),
            "--new-root-key",
            sec("root3"),
            "--threshold-root",
            "2",
        ]
    ) == 0
    root3_env = _load_envelope(meta / "root3.json")
    root3 = trust.verify_root_document(root3_env, root2)
    # Under the new role table both new-root signatures meet the threshold.
    new_signers = trust.verify_role_envelope(
        root3_env, trust.role_publics(root3, trust.ROLE_ROOT), 2
    )
    assert new_signers == {_keyid("root2"), _keyid("root3")}

    # --- retire rel1, then rel2 signs sequence 2 under the newest root -----
    assert signing.main(
        [
            "release-key",
            "retire",
            "--current-root",
            str(meta / "root3.json"),
            "--out",
            str(meta / "root4.json"),
            "--key",
            pub("rel1"),
            "--root-signing-key",
            sec("root2"),
            "--root-signing-key",
            sec("root3"),
        ]
    ) == 0
    root4_env = _load_envelope(meta / "root4.json")
    root4 = trust.verify_root_document(root4_env, root3)
    assert root4["roles"][trust.ROLE_RELEASE]["keyids"] == [_keyid("rel2")]

    _write_json(meta / "m2u.json", _unsigned_manifest("0.7.1", 2))
    assert signing.main(
        [
            "sign-manifest",
            "--input",
            str(meta / "m2u.json"),
            "--out",
            str(meta / "m2.json"),
            "--release-key",
            sec("rel2"),
            "--root",
            str(meta / "root4.json"),
        ]
    ) == 0
    m2_env = _load_envelope(meta / "m2.json")
    trust.verify_role_envelope(m2_env, trust.role_publics(root4, trust.ROLE_RELEASE), 1)
    assert signing.main(
        [
            "sign-index",
            "--manifest",
            str(meta / "m2.json"),
            "--current-index",
            str(meta / "i1.json"),
            "--out",
            str(meta / "i2.json"),
            "--release-key",
            sec("rel2"),
            "--root",
            str(meta / "root4.json"),
            "--issued-at",
            "2026-07-19T11:00:00Z",
        ]
    ) == 0
    i2_env = _load_envelope(meta / "i2.json")
    index2 = trust.validate_release_index(i2_env["signed"])
    assert trust.last_sequence(index2, trust.STABLE_LINE) == 2
    trust.verify_index_signature(i2_env, root4)

    # A stale rel1 signature is no longer authorised for a fresh manifest.
    stale_env = trust.seal_envelope(_unsigned_manifest("0.7.2", 3), [_seed("rel1")])
    with pytest.raises(trust.SignatureError):
        trust.verify_role_envelope(
            stale_env, trust.role_publics(root4, trust.ROLE_RELEASE), 1
        )

    # --- revoke the retired rel1 key, then grow revocations cumulatively ---
    assert signing.main(
        [
            "revoke",
            "--kind",
            "key",
            "--out",
            str(meta / "rev1.json"),
            "--revocation-key",
            sec("rev1"),
            "--root",
            str(meta / "root1.json"),
            "--reason",
            "test compromise",
            "--keyid",
            _keyid("rel1"),
            "--issued-at",
            "2026-07-19T12:00:00Z",
            "--expires",
            "2026-08-18T12:00:00Z",
        ]
    ) == 0
    rev1_env = _load_envelope(meta / "rev1.json")
    rev1_signed = trust.verify_revocations_signature(rev1_env, root1)
    assert trust.revoked_key_entry(rev1_signed, _keyid("rel1"))["reason"] == (
        "test compromise"
    )

    assert signing.main(
        [
            "revoke",
            "--kind",
            "release",
            "--current-revocations",
            str(meta / "rev1.json"),
            "--out",
            str(meta / "rev2.json"),
            "--revocation-key",
            sec("rev1"),
            "--root",
            str(meta / "root1.json"),
            "--reason",
            "advisory range",
            "--release-line",
            trust.STABLE_LINE,
            "--version",
            "0.5.0",
            "--to-version",
            "0.5.9",
            "--severity",
            "medium",
            "--fixed-version",
            "0.6.0",
            "--issued-at",
            "2026-07-20T12:00:00Z",
            "--expires",
            "2026-09-20T12:00:00Z",
        ]
    ) == 0
    rev2_env = _load_envelope(meta / "rev2.json")
    rev2_signed = trust.validate_revocations(rev2_env["signed"])
    assert rev2_signed["version"] == 2
    # History survives: the key revocation is still present.
    assert trust.revoked_key_entry(rev2_signed, _keyid("rel1")) is not None
    assert trust.revoked_release_entry(rev2_signed, trust.STABLE_LINE, "0.5.4") is not None

    # Overlapping release ranges must be rejected.
    assert (
        signing.main(
            [
                "revoke",
                "--kind",
                "release",
                "--current-revocations",
                str(meta / "rev2.json"),
                "--out",
                str(meta / "rev-bad.json"),
                "--revocation-key",
                sec("rev1"),
                "--root",
                str(meta / "root1.json"),
                "--reason",
                "overlap",
                "--release-line",
                trust.STABLE_LINE,
                "--version",
                "0.5.5",
                "--severity",
                "low",
                "--issued-at",
                "2026-07-21T12:00:00Z",
                "--expires",
                "2026-10-21T12:00:00Z",
            ]
        )
        == 1
    )
    assert not (meta / "rev-bad.json").exists()


# ---------------------------------------------------------------------------
# Threshold append ceremony for release signatures
# ---------------------------------------------------------------------------


def test_release_threshold_append_signatures(workspace):
    keygen = workspace["keygen"]
    meta = workspace["meta"]
    keygen("root", "root1")
    keygen("release", "rel1")
    keygen("release", "rel2")
    keygen("revocation", "rev1")

    def sec(label):
        return str(workspace["all"][label]["secret"])

    assert signing.main(
        [
            "root-init",
            "--out",
            str(meta / "root.json"),
            "--root-key",
            sec("root1"),
            "--release-key",
            sec("rel1"),
            "--release-key",
            sec("rel2"),
            "--revocation-key",
            sec("rev1"),
            "--threshold-release",
            "2",
            "--issued-at",
            ISSUED,
            "--expires",
            ROOT_EXPIRES,
        ]
    ) == 0
    root_env = _load_envelope(meta / "root.json")
    root = trust.validate_root_signed(root_env["signed"])

    _write_json(meta / "mu.json", _unsigned_manifest())
    # One signature fails the configured release threshold under --root.
    assert (
        signing.main(
            [
                "sign-manifest",
                "--input",
                str(meta / "mu.json"),
                "--out",
                str(meta / "partial.json"),
                "--release-key",
                sec("rel1"),
                "--root",
                str(meta / "root.json"),
            ]
        )
        == 1
    )
    # Without a root check the partial envelope is still emitted, then the
    # second signer appends its signature offline.
    assert signing.main(
        [
            "sign-manifest",
            "--input",
            str(meta / "mu.json"),
            "--out",
            str(meta / "partial.json"),
            "--release-key",
            sec("rel1"),
        ]
    ) == 0
    assert signing.main(
        [
            "sign-manifest",
            "--input",
            str(meta / "mu.json"),
            "--append-to",
            str(meta / "partial.json"),
            "--out",
            str(meta / "full.json"),
            "--release-key",
            sec("rel2"),
            "--root",
            str(meta / "root.json"),
        ]
    ) == 0
    full_env = _load_envelope(meta / "full.json")
    signers = trust.verify_role_envelope(
        full_env, trust.role_publics(root, trust.ROLE_RELEASE), 2
    )
    assert signers == {_keyid("rel1"), _keyid("rel2")}
    # Appending the same key twice is rejected.
    assert (
        signing.main(
            [
                "sign-manifest",
                "--input",
                str(meta / "mu.json"),
                "--append-to",
                str(meta / "full.json"),
                "--out",
                str(meta / "full2.json"),
                "--release-key",
                sec("rel2"),
            ]
        )
        == 1
    )


# ---------------------------------------------------------------------------
# TR-8.2 secret material protection
# ---------------------------------------------------------------------------


def test_keygen_refuses_git_worktree_without_override(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=str(repo), check=True)
    secret_dir = repo / "keys"
    rc = signing.main(
        [
            "keygen",
            "--role",
            "root",
            "--out",
            str(secret_dir),
            "--from-seed",
            _seed("worktree").hex(),
        ]
    )
    assert rc == 1
    assert not secret_dir.exists()
    # Explicit override unblocks the operator who really meant it.
    rc = signing.main(
        [
            "keygen",
            "--role",
            "root",
            "--out",
            str(secret_dir),
            "--from-seed",
            _seed("worktree").hex(),
            "--i-know-this-is-not-a-repo",
        ]
    )
    assert rc == 0
    assert secret_dir.exists()


def test_keygen_refuses_symlinked_path(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)
    rc = signing.main(
        [
            "keygen",
            "--role",
            "root",
            "--out",
            str(link_dir / "keys"),
            "--from-seed",
            _seed("symlink").hex(),
            "--i-know-this-is-not-a-repo",
        ]
    )
    assert rc == 1
    assert not (real_dir / "keys").exists()


def test_keygen_file_modes_and_no_seed_echo(workspace, capsys):
    material = workspace["keygen"]("release", "quiet")
    secret = material["secret"]
    public = material["public"]
    if os.name == "posix":
        assert stat.S_IMODE(secret.stat().st_mode) == 0o600
        assert stat.S_IMODE(public.stat().st_mode) == 0o644
    secret_obj = json.loads(secret.read_text("utf-8"))
    assert secret_obj["seed"] == _seed("quiet").hex()
    captured = capsys.readouterr()
    assert _seed("quiet").hex() not in captured.out
    assert _seed("quiet").hex() not in captured.err
    # Overwriting existing material is refused.
    rc = signing.main(
        [
            "keygen",
            "--role",
            "release",
            "--out",
            str(secret.parent),
            "--name",
            "quiet",
            "--from-seed",
            _seed("quiet").hex(),
            "--i-know-this-is-not-a-repo",
        ]
    )
    assert rc == 1


@pytest.mark.parametrize("bad_seed", ["zz", "ab" * 31, "ab" * 33])
def test_keygen_rejects_malformed_test_seed(workspace, bad_seed):
    rc = signing.main(
        [
            "keygen",
            "--role",
            "root",
            "--out",
            str(workspace["keys"] / "bad"),
            "--from-seed",
            bad_seed,
        ]
    )
    assert rc == 1


def test_json_output_is_machine_readable(workspace):
    import contextlib
    import io

    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert signing.main(
            [
                "--json",
                "keygen",
                "--role",
                "root",
                "--out",
                str(workspace["keys"] / "jsonout"),
                "--name",
                "j2",
                "--from-seed",
                _seed("json2").hex(),
            ]
        ) == 0
    record = json.loads(buffer.getvalue().strip())
    assert record["ok"] is True
    assert record["keyid"] == _keyid("json2")


def test_signing_tool_has_no_network_surface():
    import ast

    source = (REPO_ROOT / "scripts" / "keysmith_signing.py").read_text("utf-8")
    for forbidden in ("import socket", "http.client", "requests"):
        assert forbidden not in source
    # No network module may be imported at module top level: urllib/ssl are
    # imported lazily inside the single rekor-submit network surface.
    tree = ast.parse(source)
    top_level = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            top_level.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level.add(node.module.split(".")[0])
    assert not (top_level & {"urllib", "ssl", "socket", "http"})
    # urllib is reachable from exactly one place: the rekor HTTP helper.
    assert source.count("import urllib.request") == 1
    marker = "# Rekor hashedrekord submission"
    head, tail = source.split(marker, 1)
    assert "urllib" not in head
    assert "urllib.request.urlopen" in tail


# ---------------------------------------------------------------------------
# TR-9: rekor-submit against a local mock transparency log
# ---------------------------------------------------------------------------

REKOR_SECTION_UUID = (
    "108e9186e8c5677abb479924e76e16c239c0d392796c5c672ffa3d3f192807f4cc"
    "100d02168caf6d"
)


def _rekor_test_helpers():
    import importlib.util

    helper_path = REPO_ROOT / "tests" / "test_rekor_verify.py"
    spec = importlib.util.spec_from_file_location("trv_rekor_helpers", helper_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _strip_inclusion_proof(entry):
    stripped = json.loads(json.dumps(entry))
    verification = stripped.get("verification")
    if isinstance(verification, dict):
        verification.pop("inclusionProof", None)
    proof = stripped.get("proof")
    if isinstance(proof, dict):
        proof.pop("inclusionProof", None)
    return stripped


class _ScriptedRekor:
    """Request script returning synthetic entries from test_rekor_verify.

    ``entry`` is the eventual, inclusion-proof-bearing entry. While the
    simulated entry is pending, responses strip the inclusion proof.
    """

    def __init__(self, entry, uuid, *, post_status=201, location=None, polls=0):
        self.entry = entry
        self.pending_entry = _strip_inclusion_proof(entry)
        self.uuid = uuid
        self.post_status = post_status
        self.location = location
        self.polls = polls
        self.requests = []
        self.get_count = 0

    def _map(self, entry):
        return json.dumps({self.uuid: entry}).encode("utf-8")

    def __call__(self, method, path, body, headers):
        self.requests.append(
            {"method": method, "path": path, "body": body, "headers": headers}
        )
        if method == "POST":
            response_headers = {}
            if self.location is not None:
                response_headers["Location"] = self.location
            served = self.pending_entry if self.polls else self.entry
            return self.post_status, response_headers, self._map(served)
        self.get_count += 1
        served = self.pending_entry if self.get_count <= self.polls else self.entry
        return 200, {}, self._map(served)


def _serve(script):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):  # silence stderr noise
            pass

        def _handle(self, method):
            length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(length) if length else b""
            status, headers, payload = self.server.script(
                method, self.path, body, dict(self.headers.items())
            )
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_POST(self):  # noqa: N802
            self._handle("POST")

        def do_GET(self):  # noqa: N802
            self._handle("GET")

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.script = script
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


@pytest.fixture()
def rekor_case(tmp_path):
    helpers = _rekor_test_helpers()
    envelope = trust.seal_envelope(_unsigned_manifest("0.7.0", 1), [_seed("rel1")])
    manifest_path = tmp_path / "m1.json"
    manifest_path.write_bytes(signing.render_json(envelope))
    payload = trust.signed_payload_bytes(envelope)
    digest_hex = hashlib.sha256(payload).hexdigest()

    scalar, public_pem = helpers.p256_key(b"synthetic p256 artifact key")
    der_signature = helpers.p256_sign_e(
        scalar, int(digest_hex, 16), b"synthetic-set-nonce"
    )
    entry, log_pem, _artifact_pem, _root = helpers.make_entry(
        artifact=payload, artifact_scheme="p256"
    )
    signature_path = tmp_path / "artifact.sig.der"
    signature_path.write_bytes(der_signature)
    public_path = tmp_path / "artifact-signer.p256.pem"
    public_path.write_text(public_pem, encoding="ascii")
    log_pem_path = tmp_path / "rekor-log.pem"
    log_pem_path.write_text(log_pem, encoding="ascii")
    out_path = tmp_path / "rekor-entry.json"
    return {
        "manifest": manifest_path,
        "signature": signature_path,
        "public": public_path,
        "log_pem": log_pem_path,
        "out": out_path,
        "entry": entry,
        "digest_hex": digest_hex,
        "payload": payload,
    }


def _submit(case, base_url, script=None, **overrides):
    kwargs = dict(
        base_url=base_url,
        entries_path="/api/v1/log/entries",
        manifest_path=case["manifest"],
        signature_path=case["signature"],
        public_key_path=case["public"],
        out_path=case["out"],
        log_pem_path=case["log_pem"],
        timeout=5.0,
        poll_interval=0.01,
        max_wait=10.0,
        sleeper=lambda *_: None,
    )
    kwargs.update(overrides)
    return signing.submit_rekor_entry(**kwargs)


def test_rekor_submit_success_writes_verifiable_entry(rekor_case):
    script = _ScriptedRekor(rekor_case["entry"], REKOR_SECTION_UUID)
    server, thread = _serve(script)
    try:
        result = _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()
    assert result["uuid"] == REKOR_SECTION_UUID
    assert result["already_existed"] is False
    assert result["artifact_scheme"] == "ecdsa-p256-sha256"
    assert result["log_index"] == rekor_case["entry"]["logIndex"]

    post_record = script.requests[0]
    proposal = json.loads(post_record["body"])
    assert post_record["path"] == "/api/v1/log/entries"
    assert post_record["headers"]["Content-Type"] == "application/json"
    document = proposal["proposedEntry"]
    assert document["apiVersion"] == "0.0.1"
    assert document["kind"] == "hashedrekord"
    assert document["spec"]["data"]["hash"]["value"] == rekor_case["digest_hex"]

    written = json.loads(rekor_case["out"].read_text("utf-8"))
    log_pem = rekor_case["log_pem"].read_text("utf-8")
    binding = trust.verify_hashedrekord_entry(written, log_pem)
    assert binding["digest_hex"] == rekor_case["digest_hex"]
    assert binding["artifact_scheme"] == "ecdsa-p256-sha256"


def test_rekor_submit_polls_until_inclusion_proof(rekor_case):
    script = _ScriptedRekor(
        rekor_case["entry"], REKOR_SECTION_UUID, post_status=201, polls=2
    )
    server, _thread = _serve(script)
    try:
        result = _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()
    assert result["uuid"] == REKOR_SECTION_UUID
    assert script.get_count == 3
    assert [r["method"] for r in script.requests] == ["POST", "GET", "GET", "GET"]


def test_rekor_submit_dedups_409_and_fetches_existing(rekor_case):
    location = "/api/v1/log/entries/{}".format(REKOR_SECTION_UUID)
    script = _ScriptedRekor(
        rekor_case["entry"],
        "deadbeef" * 8,
        post_status=409,
        location=location,
        polls=1,
    )
    server, _thread = _serve(script)
    try:
        result = _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()
    assert result["already_existed"] is True
    assert result["uuid"] == REKOR_SECTION_UUID
    get_paths = [r["path"] for r in script.requests if r["method"] == "GET"]
    assert get_paths == [
        "/api/v1/log/entries/{}".format(REKOR_SECTION_UUID),
        "/api/v1/log/entries/{}".format(REKOR_SECTION_UUID),
    ]


def test_rekor_submit_fails_closed_on_http_error(rekor_case):
    script = _ScriptedRekor(
        rekor_case["entry"], REKOR_SECTION_UUID, post_status=400
    )
    server, _thread = _serve(script)
    try:
        with pytest.raises(signing.SigningError, match="HTTP 400"):
            _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()
    assert not rekor_case["out"].exists()


def test_rekor_submit_fails_closed_on_malformed_json(rekor_case):
    class _Broken(_ScriptedRekor):
        def __call__(self, method, path, body, headers):
            self.requests.append(
                {"method": method, "path": path, "body": body, "headers": headers}
            )
            if method == "POST":
                return 201, {}, b"this is not json"
            return 200, {}, json.dumps({self.uuid: self.entry}).encode("utf-8")

    server, _thread = _serve(_Broken(rekor_case["entry"], REKOR_SECTION_UUID))
    try:
        with pytest.raises(signing.SigningError, match="non-JSON"):
            _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()


def test_rekor_submit_times_out_without_inclusion_proof(rekor_case):
    script = _ScriptedRekor(rekor_case["entry"], REKOR_SECTION_UUID, polls=10**6)
    server, _thread = _serve(script)
    try:
        with pytest.raises(signing.SigningError, match="timed out"):
            _submit(
                rekor_case,
                "http://127.0.0.1:{}".format(server.server_port),
                max_wait=0.0,
            )
    finally:
        server.shutdown()
    assert not rekor_case["out"].exists()


def test_rekor_submit_detects_stored_digest_drift(rekor_case, tmp_path):
    helpers = _rekor_test_helpers()
    drifted_payload = rekor_case["payload"] + b"-drifted"
    drifted_entry, _log_pem, _pem, _root = helpers.make_entry(
        artifact=drifted_payload, artifact_scheme="p256"
    )
    script = _ScriptedRekor(drifted_entry, REKOR_SECTION_UUID)
    server, _thread = _serve(script)
    try:
        with pytest.raises(signing.SigningError, match="different digest"):
            _submit(rekor_case, "http://127.0.0.1:{}".format(server.server_port))
    finally:
        server.shutdown()


def test_rekor_submit_preflight_fails_before_any_network(rekor_case):
    # A garbage signature must be rejected locally; the bogus URL guarantees
    # that no network call happens on the success path.
    rekor_case["signature"].write_bytes(b"\x00not a der signature")
    with pytest.raises(signing.SigningError, match="local verification"):
        _submit(rekor_case, "http://127.0.0.1:1")


def test_rekor_submit_cli_json(rekor_case):
    import contextlib
    import io

    script = _ScriptedRekor(rekor_case["entry"], REKOR_SECTION_UUID, polls=1)
    server, _thread = _serve(script)
    buffer = io.StringIO()
    try:
        with contextlib.redirect_stdout(buffer):
            rc = signing.main(
                [
                    "--json",
                    "rekor-submit",
                    "--manifest",
                    str(rekor_case["manifest"]),
                    "--signature-file",
                    str(rekor_case["signature"]),
                    "--public-key",
                    str(rekor_case["public"]),
                    "--out",
                    str(rekor_case["out"]),
                    "--rekor-pub",
                    str(rekor_case["log_pem"]),
                    "--rekor-url",
                    "http://127.0.0.1:{}".format(server.server_port),
                    "--poll-interval",
                    "0.01",
                    "--max-wait",
                    "10",
                ]
            )
    finally:
        server.shutdown()
    assert rc == 0
    record = json.loads(buffer.getvalue().strip())
    assert record["ok"] is True
    assert record["uuid"] == REKOR_SECTION_UUID
    assert record["artifact_scheme"] == "ecdsa-p256-sha256"


def test_recorded_fixture_uuid_and_binding_match_metadata():
    fixture_dir = REPO_ROOT / "tests" / "fixtures" / "trust" / "rekor"
    entry = json.loads((fixture_dir / "hashedrekord_entry.json").read_text("utf-8"))
    metadata = json.loads((fixture_dir / "fixture_metadata.json").read_text("utf-8"))
    log_pem = (fixture_dir / "log_public_key.pem").read_text("utf-8")
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    assert binding["digest_hex"] == metadata["binding"]["digest_hex"]
    assert binding["log_id"] == metadata["binding"]["log_id"]
    assert binding["log_index"] == metadata["binding"]["log_index"]
    # Sharded Rekor UUIDs are a 64-hex entry identifier followed by the
    # 16-hex shard ID; they need not be prefixed by the log ID.
    uuid = metadata["entry_uuid"]
    assert len(uuid) == 80
    assert int(uuid, 16) >= 0
    assert metadata["source"].endswith(uuid)
