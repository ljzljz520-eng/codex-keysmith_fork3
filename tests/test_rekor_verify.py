"""TR-5.2 / TR-5.3 / TR-5.4 tests for Rekor transparency-log verification.

Coverage:
- TR-5.2 RFC 6962 inclusion verification against five PUBLISHED anchor
  vectors from transparency-dev/merkle (tree sizes 1/3/5/8), an independent
  naive recursive Merkle reference over every index of every tree size
  1..40, boundary indices, per-level tampering, and malformed proofs.
- TR-5.3 hashedrekord v0.0.1 verification: a recorded REAL Rekor entry
  bundle under tests/fixtures/trust/rekor/ (P-256 artifact signature, log
  SET, sharded inclusion proof, checkpoint/rootHash), full synthetic
  entries exercising both Ed25519 and P-256 artifact schemes, and a
  field-by-field tamper matrix.
- TR-5.4 zero-network guarantee: the trust engine neither imports nor opens
  sockets while verifying; the whole recorded bundle replays offline.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import socket
import urllib.request
from pathlib import Path

import pytest

from scripts import keysmith_trust as trust

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "trust" / "rekor"


# --------------------------------------------------------------------------
# Test-only ECDSA P-256 signer / SPKI builder (the product is verify-only).
# --------------------------------------------------------------------------

def _der_tlv(tag, content):
    n = len(content)
    if n < 128:
        length = bytes([n])
    else:
        body = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + content


def _der_int(value):
    body = value.to_bytes(32, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _der_tlv(0x02, body)


def p256_spki_der(x_coord, y_coord, curve_oid=trust._OID_P256_CURVE_ANSI):
    alg = _der_tlv(0x30, trust._OID_EC_PUBLIC_KEY + curve_oid)
    point = b"\x00\x04" + x_coord.to_bytes(32, "big") + y_coord.to_bytes(32, "big")
    return _der_tlv(0x30, alg + _der_tlv(0x03, point))


def pem_from_der(der):
    return (
        trust._PEM_BEGIN
        + "\n"
        + base64.encodebytes(der).decode("ascii")
        + trust._PEM_END
        + "\n"
    )


def p256_key(seed_label):
    scalar = 1 + (
        int.from_bytes(hashlib.sha256(seed_label).digest(), "big")
        % (trust._P256_N - 2)
    )
    x_coord, y_coord = trust._p256_scalar_mul(
        scalar, (trust._P256_GX, trust._P256_GY)
    )
    return scalar, pem_from_der(p256_spki_der(x_coord, y_coord))


def p256_sign_e(scalar, e_value, nonce_label):
    n_order = trust._P256_N
    k_value = 1 + (
        int.from_bytes(hashlib.sha256(nonce_label).digest(), "big")
        % (n_order - 2)
    )
    x_coord, _ = trust._p256_scalar_mul(k_value, (trust._P256_GX, trust._P256_GY))
    r_value = x_coord % n_order
    s_value = (pow(k_value, n_order - 2, n_order) * (e_value + r_value * scalar)) % n_order
    assert r_value and s_value
    return _der_tlv(0x30, _der_int(r_value) + _der_int(s_value))


def ed25519_pem(public):
    der = bytes.fromhex("302a300506032b6570032100") + public
    return pem_from_der(der)


# --------------------------------------------------------------------------
# TR-5.2: independent naive Merkle reference and published anchors
# --------------------------------------------------------------------------

def _node(a_hash, b_hash):
    return hashlib.sha256(b"\x01" + a_hash + b_hash).digest()


def _leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _naive_root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return _node(_naive_root(leaves[:split]), _naive_root(leaves[split:]))


def _naive_audit_path(leaves, index):
    proof = []

    def recurse(left, right):
        if right - left == 1:
            return
        split = 1
        while split * 2 < (right - left):
            split *= 2
        split += left
        if index < split:
            recurse(left, split)
            proof.append(_naive_root(leaves[split:right]))
        else:
            recurse(split, right)
            proof.append(_naive_root(leaves[left:split]))

    recurse(0, len(leaves))
    return proof


# Published transparency-dev/merkle testdata/inclusion positive vectors.
PUBLISHED_VECTORS = [
    (0, 1, "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
     "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=", []),
    (2, 3, "rra8/idLcKFPsGel5VeCZNsPqbUa9eC6FZFY8yngbnc=",
     "ApjRIpBtz8EIkstTpzmS/FufST6kybrbJ7eRtBJ6f+c=",
     ["+sVCA+fMaWzw38tCySodnbr3CtnmIfS9jZhmLwDjwSU="]),
    (1, 5, "Tju7H3tHjc/nH7YxYxUZo7yhLJrvyhYSv85ME6hiZNQ=",
     "lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
     ["bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms="]),
    (0, 8, "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=",
     ["lqKW0iTyhcZ77pPDD4owkVfw2qNdxbh+QQt4YwoJz8c=",
      "Xwg/ChozygdqlSeYMlgNs+DvRYS9/x9UyKNg9Q3jAx4=",
      "a0eq8p7jwq+a+Im8H7klTavTEXfxYjLdaqsDXKOb9uQ="]),
    (5, 8, "XcnaeacGWamtVZy3Ad7ZoqudgjqtL0lgz+Nw7/RgQyg=",
     "QnGia+DYqE8L1UyMMC58s6O10fpngKQLzOKHNHfatlg=",
     ["vBoGQ7EuTS18d5GPROD095qDi2z57FtcKD4fTYhZnms=",
      "yoVOoSjtBQtBs1/8G4e46yveRh6eO1WW7Oa51ZdaCuA=",
      "037kGJdt2VdTwcc4Yrk5j6Kiz5tP8P3+izDNlSCWFLc="]),
]


@pytest.mark.parametrize("leaf_index,size,root_b64,leaf_b64,proof_b64", PUBLISHED_VECTORS,
                         ids=["size1", "size3-idx2", "size5-idx1",
                              "size8-idx0", "size8-idx5"])
def test_published_inclusion_anchors(leaf_index, size, root_b64, leaf_b64, proof_b64):
    root = base64.b64decode(root_b64)
    leaf = base64.b64decode(leaf_b64)
    proof = [base64.b64decode(item) for item in proof_b64]
    assert trust.verify_rfc6962_inclusion(leaf, leaf_index, size, proof) == root


def test_inclusion_exhaustive_against_naive_reference():
    # The naive reference is written independently; the published anchors
    # above guard both implementations against a shared misunderstanding.
    for size in range(1, 41):
        datas = [("leaf-{}-".format(i)).encode() + bytes(range(i % 7)) for i in range(size)]
        leaves = [_leaf(data) for data in datas]
        root = _naive_root(leaves)
        for index in range(size):
            proof = _naive_audit_path(leaves, index)
            assert trust.verify_rfc6962_inclusion(leaves[index], index, size, proof) == root


@pytest.mark.parametrize("size", [2, 3, 5, 7, 8, 13, 16, 31])
def test_inclusion_rejects_every_tampered_proof_layer(size):
    datas = [("tamper-{}-".format(i)).encode() for i in range(size)]
    leaves = [_leaf(data) for data in datas]
    for index in (0, size - 1):
        proof = _naive_audit_path(leaves, index)
        root = _naive_root(leaves)
        for layer, honest in enumerate(proof):
            broken = list(proof)
            flipped = bytearray(honest)
            flipped[layer % 32] ^= 0x01
            broken[layer] = bytes(flipped)
            recomputed = trust.verify_rfc6962_inclusion(leaves[index], index, size, broken)
            assert recomputed != root
        leaf_mut = bytearray(leaves[index])
        leaf_mut[0] ^= 0x01
        assert trust.verify_rfc6962_inclusion(
            bytes(leaf_mut), index, size, proof
        ) != root


def test_inclusion_bounds_and_shape_validation():
    datas = [b"a", b"b", b"c", b"d"]
    leaves = [_leaf(data) for data in datas]
    root = _naive_root(leaves)
    valid = _naive_audit_path(leaves, 0)
    cases = [
        ("negative index", leaves[0], -1, 4, valid),
        ("index equals size", leaves[0], 4, 4, valid),
        ("index above size", leaves[0], 5, 4, valid),
        ("zero tree size", leaves[0], 0, 0, []),
        ("negative tree size", leaves[0], 0, -1, []),
        ("proof too short", leaves[0], 0, 4, valid[:-1]),
        ("proof too long", leaves[0], 0, 4, valid + [b"\x00" * 32]),
        ("hash 31 bytes", leaves[0], 0, 4, [b"\x00" * 31] + valid[1:]),
        ("hash 33 bytes", leaves[0], 0, 4, [b"\x00" * 33] + valid[1:]),
        ("leaf 31 bytes", b"\x00" * 31, 0, 4, valid),
        ("bool index", leaves[0], True, 4, valid),
        ("bool tree size", leaves[0], 0, True, valid),
    ]
    for label, leaf, index, size, proof in cases:
        with pytest.raises(trust.RekorError):
            trust.verify_rfc6962_inclusion(leaf, index, size, proof)
        print("rejected", label)
    # Single-leaf tree verifies with an empty proof.
    assert trust.verify_rfc6962_inclusion(leaves[0], 0, 1, []) == leaves[0]
    assert root != leaves[0]  # sanity: non-trivial tree


# --------------------------------------------------------------------------
# TR-5.3: synthetic hashedrekord entry builder
# --------------------------------------------------------------------------

def make_body(digest_hex, artifact_scheme):
    if artifact_scheme == "ed25519":
        seed = hashlib.sha256(b"synthetic ed25519 release key").digest()
        public = trust.ed25519_public_from_seed(seed)
        signature = trust.ed25519_sign(seed, digest_hex.encode("ascii"))
        public_pem = ed25519_pem(public)
        raw_sig = None
    else:
        scalar, public_pem = p256_key(b"synthetic p256 artifact key")
        raw_digest = bytes.fromhex(digest_hex)
        signature = p256_sign_e(
            scalar, int.from_bytes(raw_digest, "big"), b"synthetic-set-nonce"
        )
        # Recover r/s from the variable-length DER INTEGER encoding.
        _, sequence_content, _ = trust._der_tlv(signature, 0)
        integer_tlvs = trust._der_children(sequence_content)
        r_int = int.from_bytes(integer_tlvs[0][1], "big")
        s_int = int.from_bytes(integer_tlvs[1][1], "big")
        raw_sig = r_int.to_bytes(32, "big") + s_int.to_bytes(32, "big")
    document = {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
            "signature": {
                "content": base64.b64encode(signature).decode("ascii"),
                "publicKey": {
                    "content": base64.b64encode(public_pem.encode("ascii")).decode("ascii")
                },
            },
        },
    }
    return document, signature, public_pem, raw_sig


def make_entry(artifact=b"synthetic release artifact", artifact_scheme="ed25519",
               tree_size=7, leaf_index=3, use_raw_p256=False, set_key_seed=b"log-key",
               extra_leaf_data=None):
    log_scalar, log_pem = p256_key(set_key_seed)
    log_der = trust._pem_to_der(log_pem)
    digest_hex = hashlib.sha256(artifact).hexdigest()
    document, der_sig, artifact_pem, raw_sig = make_body(digest_hex, artifact_scheme)
    if use_raw_p256:
        assert artifact_scheme == "p256"
        document["spec"]["signature"]["content"] = base64.b64encode(raw_sig).decode()
    body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body_b64 = base64.b64encode(body).decode("ascii")

    # Build an independent synthetic tree whose target leaf is the body.
    datas = []
    for i in range(tree_size):
        if i == leaf_index:
            datas.append(body)
        else:
            datas.append(("other-leaf-{}-").format(i).encode() + bytes(range(i % 9)))
    leaves = [_leaf(data) for data in datas]
    root = _naive_root(leaves)
    proof = _naive_audit_path(leaves, leaf_index)

    log_index = leaf_index + 121904262  # top-level index may exceed the shard
    integrated_time = 1700000000
    log_id = hashlib.sha256(log_der).hexdigest()
    set_payload = trust._rekor_set_payload(body_b64, integrated_time, log_id, log_index)
    set_sig = p256_sign_e(
        log_scalar, int.from_bytes(hashlib.sha256(set_payload).digest(), "big"),
        b"set-nonce-" + str(log_index).encode(),
    )
    origin = "synthetic-log - 42"
    note = "{origin}\n{size}\n{root}\n".format(
        origin=origin,
        size=tree_size,
        root=base64.b64encode(root).decode("ascii").rstrip("="),
    )
    checkpoint_sig = p256_sign_e(
        log_scalar,
        int.from_bytes(hashlib.sha256(note.encode("utf-8")).digest(), "big"),
        b"checkpoint-nonce-" + str(tree_size).encode() + b"-" + str(leaf_index).encode(),
    )
    key_prefix = bytes.fromhex(log_id[:8])
    checkpoint = (
        note
        + "\n"
        + "\u2014 synthetic-log "
        + base64.b64encode(key_prefix + checkpoint_sig).decode("ascii")
        + "\n"
    )
    entry = {
        "body": body_b64,
        "integratedTime": integrated_time,
        "logID": log_id,
        "logIndex": log_index,
        "verification": {
            "signedEntryTimestamp": base64.b64encode(set_sig).decode("ascii"),
            "inclusionProof": {
                "hashes": [node_hash.hex() for node_hash in proof],
                "logIndex": leaf_index,
                "rootHash": root.hex(),
                "treeSize": tree_size,
                "checkpoint": checkpoint,
            },
        },
    }
    return entry, log_pem, artifact_pem, root


@pytest.mark.parametrize("scheme", ["ed25519", "p256"])
def test_synthetic_entry_full_verification(scheme):
    entry, log_pem, _, root = make_entry(artifact_scheme=scheme)
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    expected_scheme = scheme if scheme == "ed25519" else "ecdsa-p256-sha256"
    assert binding["artifact_scheme"] == expected_scheme
    assert binding["root_hash"] == root.hex()
    assert binding["log_index"] == entry["logIndex"]
    assert binding["inclusion_log_index"] == 3
    assert binding["root_size"] == 7 == binding["tree_size"]
    assert binding["digest_hex"] == hashlib.sha256(b"synthetic release artifact").hexdigest()


def test_synthetic_p256_raw_signature_and_odd_tree_boundaries():
    # Odd sizes (rootSize 1/3/7) exercise the fn == sn right-subtree branch.
    for size, index in [(1, 0), (3, 2), (7, 6), (7, 0), (8, 7)]:
        entry, log_pem, _, _ = make_entry(
            artifact_scheme="p256", use_raw_p256=True,
            tree_size=size, leaf_index=index,
        )
        binding = trust.verify_hashedrekord_entry(entry, log_pem)
        assert binding["artifact_scheme"] == "ecdsa-p256-sha256"


def test_legacy_set_inside_proof_still_verifies():
    entry, log_pem, _, _ = make_entry(artifact_scheme="ed25519", tree_size=5, leaf_index=2)
    set_sig = entry["verification"]["signedEntryTimestamp"]
    del entry["verification"]["signedEntryTimestamp"]
    entry["verification"]["inclusionProof"]["signedEntryTimestamp"] = set_sig
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    assert binding["root_size"] == 5


def test_checkpoint_with_untrusted_cosigner_line():
    entry, log_pem, _, _ = make_entry(artifact_scheme="ed25519", tree_size=4, leaf_index=1)
    # An extra signature line from an unrelated key must be ignored as long as
    # the trusted log key also signs the note (mirrors real multi-key notes).
    proof = entry["verification"]["inclusionProof"]
    lines = proof["checkpoint"].split("\n")
    # lines: origin, size, root, "", trusted line, trailing ""
    foreign = "\u2014 synthetic-log " + base64.b64encode(b"\xde\xad\xbe\xef" + b"\x30" * 8).decode()
    lines.insert(5, foreign)
    proof["checkpoint"] = "\n".join(lines)
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    assert binding["tree_size"] == 4
    # But a malformed signature line is rejected outright.
    proof["checkpoint"] = proof["checkpoint"].replace(foreign, "\u2014 no-base64-here")
    with pytest.raises(trust.RekorError):
        trust.verify_hashedrekord_entry(entry, log_pem)


def test_body_decoder_field_precision():
    digest_hex = hashlib.sha256(b"x").hexdigest()
    document, signature, public_pem, _ = make_body(digest_hex, "ed25519")

    def decode(doc):
        body = json.dumps(doc, separators=(",", ":"), sort_keys=True).encode()
        return trust.decode_hashedrekord_body(body)

    decoded = decode(document)
    assert decoded["key_scheme"] == "ed25519"
    scheme, public_hex = trust.hashedrekord_verify_artifact_signature(decoded)
    assert scheme == "ed25519" and len(public_hex) == 64

    def reject(doc, label):
        with pytest.raises((trust.RekorError, trust.SignatureError, trust.MetadataError)):
            bad = decode(doc)
            trust.hashedrekord_verify_artifact_signature(bad)
        print("rejected", label)

    bad_api = copy.deepcopy(document)
    bad_api["apiVersion"] = "0.0.2"
    reject(bad_api, "apiVersion")
    bad_kind = copy.deepcopy(document)
    bad_kind["kind"] = "rekord"
    reject(bad_kind, "kind")
    bad_alg = copy.deepcopy(document)
    bad_alg["spec"]["data"]["hash"]["algorithm"] = "sha512"
    reject(bad_alg, "hash algorithm")
    bad_unknown = copy.deepcopy(document)
    bad_unknown["spec"]["extra"] = 1
    reject(bad_unknown, "unknown spec field")
    bad_siglen = copy.deepcopy(document)
    bad_siglen["spec"]["signature"]["content"] = base64.b64encode(b"\x00" * 63).decode()
    reject(bad_siglen, "ed25519 sig 63 bytes")
    bad_pem = copy.deepcopy(document)
    bad_pem["spec"]["signature"]["publicKey"]["content"] = base64.b64encode(
        b"not a pem"
    ).decode()
    reject(bad_pem, "not-a-pem public key")
    bad_b64 = copy.deepcopy(document)
    bad_b64["spec"]["signature"]["content"] = "@@not-base64@@"
    with pytest.raises(trust.RekorError):
        decode(bad_b64)


def test_body_decoder_accepts_both_p256_key_arcs():
    digest_hex = hashlib.sha256(b"arc check").hexdigest()
    raw = bytes.fromhex(digest_hex)
    for arc in (trust._OID_P256_CURVE_ANSI, trust._OID_P256_CURVE_SECG):
        scalar = 1 + (
            int.from_bytes(hashlib.sha256(b"arc-key" + arc).digest(), "big")
            % (trust._P256_N - 2)
        )
        x_coord, y_coord = trust._p256_scalar_mul(
            scalar, (trust._P256_GX, trust._P256_GY)
        )
        public_pem = pem_from_der(p256_spki_der(x_coord, y_coord, arc))
        signature = p256_sign_e(
            scalar, int.from_bytes(raw, "big"), b"arc-nonce" + arc
        )
        doc = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": digest_hex}},
                "signature": {
                    "content": base64.b64encode(signature).decode(),
                    "publicKey": {
                        "content": base64.b64encode(public_pem.encode()).decode()
                    },
                },
            },
        }
        decoded = trust.decode_hashedrekord_body(
            json.dumps(doc, separators=(",", ":")).encode()
        )
        scheme, _ = trust.hashedrekord_verify_artifact_signature(decoded)
        assert scheme == "ecdsa-p256-sha256"


# --------------------------------------------------------------------------
# TR-5.3: recorded real Rekor bundle + tamper matrix
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def recorded_bundle():
    entry = json.loads((FIXTURE_DIR / "hashedrekord_entry.json").read_text())
    log_pem = (FIXTURE_DIR / "log_public_key.pem").read_text()
    metadata = json.loads((FIXTURE_DIR / "fixture_metadata.json").read_text())
    signer_pem = (FIXTURE_DIR / "artifact_signer_p256.pem").read_text()
    return entry, log_pem, metadata, signer_pem


def test_recorded_fixture_verifies_offline(recorded_bundle, monkeypatch):
    entry, log_pem, metadata, _ = recorded_bundle
    # Hard network block: even an accidental socket attempt fails the test.
    monkeypatch.setattr(socket, "socket", lambda *a, **k: pytest.fail("socket opened"))
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: pytest.fail("connection opened")
    )
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    expected = metadata["binding"]
    for key, value in expected.items():
        assert binding[key] == value
    artifact = metadata["artifact_message"].encode("ascii")
    assert hashlib.sha256(artifact).hexdigest() == binding["digest_hex"]
    # The body itself parses as a P-256 hashedrekord v0.0.1 record.
    body = base64.b64decode(entry["body"])
    decoded = trust.decode_hashedrekord_body(body)
    assert decoded["key_scheme"] == "ecdsa-p256-sha256"
    assert binding["log_id"] == trust.rekor_log_id_from_pem(log_pem)
    # Sharded log: shard-local inclusion index differs from the global index.
    assert binding["inclusion_log_index"] != binding["log_index"]


def _reencode_body(entry, body_document):
    entry["body"] = base64.b64encode(
        json.dumps(body_document, separators=(",", ":"), sort_keys=True).encode()
    ).decode("ascii")


def test_recorded_fixture_tamper_matrix(recorded_bundle):
    entry, log_pem, metadata, signer_pem = recorded_bundle
    failure = (trust.RekorError, trust.SignatureError, trust.MetadataError)

    def must_reject(mutated, key_pem=log_pem, label=""):
        with pytest.raises(failure):
            trust.verify_hashedrekord_entry(mutated, key_pem)
        print("tamper rejected:", label)

    # 1. Body digest no longer matches the artifact signature.
    bad = copy.deepcopy(entry)
    body = json.loads(base64.b64decode(bad["body"]))
    digest = body["spec"]["data"]["hash"]["value"]
    body["spec"]["data"]["hash"]["value"] = ("0" if digest[0] != "0" else "1") + digest[1:]
    _reencode_body(bad, body)
    must_reject(bad, label="body digest")

    # 2. Body signature content flipped.
    bad = copy.deepcopy(entry)
    body = json.loads(base64.b64decode(bad["body"]))
    sig = bytearray(base64.b64decode(body["spec"]["signature"]["content"]))
    sig[-1] ^= 1
    body["spec"]["signature"]["content"] = base64.b64encode(bytes(sig)).decode()
    _reencode_body(bad, body)
    must_reject(bad, label="body artifact signature")

    # 3. SET bit flipped (the log signature no longer verifies).
    bad = copy.deepcopy(entry)
    set_sig = bytearray(base64.b64decode(bad["verification"]["signedEntryTimestamp"]))
    set_sig[0] ^= 1
    bad["verification"]["signedEntryTimestamp"] = base64.b64encode(bytes(set_sig)).decode()
    must_reject(bad, label="SET")

    # 4. Any inclusion proof hash flipped moves the recomputed root.
    bad = copy.deepcopy(entry)
    hashes = bad["verification"]["inclusionProof"]["hashes"]
    node_hex = bytearray(bytes.fromhex(hashes[3]))
    node_hex[7] ^= 0x80
    hashes[3] = node_hex.hex()
    must_reject(bad, label="proof hash")

    # 5. treeSize smaller than the checkpoint size violates ordering.
    bad = copy.deepcopy(entry)
    bad["verification"]["inclusionProof"]["treeSize"] = (
        metadata["binding"]["root_size"] - 1
    )
    must_reject(bad, label="small treeSize")

    # 6. Checkpoint size line decremented while hashes stay the same.
    bad = copy.deepcopy(entry)
    proof = bad["verification"]["inclusionProof"]
    lines = proof["checkpoint"].split("\n")
    lines[1] = str(int(lines[1]) - 1)
    proof["checkpoint"] = "\n".join(lines)
    must_reject(bad, label="checkpoint size")

    # 7. A different trusted log key does not match the entry logID.
    bad = copy.deepcopy(entry)
    must_reject(bad, key_pem=signer_pem, label="wrong trusted log key")

    # 8. Advertised rootHash flipped.
    bad = copy.deepcopy(entry)
    root_hex = bytearray(bytes.fromhex(bad["verification"]["inclusionProof"]["rootHash"]))
    root_hex[0] ^= 1
    bad["verification"]["inclusionProof"]["rootHash"] = root_hex.hex()
    must_reject(bad, label="rootHash")

    # 9. Top-level logIndex changed: SET payload binding breaks.
    bad = copy.deepcopy(entry)
    bad["logIndex"] += 1
    must_reject(bad, label="logIndex vs SET")

    # 10. proof logIndex out of range.
    bad = copy.deepcopy(entry)
    bad["verification"]["inclusionProof"]["logIndex"] = (
        metadata["binding"]["root_size"] + 10
    )
    must_reject(bad, label="proof index out of range")

    # 11. checkpoint removed.
    bad = copy.deepcopy(entry)
    del bad["verification"]["inclusionProof"]["checkpoint"]
    must_reject(bad, label="missing checkpoint")

    # 12. SET in both locations is ambiguous.
    bad = copy.deepcopy(entry)
    bad["verification"]["inclusionProof"]["signedEntryTimestamp"] = (
        bad["verification"]["signedEntryTimestamp"]
    )
    must_reject(bad, label="duplicate SET location")

    # 13. Unknown field smuggled into verification.
    bad = copy.deepcopy(entry)
    bad["verification"]["intruder"] = True
    must_reject(bad, label="unknown verification field")

    # 14. Checkpoint signature lines removed: unsigned note rejected.
    bad = copy.deepcopy(entry)
    proof = bad["verification"]["inclusionProof"]
    unsigned_lines = proof["checkpoint"].split("\n")[:3]
    proof["checkpoint"] = "\n".join(unsigned_lines) + "\n\n"
    must_reject(bad, label="unsigned checkpoint")

    # 15. Checkpoint root line flipped but signature left intact.
    bad = copy.deepcopy(entry)
    proof = bad["verification"]["inclusionProof"]
    cp_lines = proof["checkpoint"].split("\n")
    root_b64 = bytearray(cp_lines[2].encode("ascii"))
    root_b64[0] = ord("A") if root_b64[0] != ord("A") else ord("B")
    cp_lines[2] = bytes(root_b64).decode("ascii")
    proof["checkpoint"] = "\n".join(cp_lines)
    must_reject(bad, label="checkpoint root line")


def test_recorded_fixture_replays_identically(recorded_bundle):
    # The frozen fixture must be deterministic across replays (no clock/network).
    entry, log_pem, _, _ = recorded_bundle
    first = trust.verify_hashedrekord_entry(entry, log_pem)
    second = trust.verify_hashedrekord_entry(entry, log_pem)
    assert first == second


# --------------------------------------------------------------------------
# TR-5.4: the engine itself must be network-free.
# --------------------------------------------------------------------------

ENGINE_PATH = Path(trust.__file__)


def test_engine_has_no_network_imports():
    source = ENGINE_PATH.read_text()
    for forbidden in (
        "import socket",
        "from socket",
        "import urllib",
        "from urllib",
        "import http.client",
        "import requests",
        "import ssl",
    ):
        assert forbidden not in source


def test_verification_path_opens_no_sockets(recorded_bundle, monkeypatch):
    entry, log_pem, _, _ = recorded_bundle

    def fail_socket(*args, **kwargs):
        raise AssertionError("verify path must not open sockets")

    monkeypatch.setattr(socket, "socket", fail_socket)
    monkeypatch.setattr(socket, "create_connection", fail_socket)
    monkeypatch.setattr(urllib.request, "urlopen", fail_socket)
    # Pure helpers plus the whole recorded entry, all offline.
    trust.verify_rfc6962_inclusion(b"\x00" * 32, 0, 1, [])
    trust.decode_hashedrekord_body(base64.b64decode(entry["body"]))
    binding = trust.verify_hashedrekord_entry(entry, log_pem)
    assert binding["log_index"] >= 0
