"""RFC 8032 Ed25519 conformance and trust-envelope tests.

Coverage:
- The five published RFC 8032 section 7.1 Ed25519 known-answer vectors
  (TEST 1, TEST 2, TEST 3, TEST 1024 with its 1023-byte message, TEST
  SHA(abc)): public key derivation, deterministic signing and verification.
- Three deterministic 1024-signature stress schedules:
  * "random": seed_0 = 0^32; sk = seed; pk = P(sk); m = seed;
    sigma = Sign(sk, m); seed_{i+1} = SHA-512(sigma)[:32].
  * "cyclic": seed_0 = 0^32; sk = seed; pk = P(sk); m = pk;
    sigma = Sign(sk, m); seed_{i+1} = pk.
  * "switch": the random schedule triples replayed in reverse order.
  The final triples were independently confirmed bit-for-bit with OpenSSL's
  Ed25519 (via Node's crypto) on 2025-07-01 during implementation.
- Negative cases: wrong key/message/signature bytes, non-canonical scalar.
- Multi-signer envelopes with thresholds and the canonical-payload binding.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess

import pytest

from scripts import keysmith_trust as trust

# --- RFC 8032 section 7.1 published known-answer vectors -------------------

RFC_VECTORS = [
    {
        "seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "public": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "message": "",
        "signature": (
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ),
    },
    {
        "seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "public": "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "message": "72",
        "signature": (
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        ),
    },
    {
        "seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "public": "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "message": "af82",
        "signature": (
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
            "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
        ),
    },
    {
        "seed": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "public": "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "message": (
            "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0"
            ),
        "signature": (
            "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
            "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
        ),
    },
    {
        "seed": "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "public": "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "message": (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        ),
        "signature": (
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589"
            "09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"
        ),
    },
]


@pytest.mark.parametrize("vector", RFC_VECTORS, ids=["test1", "test2", "test3", "test1024", "sha-abc"])
def test_rfc8032_vectors(vector):
    seed = bytes.fromhex(vector["seed"])
    public = bytes.fromhex(vector["public"])
    message = bytes.fromhex(vector["message"])
    signature = bytes.fromhex(vector["signature"])
    assert trust.ed25519_public_from_seed(seed) == public
    assert trust.ed25519_sign(seed, message) == signature
    trust.ed25519_verify(public, message, signature)  # raises on failure


@pytest.fixture(scope="module")
def random_schedule():
    triples = []
    seed = b"\x00" * 32
    for _ in range(1024):
        public = trust.ed25519_public_from_seed(seed)
        signature = trust.ed25519_sign(seed, seed)
        trust.ed25519_verify(public, seed, signature)
        triples.append((seed, public, seed, signature))
        seed = hashlib.sha512(signature).digest()[:32]
    return triples


@pytest.fixture(scope="module")
def cyclic_schedule():
    triples = []
    seed = b"\x00" * 32
    for _ in range(1024):
        public = trust.ed25519_public_from_seed(seed)
        signature = trust.ed25519_sign(seed, public)
        trust.ed25519_verify(public, public, signature)
        triples.append((seed, public, public, signature))
        seed = public
    return triples


def test_random_schedule_final_triple(random_schedule):
    seed, public, message, signature = random_schedule[-1]
    assert seed.hex() == (
        "ad1c33988a3d5b06236ab0f873ac0b92cdf6f69545d81e7a63bab263d87d6b8d"
    )
    assert public.hex() == (
        "aa02c674dc4df2670f8a8aa4157b2fc3c6f261405185302fd995637f13af65c3"
    )
    assert message == seed
    assert signature.hex() == (
        "047224f76ab793dc4b6eee88b2c3f16d045d3c86e94cb1c443714abdde18457f"
        "a5a53325996cefb1e037a65ae618061588c5b2b24b8c290431b81fc433b3ba02"
    )


def test_cyclic_schedule_final_triple(cyclic_schedule):
    seed, public, message, signature = cyclic_schedule[-1]
    assert seed.hex() == (
        "0e5d2a246ec4abc934cefddfda08a909ad120013f740b3403a997cee3bbe3b78"
    )
    assert public.hex() == (
        "c64cf4de96e9e7ca32184f02c586f9e04662b3d7967426a62fe5f52ad3f39562"
    )
    assert message == public
    assert signature.hex() == (
        "14690588c8e7f42098ff569f23e2d391762e74aa8860d7d251c039acd1efb3b8"
        "646872a37c1cab05e425714608b2322b8b4d230b26f563ccd0628b5415685607"
    )


def test_switch_replay_verifies_random_triples_reversed(random_schedule):
    for _seed, public, message, signature in reversed(random_schedule):
        trust.ed25519_verify(public, message, signature)


def test_each_schedule_link_is_chained(random_schedule, cyclic_schedule):
    # Guards the schedule itself: the next seed derives from the previous link.
    previous_seed = b"\x00" * 32
    for seed, _public, message, signature in random_schedule:
        assert seed == previous_seed
        assert message == seed
        previous_seed = hashlib.sha512(signature).digest()[:32]
    previous_seed = b"\x00" * 32
    for seed, public, message, _signature in cyclic_schedule:
        assert seed == previous_seed
        assert message == public
        previous_seed = public


def test_generated_key_roundtrip():
    for _ in range(8):
        seed = trust.ed25519_generate_seed()
        assert len(seed) == 32
        public = trust.ed25519_public_from_seed(seed)
        message = b"deterministic release manifest payload"
        signature = trust.ed25519_sign(seed, message)
        trust.ed25519_verify(public, message, signature)


def test_verify_rejects_tampered_inputs():
    seed = bytes.fromhex(RFC_VECTORS[1]["seed"])
    public = bytes.fromhex(RFC_VECTORS[1]["public"])
    message = bytes.fromhex(RFC_VECTORS[1]["message"])
    signature = bytearray(trust.ed25519_sign(seed, message))

    good_sig = bytes(signature)
    trust.ed25519_verify(public, message, good_sig)

    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(public, message + b"x", good_sig)
    flipped = bytearray(good_sig)
    flipped[0] ^= 0x01
    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(public, message, bytes(flipped))
    flipped = bytearray(good_sig)
    flipped[63] ^= 0x80
    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(public, message, bytes(flipped))
    wrong_public = bytearray(public)
    wrong_public[0] ^= 0x01
    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(bytes(wrong_public), message, good_sig)

    # Non-canonical scalar S (>= group order) and off-curve public encodings.
    oversized = bytearray(good_sig)
    oversized[32:] = b"\xff" * 32  # 2^256 - 1, far above the group order
    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(public, message, bytes(oversized))
    with pytest.raises(trust.SignatureError):
        trust.ed25519_verify(b"\xff" * 32, message, good_sig)

    # Length discipline.
    for bad_public in (b"", b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(trust.SignatureError):
            trust.ed25519_verify(bad_public, message, good_sig)
    for bad_sig in (b"", b"\x00" * 63, b"\x00" * 65):
        with pytest.raises(trust.SignatureError):
            trust.ed25519_verify(public, message, bad_sig)
    with pytest.raises(trust.SignatureError):
        trust.ed25519_sign(b"\x00" * 31, message)


def test_canonical_payload_binding():
    seed = bytes.fromhex(RFC_VECTORS[0]["seed"])
    signed = {"_type": "root", "version": 1, "expires": "2030-01-01T00:00:00Z"}
    envelope = trust.seal_envelope(signed, [seed])
    raw = trust.canonical_json_bytes(envelope)
    parsed = trust.load_envelope(raw)
    # Signing bytes are exactly the canonical serialization of "signed".
    assert trust.signed_payload_bytes(parsed) == trust.canonical_json_bytes(signed)
    keyid = trust.ed25519_key_id(trust.ed25519_public_from_seed(seed))
    trust.verify_role_envelope(parsed, {keyid: trust.ed25519_public_from_seed(seed)}, 1)

    tampered = json.loads(raw.decode("utf-8"))
    tampered["signed"]["version"] = 2
    tampered_envelope = trust.load_envelope(trust.canonical_json_bytes(tampered))
    with pytest.raises(trust.SignatureError):
        trust.verify_role_envelope(
            tampered_envelope, {keyid: trust.ed25519_public_from_seed(seed)}, 1
        )


def test_threshold_envelope_matrix():
    seeds = [trust.ed25519_generate_seed() for _ in range(3)]
    publics = {
        trust.ed25519_key_id(trust.ed25519_public_from_seed(seed)): trust.ed25519_public_from_seed(seed)
        for seed in seeds
    }
    signed = {"_type": "root", "version": 2}

    one = trust.seal_envelope(signed, [seeds[0]])
    two = trust.seal_envelope(signed, [seeds[0], seeds[1]])

    assert trust.verify_role_envelope(two, publics, 2) == {
        trust.ed25519_key_id(trust.ed25519_public_from_seed(seeds[0])),
        trust.ed25519_key_id(trust.ed25519_public_from_seed(seeds[1])),
    }
    with pytest.raises(trust.SignatureError):
        trust.verify_role_envelope(one, publics, 2)
    trust.verify_role_envelope(one, publics, 1)

    # A third (not yet authorised) successor key self-signing a rotation
    # document is ignored against the PREVIOUS root role table, but cannot
    # count towards the previous-root threshold.
    old_role = {
        trust.ed25519_key_id(trust.ed25519_public_from_seed(seed)):
            trust.ed25519_public_from_seed(seed)
        for seed in seeds[:2]
    }
    rotated = trust.add_envelope_signature(one, seeds[2])
    valid = trust.verify_role_envelope(rotated, old_role, 1)
    third_id = trust.ed25519_key_id(trust.ed25519_public_from_seed(seeds[2]))
    assert third_id not in valid
    with pytest.raises(trust.SignatureError):
        trust.verify_role_envelope(rotated, old_role, 2)

    # Duplicate signer append is rejected.
    with pytest.raises(trust.SignatureError):
        trust.add_envelope_signature(one, seeds[0])


def test_secret_container_roundtrip_and_validation():
    seed = trust.ed25519_generate_seed()
    container = trust.make_secret_container(seed)
    loaded_seed, public = trust.load_secret_container(container)
    assert loaded_seed == seed
    assert public == trust.ed25519_public_from_seed(seed)

    bad = dict(container)
    bad["public"] = "00" * 32
    with pytest.raises(trust.SignatureError):
        trust.load_secret_container(bad)
    bad = dict(container)
    bad["seed"] = "11" * 32
    with pytest.raises(trust.SignatureError):
        trust.load_secret_container(bad)
    with pytest.raises(trust.SignatureError):
        trust.load_secret_container({"keytype": "rsa", "seed": "00" * 32, "public": "00" * 32})


def test_openssh_line_and_fingerprint_are_stable():
    public = bytes.fromhex(RFC_VECTORS[0]["public"])
    line = trust.openssh_ed25519_line(public, "rfc8032-test1")
    assert line == (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
        " rfc8032-test1"
    )
    assert trust.openssh_ed25519_fingerprint(public) == (
        "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
    )


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")
def test_openssh_fingerprint_matches_ssh_keygen(tmp_path):
    public = bytes.fromhex(RFC_VECTORS[0]["public"])
    key_file = tmp_path / "test1.pub"
    key_file.write_text(trust.openssh_ed25519_line(public, "rfc8032-test1") + "\n")
    result = subprocess.run(
        ["ssh-keygen", "-lf", str(key_file)], capture_output=True, text=True, check=True
    )
    assert "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8" in result.stdout
    assert "ED25519" in result.stdout


def test_grouped_hex_for_human_comparison():
    assert trust.grouped_hex("abcdef0123", 2) == "ab cd ef 01 23"


# --- TR-5.1: ECDSA P-256 verification (RFC 4754 / SEC1, verify-only) --------
#
# The product engine never signs with P-256 (offline anchors are produced by
# external tooling such as openssl), so the sign() routine below is a
# test-only oracle built from the engine's own point primitives; its output is
# pinned against the published RFC 4754 section 8.1 vector before use.

RFC4754_P256_QX = 0x2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970
RFC4754_P256_QY = 0x6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D
RFC4754_P256_R = 0xCB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C
RFC4754_P256_S = 0x86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315
RFC4754_P256_W = 0xDC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F
RFC4754_P256_K = 0x9E56F509196784D963D1C0A401510EE7ADA3DCC5DEE04B154BF61AF1D5A6DECE


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


def _p256_sign_e(scalar, e_value, nonce):
    """Test-only ECDSA signer with an explicit nonce (never used in product)."""
    n_order = trust._P256_N
    k_value = 1 + (int.from_bytes(hashlib.sha256(nonce).digest(), "big") % (n_order - 2))
    for _ in range(8):
        x_coord, _ = trust._p256_scalar_mul(k_value, (trust._P256_GX, trust._P256_GY))
        r_value = x_coord % n_order
        if r_value != 0:
            break
        k_value += 1
    s_value = (pow(k_value, n_order - 2, n_order) * (e_value + r_value * scalar)) % n_order
    assert s_value != 0
    return r_value, s_value


def _p256_test_key(seed_label):
    scalar = 1 + (
        int.from_bytes(hashlib.sha256(seed_label).digest(), "big") % (trust._P256_N - 2)
    )
    x_coord, y_coord = trust._p256_scalar_mul(scalar, (trust._P256_GX, trust._P256_GY))
    return scalar, x_coord, y_coord


def test_rfc4754_signing_oracle_matches_published_vector():
    x_coord, _ = trust._p256_scalar_mul(RFC4754_P256_K, (trust._P256_GX, trust._P256_GY))
    r_value = x_coord % trust._P256_N
    e_value = int.from_bytes(hashlib.sha256(b"abc").digest(), "big")
    s_value = (
        pow(RFC4754_P256_K, trust._P256_N - 2, trust._P256_N)
        * (e_value + r_value * RFC4754_P256_W)
    ) % trust._P256_N
    assert r_value == RFC4754_P256_R
    assert s_value == RFC4754_P256_S
    assert trust.p256_on_curve(RFC4754_P256_QX, RFC4754_P256_QY)


def test_p256_verify_rfc4754_vector_der_and_raw():
    spki = p256_spki_der(RFC4754_P256_QX, RFC4754_P256_QY)
    der_signature = _der_tlv(0x30, _der_int(RFC4754_P256_R) + _der_int(RFC4754_P256_S))
    raw_signature = RFC4754_P256_R.to_bytes(32, "big") + RFC4754_P256_S.to_bytes(32, "big")
    trust.p256_verify(spki, b"abc", der_signature)
    trust.p256_verify(spki, b"abc", raw_signature)
    # PEM armouring and both named-curve OID arcs must verify identically.
    pem = (
        trust._PEM_BEGIN
        + "\n"
        + base64.encodebytes(spki).decode("ascii")
        + trust._PEM_END
        + "\n"
    )
    trust.p256_verify(pem, b"abc", der_signature)
    spki_secg = p256_spki_der(RFC4754_P256_QX, RFC4754_P256_QY, trust._OID_P256_CURVE_SECG)
    trust.p256_verify(spki_secg, b"abc", der_signature)


def test_p256_verify_matches_digest_entry_point():
    scalar, x_coord, y_coord = _p256_test_key(b"p256 digest entry point")
    spki = p256_spki_der(x_coord, y_coord)
    message = b"hashedrekord binds raw digests"
    r_value, s_value = _p256_sign_e(
        scalar, int.from_bytes(hashlib.sha256(message).digest(), "big"), b"nonce-1"
    )
    signature = _der_tlv(0x30, _der_int(r_value) + _der_int(s_value))
    trust.p256_verify(spki, message, signature)
    trust.p256_verify_digest(spki, hashlib.sha256(message).digest(), signature)


def test_p256_rejects_wrong_message_key_and_tampered_signature():
    scalar, x_coord, y_coord = _p256_test_key(b"p256 rejection matrix")
    spki = p256_spki_der(x_coord, y_coord)
    _, ox, oy = _p256_test_key(b"p256 rejection matrix other")
    other_spki = p256_spki_der(ox, oy)
    message = b"same message bytes"
    r_value, s_value = _p256_sign_e(
        scalar, int.from_bytes(hashlib.sha256(message).digest(), "big"), b"nonce-2"
    )
    signature = _der_tlv(0x30, _der_int(r_value) + _der_int(s_value))
    raw = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")

    trust.p256_verify(spki, message, signature)
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(spki, b"other message", signature)
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(other_spki, message, signature)
    tampered = bytearray(signature)
    tampered[-1] ^= 0x01
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(spki, message, bytes(tampered))
    raw_tampered = bytearray(raw)
    raw_tampered[0] ^= 0x01
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(spki, message, bytes(raw_tampered))
    # s == n and r == 0 are unrecoverable regardless of key/message.
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(spki, message, r_value.to_bytes(32, "big") + trust._P256_N.to_bytes(32, "big"))
    with pytest.raises(trust.SignatureError):
        trust.p256_verify(spki, message, (0).to_bytes(64, "big"))


def test_p256_rejects_malformed_spki_and_signatures():
    scalar, x_coord, y_coord = _p256_test_key(b"p256 der defects")
    spki = p256_spki_der(x_coord, y_coord)
    r_value, s_value = _p256_sign_e(
        scalar, int.from_bytes(hashlib.sha256(b"msg").digest(), "big"), b"nonce-3"
    )
    signature = _der_tlv(0x30, _der_int(r_value) + _der_int(s_value))

    def expect_reject(material, label):
        with pytest.raises(trust.SignatureError):
            trust.p256_verify(material, b"msg", signature)
        with pytest.raises(trust.SignatureError):
            trust.p256_public_from_spki(material)
        print("rejected", label)

    # Off-curve point (flip the final y byte).
    bad_point = bytearray(spki)
    bad_point[-1] ^= 0x01
    expect_reject(bytes(bad_point), "off-curve point")
    # Compressed point instead of uncompressed 65-byte point.
    alg = _der_tlv(0x30, trust._OID_EC_PUBLIC_KEY + trust._OID_P256_CURVE_ANSI)
    compressed = _der_tlv(0x30, alg + _der_tlv(0x03, b"\x00\x02" + x_coord.to_bytes(32, "big")))
    expect_reject(compressed, "compressed point")
    # secp384r1 named curve is not accepted.
    p384_oid = bytes.fromhex("06052b81040023")
    p384_like = _der_tlv(
        0x30,
        _der_tlv(0x30, trust._OID_EC_PUBLIC_KEY + p384_oid)
        + _der_tlv(0x03, b"\x00\x04" + b"\x01" * 96),
    )
    expect_reject(p384_like, "p384 curve oid")
    # Bit string claims a used-unused-bits byte other than 0.
    dirty_bits = _der_tlv(
        0x30, alg + _der_tlv(0x03, b"\x01\x04" + x_coord.to_bytes(32, "big") + y_coord.to_bytes(32, "big"))
    )
    expect_reject(dirty_bits, "dirty unused bits")
    # Trailing garbage after the SPKI SEQUENCE.
    expect_reject(spki + b"\x00", "trailing garbage")
    # Not an SPKI at all.
    expect_reject(b"\x04" + spki, "wrong outer tag")
    # An Ed25519 SPKI is not a P-256 key.
    ed_public = bytes.fromhex(RFC_VECTORS[0]["public"])
    ed_spki = bytes.fromhex("302a300506032b6570032100") + ed_public
    expect_reject(ed_spki, "ed25519 spki")

    def expect_sig_reject(sig, label):
        with pytest.raises(trust.SignatureError):
            trust.p256_verify(spki, b"msg", sig)
        print("rejected sig", label)

    expect_sig_reject(b"", "empty")
    expect_sig_reject(b"\x32" + signature[1:], "broken der tag")
    expect_sig_reject(signature[:-1], "truncated der")
    expect_sig_reject(b"\x00" * 64, "zero raw")
    expect_sig_reject(bytes([0x30]) + signature[2:], "missing der length byte")
    expect_sig_reject(_der_tlv(0x31, _der_int(r_value) + _der_int(s_value)), "wrong seq tag")
    expect_sig_reject(
        _der_tlv(0x30, _der_int(r_value) + _der_int(s_value) + _der_int(r_value)),
        "three integers",
    )
    negative = _der_tlv(
        0x30,
        _der_tlv(0x02, (-r_value).to_bytes(33, "big", signed=True)) + _der_int(s_value),
    )
    expect_sig_reject(negative, "negative r")
    expect_sig_reject((1).to_bytes(33, "big") + s_value.to_bytes(32, "big"), "raw 65 bytes")
    expect_sig_reject(b"not-a-signature-at-all", "ascii garbage")


def test_rekor_log_id_is_sha256_of_der():
    scalar, x_coord, y_coord = _p256_test_key(b"p256 log id")
    spki = p256_spki_der(x_coord, y_coord)
    pem = (
        trust._PEM_BEGIN
        + "\n"
        + base64.encodebytes(spki).decode("ascii")
        + trust._PEM_END
        + "\n"
    )
    expected = hashlib.sha256(spki).hexdigest()
    assert trust.rekor_log_id_from_pem(pem) == expected
    assert trust.rekor_log_id_from_pem(spki) == expected
    with pytest.raises(trust.SignatureError):
        trust.rekor_log_id_from_pem(b"not a key")
