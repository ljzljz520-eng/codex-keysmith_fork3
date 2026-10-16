"""TR-8.3: no private key material may be committed outside the trust fixture.

The only allowed home for secret-shaped test material is
``tests/fixtures/trust/``. Published RFC 8032 Ed25519 test vectors in
test_trust_crypto.py are public constants and therefore intentionally not
flagged: the scanner looks for full Ed25519 *secret containers* (the exact
on-disk shape produced by keysmith_signing keygen) and for PEM private-key
blocks, which are the shapes a real key leak would take.
"""

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PREFIX = "tests/fixtures/trust/"

PEM_PRIVATE_PATTERNS = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN ANY PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
)

# A generated container renders (sort_keys) as keytype/public/seed, but accept
# either field order so a hand-reordered leak is still caught.
_HEX64 = r"[0-9a-f]{64}"
SECRET_CONTAINER_PATTERN = re.compile(
    r'"keytype"\s*:\s*"ed25519"[\s\S]{0,400}?'
    r"(?:"
    r'"public"\s*:\s*"' + _HEX64 + r'"[\s\S]{0,200}?"seed"\s*:\s*"' + _HEX64 + r'"'
    r"|"
    r'"seed"\s*:\s*"' + _HEX64 + r'"[\s\S]{0,200}?"public"\s*:\s*"' + _HEX64 + r'"'
    r")"
)


def _tracked_files():
    result = subprocess.run(
        ["git", "ls-files"],
        cwd=str(REPO_ROOT),
        check=True,
        stdout=subprocess.PIPE,
    )
    return [line for line in result.stdout.decode("utf-8").splitlines() if line]


def scan_tracked_secrets():
    findings = []
    for relative in _tracked_files():
        allowed = relative.startswith(ALLOWLIST_PREFIX)
        path = REPO_ROOT / relative
        data = path.read_bytes()
        # PEM private blocks are never allowed anywhere, including fixtures
        # (the Rekor fixture only carries PUBLIC SPKI PEMs).
        for marker in PEM_PRIVATE_PATTERNS:
            if marker in data:
                findings.append((relative, "PEM private key block: {}".format(
                    marker.decode("ascii"))))
        if allowed:
            continue
        if relative.endswith(".key.json"):
            findings.append((relative, "tracked Ed25519 secret container file name"))
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        match = SECRET_CONTAINER_PATTERN.search(text)
        if match:
            line = text.count("\n", 0, match.start()) + 1
            findings.append((relative, "Ed25519 secret container near line {}".format(line)))
    return findings


def test_tracked_tree_is_free_of_private_key_material():
    findings = scan_tracked_secrets()
    assert findings == []


def test_scanner_detects_rendered_secret_container(tmp_path):
    from scripts import keysmith_signing as signing
    from scripts import keysmith_trust as trust

    seed = bytes(range(32))
    container = signing.render_json(trust.make_secret_container(seed)).decode("ascii")
    assert SECRET_CONTAINER_PATTERN.search(container)

    reordered = container.replace('"public"', '"zz-public"')
    # Sanity: the pattern needs all three fields, so damaging one hides it.
    assert SECRET_CONTAINER_PATTERN.search(reordered) is None

    hand_written = (
        '{\n  "keytype": "ed25519",\n  "seed": "' + "ab" * 32 + '",\n'
        '  "public": "' + "cd" * 32 + '"\n}\n'
    )
    assert SECRET_CONTAINER_PATTERN.search(hand_written)


def test_fixture_directory_contains_only_public_rekor_pem():
    for path in (REPO_ROOT / ALLOWLIST_PREFIX.rstrip("/")).rglob("*.pem"):
        text = path.read_text("utf-8", errors="replace")
        assert "BEGIN PUBLIC KEY" in text
        for marker in PEM_PRIVATE_PATTERNS:
            assert marker.decode("ascii") not in text
