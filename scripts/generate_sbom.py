#!/usr/bin/env python3
"""Deterministic SBOM generator for codex-keysmith releases.

Emits two machine-readable SBOM documents for one release:

* SPDX 2.3 JSON (``*.spdx.json``)
* CycloneDX 1.6 JSON (``*.cdx.json``)

The generator is standard-library-only and deterministic: it never reads the
wall clock, environment, or network. Callers supply the release identifier
(version/line), the source commit, and an explicit ``issued_at`` timestamp.
Every shipped repository file is recorded with its size and SHA-256 digest;
desktop build inputs (npm/cargo/pip lock files) are parsed fail-closed into
third-party component inventories. Running the generator twice over the same
tree produces byte-identical documents.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from scripts import keysmith_trust as trust
from scripts.build_release import ARCHIVE_FILES

PRODUCT = trust.PRODUCT
SPDX_OUTPUT_VERSION = "SPDX-2.3"
CDX_SPEC_VERSION = "1.6"
TOOL_NAME = "codex-keysmith-generate-sbom"
TOOL_VERSION = "1.0.0"
LICENSE_LIST_VERSION = "3.25"
NPM_LOCK_VERSION = 3
CARGO_LOCK_VERSIONS = (3, 4)
SBOM_SPDX_SUFFIX = ".spdx.json"
SBOM_CDX_SUFFIX = ".cdx.json"
EXTRA_ROOTS = ("scenarios", "fixture_packs")

_SAFE_ID_PATTERN = re.compile(r"[^A-Za-z0-9.\-]+")
_SPDX_EXPRESSION_PATTERN = re.compile(r"^[A-Za-z0-9.+\-() ]+$")
_CARGO_HEADER_VERSION = re.compile(r'^version\s*=\s*(\d+)\s*$')
_CARGO_STRING = re.compile(r'^"((?:[^"\\]|\\.)*)"$')
_PIP_PIN_PATTERN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9+._-]*)$")


class SbomError(Exception):
    """Raised when an SBOM cannot be generated from the supplied inputs."""


# ---------------------------------------------------------------------------
# File inventory
# ---------------------------------------------------------------------------

def hash_file(path: Path) -> Tuple[str, int]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise SbomError("cannot stat file {}: {}".format(path, exc)) from exc
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise SbomError("cannot read file {}: {}".format(path, exc)) from exc
    return digest.hexdigest(), size


def _safe_relative(path: Path, root: Path) -> str:
    relative = path.relative_to(root)
    if any(part in ("", "..") for part in relative.parts):
        raise SbomError("file escapes repository root: {}".format(path))
    text = PurePosixPath(*relative.parts).as_posix()
    if not text or text.startswith("/") or "\\" in text:
        raise SbomError("unsafe repository-relative path: {!r}".format(text))
    return text


def _walk_root(repo_root: Path, root_name: str) -> List[str]:
    base = repo_root / root_name
    if not base.exists():
        return []
    if not base.is_dir():
        raise SbomError("expected a directory at {}".format(base))
    found: List[str] = []
    for path in sorted(base.rglob("*")):
        if path.is_symlink():
            raise SbomError("refusing to SBOM a symlinked path: {}".format(path))
        if path.is_file():
            found.append(_safe_relative(path, repo_root))
    return found


def collect_shipped_files(
    repo_root: Path,
    *,
    fixed_files: Sequence[str] = ARCHIVE_FILES,
    extra_roots: Sequence[str] = EXTRA_ROOTS,
) -> List[str]:
    """Return every shipped repository file as a sorted POSIX relative path."""

    repo_root = Path(repo_root)
    collected = set(fixed_files)
    for name in fixed_files:
        candidate = repo_root / name
        if not candidate.is_file():
            raise SbomError("declared release file is missing: {}".format(name))
    for root_name in extra_roots:
        for relative in _walk_root(repo_root, root_name):
            if relative in collected:
                raise SbomError("duplicate file across inventory roots: {}".format(relative))
            collected.add(relative)
    return sorted(collected)


# ---------------------------------------------------------------------------
# Third-party component parsers
# ---------------------------------------------------------------------------

def _spdx_license(raw: Optional[str]) -> str:
    if not raw or not isinstance(raw, str):
        return "NOASSERTION"
    text = raw.strip()
    if not text or not _SPDX_EXPRESSION_PATTERN.fullmatch(text):
        return "NOASSERTION"
    return text


def _purl_quote(name: str) -> str:
    # PURL percent-encoding for the name segment (no network usage).
    return "".join(
        ch if ch.isalnum() or ch in ".-~_" else "%{:02X}".format(ord(ch))
        for ch in name
    )


def _component_id(prefix: str, key: str) -> str:
    sanitized = _SAFE_ID_PATTERN.sub("-", key).strip("-")
    return "{}-{}".format(prefix, sanitized)[:240]


def parse_npm_lock(document: object, *, source_label: str = "gui/package-lock.json") -> List[dict]:
    if not isinstance(document, dict):
        raise SbomError("{} must be a JSON object".format(source_label))
    if document.get("lockfileVersion") != NPM_LOCK_VERSION:
        raise SbomError(
            "{} lockfileVersion must be {}".format(source_label, NPM_LOCK_VERSION)
        )
    packages = document.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise SbomError("{} must contain a non-empty 'packages' map".format(source_label))
    components: Dict[Tuple[str, str], dict] = {}
    for install_path in sorted(packages):
        if not isinstance(install_path, str):
            raise SbomError("{} has an invalid package path".format(source_label))
        # The empty key describes the project itself, not a dependency.
        if install_path == "":
            continue
        if not install_path:
            raise SbomError("{} has an empty package path".format(source_label))
        entry = packages[install_path]
        if not isinstance(entry, dict):
            raise SbomError("{} entry {!r} must be an object".format(source_label, install_path))
        name = install_path.rsplit("node_modules/", 1)[-1]
        if not name:
            raise SbomError("{} entry {!r} has no package name".format(source_label, install_path))
        version = entry.get("version")
        if not isinstance(version, str) or not version:
            raise SbomError(
                "npm package {!r} must declare a string version".format(install_path)
            )
        integrity = entry.get("integrity")
        digest_hex = None
        if integrity is not None:
            if not isinstance(integrity, str) or not integrity.startswith("sha512-"):
                raise SbomError(
                    "npm package {!r} integrity must be a sha512- value".format(install_path)
                )
            try:
                digest_bytes = base64.b64decode(integrity[len("sha512-"):], validate=True)
            except (binascii.Error, ValueError) as exc:
                raise SbomError("npm package {!r} integrity is not valid base64".format(
                    install_path)) from exc
            if len(digest_bytes) != 64:
                raise SbomError(
                    "npm package {!r} sha512 integrity must decode to 64 bytes".format(
                        install_path
                    )
                )
            digest_hex = digest_bytes.hex()
        key = (name, version)
        if key in components:
            existing = components[key]
            if digest_hex and existing["digest_hex"] and digest_hex != existing["digest_hex"]:
                raise SbomError(
                    "npm package {}@{} appears with conflicting integrity".format(
                        name, version
                    )
                )
            if digest_hex and not existing["digest_hex"]:
                existing["digest_hex"] = digest_hex
            continue
        components[key] = {
            "ecosystem": "npm",
            "name": name,
            "version": version,
            "digest_algorithm": "SHA-512" if digest_hex else None,
            "digest_hex": digest_hex,
            "license": _spdx_license(entry.get("license")),
            "purl": "pkg:npm/{}@{}".format(_purl_quote(name), _purl_quote(version)),
            "optional": bool(entry.get("dev", False)),
        }
    return sorted(components.values(), key=lambda item: (item["name"], item["version"]))


def _cargo_unquote(value: str) -> Optional[str]:
    match = _CARGO_STRING.match(value.strip())
    if not match:
        return None
    return match.group(1).replace('\\"', '"').replace("\\\\", "\\")


def parse_cargo_lock(text: str, *, source_label: str = "gui/src-tauri/Cargo.lock") -> Tuple[
    List[dict], List[Tuple[str, str]]
]:
    if not isinstance(text, str):
        raise SbomError("{} must be text".format(source_label))
    lines = text.splitlines()
    if not lines or not lines[0].startswith("#"):
        raise SbomError("{} is missing the Cargo.lock banner".format(source_label))
    header_match = None
    for line in lines[:6]:
        header_match = _CARGO_HEADER_VERSION.match(line.strip()) or header_match
    if not header_match or int(header_match.group(1)) not in CARGO_LOCK_VERSIONS:
        raise SbomError(
            "{} version must be one of {}".format(source_label, CARGO_LOCK_VERSIONS)
        )

    packages: List[dict] = []
    edges: List[Tuple[str, str]] = []
    current: Optional[dict] = None
    in_dependency_list = False

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        if not current.get("name") or not current.get("version"):
            raise SbomError("{} has a package without name/version".format(source_label))
        packages.append(current)
        current = None

    for raw_line in lines:
        stripped = raw_line.strip()
        if stripped == "[[package]]":
            flush()
            current = {"dependencies": []}
            in_dependency_list = False
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            # Any other table (e.g. [[patch.unused]]) ends package parsing.
            flush()
            current = None
            in_dependency_list = False
            continue
        if current is None:
            continue
        if in_dependency_list:
            if stripped == "]":
                in_dependency_list = False
                continue
            dep_name = _cargo_unquote(stripped.rstrip(","))
            if dep_name is None:
                raise SbomError("{} has an unparseable dependency list".format(source_label))
            current["dependencies"].append(dep_name)
            continue
        if "=" not in stripped:
            if stripped:
                raise SbomError("{} has an unparseable line: {!r}".format(source_label, stripped))
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "name":
            parsed = _cargo_unquote(value)
            if parsed is None:
                raise SbomError("{} package name is not a quoted string".format(source_label))
            current["name"] = parsed
        elif key == "version":
            parsed = _cargo_unquote(value)
            if parsed is None:
                raise SbomError("{} package version is not a quoted string".format(source_label))
            current["version"] = parsed
        elif key == "checksum":
            parsed = _cargo_unquote(value)
            if parsed is None or not re.fullmatch(r"[0-9a-f]{64}", parsed):
                raise SbomError("{} crate checksum must be 64 lowercase hex chars".format(
                    source_label))
            current["checksum"] = parsed
        elif key == "source":
            parsed = _cargo_unquote(value)
            if parsed is None:
                raise SbomError("{} package source is not quoted".format(source_label))
            current["source"] = parsed
        elif key == "dependencies":
            if value != "[":
                raise SbomError("{} dependencies must use a bracketed list".format(source_label))
            in_dependency_list = True
        # Other package keys are ignored; Cargo.lock is a controlled file.
    flush()

    by_name: Dict[str, dict] = {}
    components: List[dict] = []
    for package in packages:
        name = package["name"]
        registry = package.get("source", "").startswith("registry+")
        component = {
            "ecosystem": "cargo",
            "name": name,
            "version": package["version"],
            "digest_algorithm": "SHA-256" if package.get("checksum") else None,
            "digest_hex": package.get("checksum"),
            "license": "NOASSERTION",
            "purl": "pkg:cargo/{}@{}".format(
                _purl_quote(name), _purl_quote(package["version"])
            ) if registry else None,
            "optional": False,
        }
        components.append(component)
        previous = by_name.get(name)
        if previous is not None and previous["version"] != package["version"]:
            # Name-only dependency edges become ambiguous; leave them out.
            by_name[name] = None
        elif previous is None:
            by_name[name] = component
    for package in packages:
        source_component = by_name.get(package["name"])
        if source_component is None:
            continue
        for dependency in package["dependencies"]:
            target = by_name.get(dependency)
            if target is not None and target is not source_component:
                edges.append((source_component["purl"] or source_component["name"],
                              target["purl"] or target["name"]))
    if not packages:
        raise SbomError("{} does not contain any [[package]] entries".format(source_label))
    components.sort(key=lambda item: (item["name"], item["version"]))
    return components, sorted(set(edges))


def parse_python_pins(
    text: str, *, source_label: str = "gui/requirements-build.txt"
) -> List[dict]:
    if not isinstance(text, str):
        raise SbomError("{} must be text".format(source_label))
    components: List[dict] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIP_PIN_PATTERN.fullmatch(line)
        if not match:
            raise SbomError(
                "{} line {} must pin name==version: {!r}".format(
                    source_label, line_number, raw_line
                )
            )
        name, version = match.group(1), match.group(2)
        components.append({
            "ecosystem": "pypi",
            "name": name,
            "version": version,
            "digest_algorithm": None,
            "digest_hex": None,
            "license": "NOASSERTION",
            "purl": "pkg:pypi/{}@{}".format(_purl_quote(name.lower()), _purl_quote(version)),
            "optional": False,
        })
    components.sort(key=lambda item: (item["name"], item["version"]))
    return components


def collect_desktop_components(
    repo_root: Path,
) -> Tuple[List[dict], List[Tuple[str, str]], Dict[str, Tuple[str, int]]]:
    """Parse the three desktop lock sources; return components, edges, files."""

    repo_root = Path(repo_root)
    gui = repo_root / "gui"
    npm_path = gui / "package-lock.json"
    cargo_path = gui / "src-tauri" / "Cargo.lock"
    pip_path = gui / "requirements-build.txt"
    present = [path for path in (npm_path, cargo_path, pip_path) if path.exists()]
    if not present:
        return [], [], {}
    missing = [path for path in (npm_path, cargo_path, pip_path) if not path.exists()]
    if missing:
        raise SbomError(
            "desktop SBOM inputs are incomplete; missing: {}".format(
                ", ".join(str(path) for path in missing)
            )
        )
    try:
        npm_document = json.loads(npm_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SbomError("cannot parse {}: {}".format(npm_path, exc)) from exc
    npm_components = parse_npm_lock(npm_document)
    try:
        cargo_components, cargo_edges = parse_cargo_lock(cargo_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        raise SbomError("cannot read {}: {}".format(cargo_path, exc)) from exc
    try:
        pip_components = parse_python_pins(pip_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SbomError("cannot read {}: {}".format(pip_path, exc)) from exc
    lock_records = {}
    for path in (npm_path, cargo_path, pip_path):
        digest_hex, size = hash_file(path)
        lock_records[_safe_relative(path, repo_root)] = (digest_hex, size)
    return npm_components + cargo_components + pip_components, cargo_edges, lock_records


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------

def _unique_identifiers(items: Iterable[Tuple[str, str]], label: str) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for identifier, key in items:
        if identifier in mapping and mapping[identifier] != key:
            raise SbomError("SBOM {} identifier collision: {}".format(label, identifier))
        mapping[identifier] = key
    return mapping


def build_documents(
    *,
    repo_root: Path,
    release_line: str,
    version: str,
    issued_at: str,
    source_commit: str,
    builder: Optional[dict] = None,
    fixed_files: Sequence[str] = ARCHIVE_FILES,
    include_desktop: bool = True,
    extra_files: Sequence[Tuple[str, Path]] = (),
) -> Tuple[dict, dict, Dict[str, Tuple[str, int]]]:
    """Build (SPDX document, CycloneDX document, file records) dictionaries."""

    repo_root = Path(repo_root)
    trust.parse_semver(version, label="sbom.version")
    trust.require_iso8601_utc(issued_at, "sbom.issued_at")
    if release_line not in trust.RELEASE_LINES:
        raise SbomError("unknown release line: {!r}".format(release_line))
    if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40,64}", source_commit):
        raise SbomError("sbom source_commit must be 40-64 lowercase hex chars")
    tag = trust.expected_tag_for(release_line, version)

    shipped = collect_shipped_files(repo_root, fixed_files=fixed_files)
    file_records: Dict[str, Tuple[str, int]] = {}
    file_entries: List[dict] = []
    for relative in shipped:
        digest_hex, size = hash_file(repo_root / relative)
        file_records[relative] = (digest_hex, size)
        file_entries.append({"path": relative, "sha256": digest_hex, "size": size})

    for logical_name, candidate in extra_files:
        candidate = Path(candidate)
        trust.validate_asset_name(logical_name, "extra sbom file")
        if logical_name in file_records:
            raise SbomError("extra sbom file name already inventoried: {}".format(logical_name))
        digest_hex, size = hash_file(candidate)
        file_records[logical_name] = (digest_hex, size)
        file_entries.append({"path": logical_name, "sha256": digest_hex, "size": size})
    file_entries.sort(key=lambda item: item["path"])

    if include_desktop:
        components, cargo_edges, lock_records = collect_desktop_components(repo_root)
        for relative, record in lock_records.items():
            if relative not in file_records:
                file_records[relative] = record
                file_entries.append(
                    {"path": relative, "sha256": record[0], "size": record[1]}
                )
        file_entries.sort(key=lambda item: item["path"])
    else:
        components, cargo_edges = [], []

    # Deduplicate components across ecosystems on purl/name+version identity.
    unique: Dict[Tuple[str, str], dict] = {}
    for component in components:
        key = (component["ecosystem"], component["purl"] or component["name"])
        if key in unique:
            raise SbomError("component identity collision: {!r}".format(key))
        unique[key] = component
    components = sorted(unique.values(), key=lambda item: (
        item["ecosystem"], item["purl"] or item["name"]))

    file_ids = _unique_identifiers(
        (("SPDXRef-File-" + _SAFE_ID_PATTERN.sub("-", entry["path"]).strip("-"),
          entry["path"]) for entry in file_entries),
        "file",
    )
    component_keys = {
        ("npm", component["purl"]): _component_id("SPDXRef-Package-npm", component["purl"])
        for component in components if component["ecosystem"] == "npm"
    }
    component_keys.update({
        ("cargo", component["purl"] or component["name"]): _component_id(
            "SPDXRef-Package-cargo", component["purl"] or component["name"])
        for component in components if component["ecosystem"] == "cargo"
    })
    component_keys.update({
        ("pypi", component["purl"]): _component_id("SPDXRef-Package-pypi", component["purl"])
        for component in components if component["ecosystem"] == "pypi"
    })
    _unique_identifiers(
        ((identifier, key[0] + ":" + key[1]) for key, identifier in component_keys.items()),
        "component",
    )

    product_id = "SPDXRef-Package-{}".format(PRODUCT)
    spdx = _build_spdx(
        tag=tag,
        version=version,
        issued_at=issued_at,
        source_commit=source_commit,
        builder=builder,
        product_id=product_id,
        file_entries=file_entries,
        file_ids=file_ids,
        components=components,
        component_keys=component_keys,
        cargo_edges=cargo_edges,
    )
    cdx = _build_cyclonedx(
        tag=tag,
        release_line=release_line,
        version=version,
        issued_at=issued_at,
        source_commit=source_commit,
        builder=builder,
        product_bom_ref=product_id,
        file_entries=file_entries,
        file_ids=file_ids,
        components=components,
        component_keys=component_keys,
        cargo_edges=cargo_edges,
    )
    return spdx, cdx, file_records


def _builder_properties(builder: Optional[dict]) -> List[Tuple[str, str]]:
    if not builder:
        return []
    return sorted(
        ("builder.{}".format(key), str(value))
        for key, value in builder.items()
        if not isinstance(value, (dict, list))
    )


def _build_spdx(*, tag, version, issued_at, source_commit, builder, product_id,
                file_entries, file_ids, components, component_keys, cargo_edges) -> dict:
    document_id = "SPDXRef-DOCUMENT"
    namespace = "https://{}.invalid/sbom/{}/{}".format(PRODUCT, tag, source_commit[:12])
    root_package = {
        "SPDXID": product_id,
        "name": PRODUCT,
        "versionInfo": version,
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "MIT",
        "licenseDeclared": "MIT",
        "copyrightText": "NOASSERTION",
        "externalRefs": [
            {"referenceCategory": "PERSISTENT-ID", "referenceType": "swh",
             "referenceLocator": "swh:1:rev:{}".format(source_commit)},
        ],
    }
    packages = [root_package]
    for component in components:
        key = (component["ecosystem"], component["purl"] or component["name"])
        package = {
            "SPDXID": component_keys[key],
            "name": "{}:{}".format(component["ecosystem"], component["name"]),
            "versionInfo": component["version"],
            "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": component["license"],
            "copyrightText": "NOASSERTION",
        }
        if component["purl"]:
            package["externalRefs"] = [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                 "referenceLocator": component["purl"]},
            ]
        if component["digest_hex"]:
            spdx_algorithm = "SHA256" if component["digest_algorithm"] == "SHA-256" else "SHA512"
            package["checksums"] = [
                {"algorithm": spdx_algorithm, "checksumValue": component["digest_hex"]},
            ]
        packages.append(package)

    files = []
    for entry in file_entries:
        identifier = next(
            spdx_id for spdx_id, path in file_ids.items() if path == entry["path"]
        )
        files.append({
            "SPDXID": identifier,
            "fileName": "./" + entry["path"],
            "checksums": [{"algorithm": "SHA256", "checksumValue": entry["sha256"]}],
            "licenseConcluded": "MIT",
            "copyrightText": "NOASSERTION",
        })

    relationships = [
        {"spdxElementId": document_id, "relationshipType": "DESCRIBES",
         "relatedSpdxElement": product_id},
    ]
    for identifier in sorted(file_ids):
        relationships.append({
            "spdxElementId": product_id, "relationshipType": "CONTAINS",
            "relatedSpdxElement": identifier,
        })
    for identifier in sorted(component_keys.values()):
        relationships.append({
            "spdxElementId": product_id, "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": identifier,
        })
    id_by_component = dict(
        ((ecosystem, locator), spdx_id)
        for (ecosystem, locator), spdx_id in component_keys.items()
    )
    for source_locator, target_locator in cargo_edges:
        source_id = id_by_component.get(("cargo", source_locator))
        target_id = id_by_component.get(("cargo", target_locator))
        if source_id and target_id:
            relationships.append({
                "spdxElementId": source_id, "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": target_id,
            })

    document = {
        "spdxVersion": SPDX_OUTPUT_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": document_id,
        "name": "{}-{}-spdx".format(PRODUCT, tag),
        "documentNamespace": namespace,
        "creationInfo": {
            "created": issued_at,
            "creators": [
                "Tool: {} {}".format(TOOL_NAME, TOOL_VERSION),
                "Organization: {} offline release trust".format(PRODUCT),
            ],
            "licenseListVersion": LICENSE_LIST_VERSION,
        },
        "documentDescribes": [product_id],
        "packages": packages,
        "files": files,
        "relationships": relationships,
    }
    properties = _builder_properties(builder)
    if properties:
        document["annotations"] = [{
            "annotator": "Tool: {} {}".format(TOOL_NAME, TOOL_VERSION),
            "annotationDate": issued_at,
            "annotationType": "OTHER",
            "annotationText": json.dumps(
                [{"name": name, "value": value} for name, value in properties],
                separators=(",", ":"), sort_keys=True,
            ),
        }]
    return document


def _license_choice(component: dict):
    if component["license"] == "NOASSERTION":
        return None
    return [{"expression": component["license"]}]


def _build_cyclonedx(*, tag, release_line, version, issued_at, source_commit, builder,
                     product_bom_ref, file_entries, file_ids, components,
                     component_keys, cargo_edges) -> dict:
    serial_seed = "{}:{}:{}:{}".format(PRODUCT, release_line, tag, source_commit)
    serial_number = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, serial_seed))

    cdx_components = []
    file_ref_by_path = {path: spdx_id for spdx_id, path in file_ids.items()}
    for entry in file_entries:
        cdx_components.append({
            "type": "file",
            "bom-ref": file_ref_by_path[entry["path"]],
            "name": entry["path"],
            "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}],
            "properties": [{"name": "codex-keysmith:size", "value": str(entry["size"])}],
        })
    for component in components:
        key = (component["ecosystem"], component["purl"] or component["name"])
        item = {
            "type": "library",
            "bom-ref": component_keys[key],
            "name": component["name"],
            "version": component["version"],
            "purl": component["purl"],
        }
        if not item["purl"]:
            del item["purl"]
        licenses = _license_choice(component)
        if licenses:
            item["licenses"] = licenses
        if component["digest_hex"]:
            item["hashes"] = [{
                "alg": component["digest_algorithm"], "content": component["digest_hex"],
            }]
        if component["optional"]:
            item["scope"] = "optional"
        cdx_components.append(item)

    product_dependencies = sorted(
        [ref for ref in file_ids] + list(dict.fromkeys(component_keys.values()))
    )
    dependencies = [{"ref": product_bom_ref, "dependsOn": product_dependencies}]
    id_by_component = dict(
        ((ecosystem, locator), bom_ref)
        for (ecosystem, locator), bom_ref in component_keys.items()
    )
    cargo_dependency_map: Dict[str, set] = {}
    for source_locator, target_locator in cargo_edges:
        source_ref = id_by_component.get(("cargo", source_locator))
        target_ref = id_by_component.get(("cargo", target_locator))
        if source_ref and target_ref:
            cargo_dependency_map.setdefault(source_ref, set()).add(target_ref)
    for ref in sorted(cargo_dependency_map):
        dependencies.append({"ref": ref, "dependsOn": sorted(cargo_dependency_map[ref])})

    metadata = {
        "timestamp": issued_at,
        "tools": {"components": [{
            "type": "application", "name": TOOL_NAME, "version": TOOL_VERSION,
        }]},
        "component": {
            "type": "application",
            "bom-ref": product_bom_ref,
            "name": PRODUCT,
            "version": version,
            "purl": "pkg:generic/{}@{}".format(_purl_quote(PRODUCT), _purl_quote(version)),
            "properties": [
                {"name": "codex-keysmith:release-line", "value": release_line},
                {"name": "codex-keysmith:tag", "value": tag},
                {"name": "codex-keysmith:source-commit", "value": source_commit},
            ],
        },
    }
    for name, value in _builder_properties(builder):
        metadata["component"]["properties"].append({"name": name, "value": value})
    metadata["component"]["properties"].sort(key=lambda prop: prop["name"])

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": cdx_components,
        "dependencies": dependencies,
    }


def render_document(document: dict) -> bytes:
    """Canonical deterministic JSON rendering of an SBOM document."""

    return (
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def sbom_asset_names(tag: str) -> Tuple[str, str]:
    return (
        "{}-{}-sbom{}".format(PRODUCT, tag, SBOM_SPDX_SUFFIX),
        "{}-{}-sbom{}".format(PRODUCT, tag, SBOM_CDX_SUFFIX),
    )


def write_sbom_documents(
    spdx_document: dict,
    cdx_document: dict,
    *,
    out_dir: Path,
    tag: str,
) -> Dict[str, Dict[str, object]]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    spdx_name, cdx_name = sbom_asset_names(tag)
    outputs = ((spdx_name, render_document(spdx_document)),
               (cdx_name, render_document(cdx_document)))
    records: Dict[str, Dict[str, object]] = {}
    for name, data in outputs:
        target = out_dir / name
        trust.atomic_write(target, data, mode=0o644)
        records[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return records


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _load_builder(value: Optional[str]) -> Optional[dict]:
    if not value:
        return None
    try:
        document = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SbomError("--builder-json must be valid JSON: {}".format(exc)) from exc
    if not isinstance(document, dict):
        raise SbomError("--builder-json must be a JSON object")
    return document


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Generate deterministic release SBOMs")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--release-line", required=True, choices=trust.RELEASE_LINES)
    parser.add_argument("--version", required=True)
    parser.add_argument("--issued-at", required=True,
                        help="deterministic UTC ISO-8601 timestamp; the clock is never read")
    parser.add_argument("--commit", required=True, help="verified source commit (hex)")
    parser.add_argument("--builder-json", default=None, help="optional JSON object string")
    parser.add_argument("--no-desktop", action="store_true",
                        help="skip gui lock-file component inventory")
    parser.add_argument("--fixed-file", action="append", dest="fixed_files",
                        help="override the shipped fixed-file set (repeatable; "
                             "defaults to build_release.ARCHIVE_FILES)")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)

    try:
        spdx_document, cdx_document, _ = build_documents(
            repo_root=Path(args.repo_root),
            release_line=args.release_line,
            version=args.version,
            issued_at=args.issued_at,
            source_commit=args.commit,
            builder=_load_builder(args.builder_json),
            include_desktop=not args.no_desktop,
            fixed_files=tuple(args.fixed_files) if args.fixed_files else ARCHIVE_FILES,
        )
        tag = trust.expected_tag_for(args.release_line, args.version)
        records = write_sbom_documents(
            spdx_document, cdx_document, out_dir=Path(args.out_dir), tag=tag
        )
    except (SbomError, trust.TrustError) as exc:
        print("generate-sbom: {}".format(exc), file=sys.stderr)
        return 1
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
