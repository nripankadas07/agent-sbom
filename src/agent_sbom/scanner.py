"""Deterministic, deliberately conservative static scanner.

The scanner reports evidence, not intent.  Its rules are small enough to inspect
and its output is stable enough to diff in CI.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from . import SCHEMA_VERSION, __version__


IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    "artifacts",
}

TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".jsonc",
    ".toml",
    ".yaml",
    ".yml",
    ".py",
    ".sh",
    ".bash",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".ps1",
}

SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".ps1"}
MANIFEST_NAMES = {"mcp.json", ".mcp.json", "mcp.jsonc", "package.json", "pyproject.toml"}
PROMPT_MARKERS = {"prompt", "instruction", "agents.md", "claude.md", "skill.md"}

# Capability, regex, severity, short rationale.  Regexes intentionally trade
# recall for inspectability; evidence and explicit limits prevent false certainty.
RULES: Sequence[Tuple[str, re.Pattern[str], str, str]] = (
    (
        "destructive",
        re.compile(r"(\brm\s+-[^\n]*r|['\"]rm['\"]\s*,\s*['\"]-r|shutil\.rmtree|os\.unlink|\.unlink\(|git\s+reset\s+--hard|drop\s+table|delete\s+from)", re.I),
        "high",
        "May remove files, rewrite version-control state, or delete data.",
    ),
    (
        "credential",
        re.compile(r"(api[_-]?key|access[_-]?token|password|client[_-]?secret|\.ssh/|credentials|\.env\b|os\.environ|getenv\()", re.I),
        "high",
        "References credentials, secret-bearing environment data, or credential files.",
    ),
    (
        "process",
        re.compile(r"(subprocess\.|os\.system\(|child_process|\bexec(?:file|sync)?\s*\(|\bspawn(?:sync)?\s*\(|\bcurl\b|\bwget\b|\bsh\s+-c\b|\bbash\s+-c\b)", re.I),
        "medium",
        "May create a process or invoke a shell command.",
    ),
    (
        "network",
        re.compile(r"(https?://|\brequests\.|\burllib\.|\bhttpx\.|\bsocket\.|\bfetch\s*\(|\bcurl\b|\bwget\b|websocket)", re.I),
        "medium",
        "May communicate with a network endpoint.",
    ),
    (
        "browser",
        re.compile(r"(playwright|selenium|puppeteer|chromedriver|browser\.(?:open|navigate)|chrome\.)", re.I),
        "medium",
        "May automate or inspect a browser.",
    ),
    (
        "write",
        re.compile(
            r"(write_text\(|write_bytes\(|writeFile|appendFile|"
            r"open\([^\n]*(?:['\"]w|['\"]a)|\bapply_patch\b|"
            r"\btee(?:\s+-[A-Za-z]+\s+|\s+)\S+|"
            r"(?:^|&&|\|\||;)\s*(?:\$\s*)?"
            r"(?:echo|printf|cat|sed|awk|grep|find|curl|wget|python3?|node|npm|npx|bash|sh)\b"
            r"[^\n]*\s(?:[12]?>>?|&>)\s*\S+)",
            re.I,
        ),
        "medium",
        "May write or append filesystem content.",
    ),
    (
        "filesystem",
        re.compile(r"(read_text\(|read_bytes\(|readFile|\bopen\s*\(|\bpathlib\b|\bos\.walk\b|\bglob\s*\(|\bcat\s+[^|])", re.I),
        "low",
        "May inspect local filesystem content.",
    ),
)

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _stable_id(kind: str, path: str) -> str:
    digest = hashlib.sha256((kind + "\0" + path).encode("utf-8")).hexdigest()[:16]
    return "urn:agent-sbom:%s:%s" % (kind, digest)


def _regular_lstat(path: Path) -> Optional[os.stat_result]:
    """Return metadata only for an existing, non-symlink regular file."""
    try:
        metadata = path.lstat()
    except OSError:
        return None
    return metadata if stat.S_ISREG(metadata.st_mode) else None


def _inspect_file(
    path: Path, limit: int = 1_000_000
) -> Optional[Tuple[str, bool, str, int]]:
    """Hash a stable regular file while retaining only a bounded text prefix.

    Traversal filters special files before this function is called. The second
    lstat plus non-blocking open and fstat identity check close the useful race
    windows without ever waiting on a FIFO that replaces a regular file.
    """
    before = _regular_lstat(path)
    if before is None:
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError:
        return None
    opened = os.fstat(descriptor)
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_dev != before.st_dev
        or opened.st_ino != before.st_ino
    ):
        os.close(descriptor)
        return None
    digest = hashlib.sha256()
    prefix = bytearray()
    size = 0
    with os.fdopen(descriptor, "rb") as handle:
        while True:
            chunk = handle.read(64 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            remaining = limit - len(prefix)
            if remaining > 0:
                prefix.extend(chunk[:remaining])
    return prefix.decode("utf-8", errors="replace"), size > limit, digest.hexdigest(), size


def _redact_evidence(value: str) -> str:
    value = value.strip().replace("\t", " ")
    value = re.sub(
        r"(?i)(api[_-]?key|access[_-]?token|password|secret)(\s*[:=]\s*)[^\s,'\"]+",
        r"\1\2<redacted>",
        value,
    )
    if re.search(r"(?i)(api[_-]?key|access[_-]?token|password|secret|credential)", value):
        value = re.sub(r"(['\"])[A-Za-z0-9_.:/+-]{12,}\1", r"\1<redacted>\1", value)
    return value[:200]


def _classify(relative: str, path: Path) -> str:
    name = path.name.lower()
    lowered = relative.lower()
    if name == "skill.md":
        return "agent-skill"
    if name in MANIFEST_NAMES or "mcp" in name and path.suffix.lower() in {".json", ".jsonc", ".yaml", ".yml"}:
        return "manifest"
    if path.suffix.lower() in SCRIPT_SUFFIXES:
        return "script"
    if any(marker in lowered for marker in PROMPT_MARKERS):
        return "prompt"
    return "document"


def _iter_files(root: Path) -> Iterable[Path]:
    for current, dirs, files in os.walk(str(root)):
        dirs[:] = sorted(
            directory
            for directory in dirs
            if directory not in IGNORED_DIRS
            and not directory.startswith(".pytest")
            and not (Path(current) / directory).is_symlink()
        )
        for filename in sorted(files):
            path = Path(current) / filename
            if (
                _regular_lstat(path) is not None
                and (path.suffix.lower() in TEXT_SUFFIXES or path.name.lower() in MANIFEST_NAMES)
            ):
                yield path


def _declared_tools(text: str, path: Path) -> List[str]:
    if path.suffix.lower() != ".json" or "mcp" not in path.name.lower():
        return []
    try:
        payload = json.loads(text)
    except (ValueError, TypeError):
        return []
    found: Set[str] = set()

    def visit(value: Any, parent: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_text = str(key)
                if parent.lower() in {"tools", "mcpservers", "servers"}:
                    found.add(key_text)
                visit(child, key_text)
        elif isinstance(value, list):
            for child in value:
                visit(child, parent)

    visit(payload)
    return sorted(found)


def scan(root_value: str) -> Dict[str, Any]:
    supplied_root = Path(root_value)
    if supplied_root.is_symlink():
        raise ValueError("scan root must not be a symbolic link: %s" % root_value)
    root = supplied_root.resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError("scan root must be an existing directory: %s" % root_value)

    root_component_id = _stable_id("project", ".")
    components: List[Dict[str, Any]] = [
        {
            "id": root_component_id,
            "kind": "project",
            "path": ".",
            "sha256": "",
            "capabilities": [],
            "declared_tools": [],
        }
    ]
    relationships: List[Dict[str, str]] = []
    findings: List[Dict[str, Any]] = []
    capability_index: Dict[str, Set[str]] = {}

    for path in _iter_files(root):
        relative = path.relative_to(root).as_posix()
        inspected = _inspect_file(path)
        if inspected is None:
            continue
        text, truncated, digest, size = inspected
        kind = _classify(relative, path)
        component_id = _stable_id(kind, relative)
        capabilities: Set[str] = set()
        component_findings: List[Dict[str, Any]] = []
        lines = text.splitlines()
        for line_number, line in enumerate(lines, 1):
            for capability, pattern, severity, rationale in RULES:
                if pattern.search(line):
                    capabilities.add(capability)
                    finding = {
                        "id": "%s:%s:%d" % (capability, component_id.rsplit(":", 1)[-1], line_number),
                        "rule": "capability/%s" % capability,
                        "severity": severity,
                        "component_id": component_id,
                        "path": relative,
                        "line": line_number,
                        "evidence": _redact_evidence(line),
                        "message": rationale,
                    }
                    component_findings.append(finding)
        component_findings.sort(key=lambda item: (item["path"], item["line"], item["rule"]))
        findings.extend(component_findings)
        capabilities_sorted = sorted(capabilities)
        components.append(
            {
                "id": component_id,
                "kind": kind,
                "path": relative,
                "sha256": digest,
                "size": size,
                "truncated": truncated,
                "capabilities": capabilities_sorted,
                "declared_tools": _declared_tools(text, path),
            }
        )
        capability_index[component_id] = capabilities
        relationships.append({"from": root_component_id, "type": "contains", "to": component_id})

    components.sort(key=lambda item: (item["path"], item["kind"]))
    relationships.sort(key=lambda item: (item["from"], item["type"], item["to"]))
    findings.sort(
        key=lambda item: (-SEVERITY_RANK[item["severity"]], item["path"], item["line"], item["rule"])
    )
    aggregate_capabilities = sorted({cap for caps in capability_index.values() for cap in caps})
    summary = {
        "components": len(components),
        "files": max(0, len(components) - 1),
        "findings": len(findings),
        "high": sum(1 for item in findings if item["severity"] == "high"),
        "medium": sum(1 for item in findings if item["severity"] == "medium"),
        "low": sum(1 for item in findings if item["severity"] == "low"),
        "capabilities": aggregate_capabilities,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "scanner_version": __version__,
        "subject": {"name": root.name, "root": "."},
        "summary": summary,
        "components": components,
        "relationships": relationships,
        "findings": findings,
        "limits": [
            "Rules are lexical heuristics and do not prove runtime behavior or intent.",
            "Dynamic imports, generated code, encoded payloads, and remote content may be missed.",
            "Evidence can include comments or documentation and therefore can be a false positive.",
            "Only text-like files up to one megabyte are inspected.",
            "Symbolic-link roots, files, and directories are never followed.",
        ],
    }


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _string_list(value: Any, field: str) -> List[str]:
    if not isinstance(value, list) or any(not _non_empty_string(item) for item in value):
        raise ValueError("%s must be a list of non-empty strings" % field)
    if len(set(value)) != len(value):
        raise ValueError("%s must not contain duplicates" % field)
    return value


def validate_artifact(value: Any, label: str = "artifact") -> Mapping[str, Any]:
    """Validate the complete canonical shape consumed by ``diff``."""
    if not isinstance(value, dict):
        raise ValueError("%s must be a JSON object" % label)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("%s schema_version must be %s" % (label, SCHEMA_VERSION))
    if not _non_empty_string(value.get("scanner_version")):
        raise ValueError("%s.scanner_version must be a non-empty string" % label)

    subject = value.get("subject")
    if not isinstance(subject, dict) or not _non_empty_string(subject.get("name")):
        raise ValueError("%s.subject.name must be a non-empty string" % label)
    if subject.get("root") != ".":
        raise ValueError("%s.subject.root must be '.'" % label)

    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("%s.components must be a non-empty list" % label)
    component_ids: Set[str] = set()
    component_paths: Set[str] = set()
    component_capabilities: Set[str] = set()
    components_by_id: Dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(components):
        field = "%s.components[%d]" % (label, index)
        if not isinstance(item, dict):
            raise ValueError("%s must be an object" % field)
        for key in ("id", "kind", "path"):
            if not _non_empty_string(item.get(key)):
                raise ValueError("%s.%s must be a non-empty string" % (field, key))
        if item["id"] in component_ids or item["path"] in component_paths:
            raise ValueError("%s contains a duplicate id or path" % field)
        component_ids.add(item["id"])
        component_paths.add(item["path"])
        components_by_id[item["id"]] = item
        capabilities = _string_list(item.get("capabilities"), "%s.capabilities" % field)
        _string_list(item.get("declared_tools"), "%s.declared_tools" % field)
        component_capabilities.update(capabilities)
        if item["path"] == ".":
            if item["kind"] != "project":
                raise ValueError("%s.kind must be project for the project component" % field)
            if item.get("sha256") != "":
                raise ValueError("%s.sha256 must be empty for the project component" % field)
        else:
            digest = item.get("sha256")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise ValueError("%s.sha256 must be a lowercase SHA-256 digest" % field)
            if type(item.get("size")) is not int or item["size"] < 0:
                raise ValueError("%s.size must be a non-negative integer" % field)
            if type(item.get("truncated")) is not bool:
                raise ValueError("%s.truncated must be a boolean" % field)
    if "." not in component_paths:
        raise ValueError("%s.components must include the project component" % label)
    project_id = next(item["id"] for item in components if item["path"] == ".")

    relationships = value.get("relationships")
    if not isinstance(relationships, list):
        raise ValueError("%s.relationships must be a list" % label)
    relationship_values: Set[Tuple[str, str, str]] = set()
    for index, item in enumerate(relationships):
        field = "%s.relationships[%d]" % (label, index)
        if not isinstance(item, dict) or item.get("type") != "contains":
            raise ValueError("%s must be a contains relationship object" % field)
        if not _non_empty_string(item.get("from")) or not _non_empty_string(item.get("to")):
            raise ValueError("%s endpoints must be non-empty strings" % field)
        if item.get("from") not in component_ids or item.get("to") not in component_ids:
            raise ValueError("%s references an unknown component" % field)
        relationship = (item["from"], item["type"], item["to"])
        if relationship in relationship_values:
            raise ValueError("%s duplicates a relationship" % field)
        relationship_values.add(relationship)
    expected_relationships = {
        (project_id, "contains", item["id"])
        for item in components
        if item["path"] != "."
    }
    if relationship_values != expected_relationships:
        raise ValueError("%s.relationships does not match project components" % label)

    findings = value.get("findings")
    if not isinstance(findings, list):
        raise ValueError("%s.findings must be a list" % label)
    finding_ids: Set[str] = set()
    for index, item in enumerate(findings):
        field = "%s.findings[%d]" % (label, index)
        if not isinstance(item, dict):
            raise ValueError("%s must be an object" % field)
        for key in ("id", "rule", "path", "evidence", "message"):
            if not _non_empty_string(item.get(key)):
                raise ValueError("%s.%s must be a non-empty string" % (field, key))
        if item["id"] in finding_ids:
            raise ValueError("%s.id must be unique" % field)
        finding_ids.add(item["id"])
        if not isinstance(item.get("severity"), str) or item["severity"] not in SEVERITY_RANK:
            raise ValueError("%s.severity is invalid" % field)
        if not _non_empty_string(item.get("component_id")):
            raise ValueError("%s.component_id must be a non-empty string" % field)
        if item["component_id"] not in component_ids:
            raise ValueError("%s.component_id references an unknown component" % field)
        if item["path"] != components_by_id[item["component_id"]]["path"]:
            raise ValueError("%s.path does not match its component" % field)
        if type(item.get("line")) is not int or item["line"] < 1:
            raise ValueError("%s.line must be a positive integer" % field)

    summary = value.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("%s.summary must be an object" % label)
    for key in ("components", "files", "findings", "high", "medium", "low"):
        if type(summary.get(key)) is not int or summary[key] < 0:
            raise ValueError("%s.summary.%s must be a non-negative integer" % (label, key))
    summary_capabilities = _string_list(
        summary.get("capabilities"), "%s.summary.capabilities" % label
    )
    expected_counts = {
        "components": len(components),
        "files": len(components) - 1,
        "findings": len(findings),
        "high": sum(1 for item in findings if item["severity"] == "high"),
        "medium": sum(1 for item in findings if item["severity"] == "medium"),
        "low": sum(1 for item in findings if item["severity"] == "low"),
    }
    for key, expected in expected_counts.items():
        if summary[key] != expected:
            raise ValueError("%s.summary.%s does not match artifact contents" % (label, key))
    if set(summary_capabilities) != component_capabilities:
        raise ValueError("%s.summary.capabilities does not match components" % label)
    _string_list(value.get("limits"), "%s.limits" % label)
    return value


def diff_artifacts(before: Mapping[str, Any], after: Mapping[str, Any]) -> Dict[str, Any]:
    before = validate_artifact(before, "before artifact")
    after = validate_artifact(after, "after artifact")

    def component_map(value: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
        return {str(item["path"]): item for item in value.get("components", []) if item.get("path") != "."}

    old = component_map(before)
    new = component_map(after)
    old_paths = set(old)
    new_paths = set(new)
    changed = sorted(path for path in old_paths & new_paths if old[path].get("sha256") != new[path].get("sha256"))
    old_caps = set(before.get("summary", {}).get("capabilities", []))
    new_caps = set(after.get("summary", {}).get("capabilities", []))
    old_finding_ids = {item.get("id") for item in before.get("findings", [])}
    introduced = [item for item in after.get("findings", []) if item.get("id") not in old_finding_ids]
    return {
        "schema_version": "agent-sbom-diff/v1",
        "added_components": sorted(new_paths - old_paths),
        "removed_components": sorted(old_paths - new_paths),
        "changed_components": changed,
        "added_capabilities": sorted(new_caps - old_caps),
        "removed_capabilities": sorted(old_caps - new_caps),
        "introduced_findings": introduced,
        "summary": {
            "added": len(new_paths - old_paths),
            "removed": len(old_paths - new_paths),
            "changed": len(changed),
            "introduced_findings": len(introduced),
        },
    }


def cyclonedx(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    components = []
    for item in artifact.get("components", []):
        if item.get("path") == ".":
            continue
        properties = [
            {"name": "agent-sbom:kind", "value": str(item.get("kind", ""))},
            {"name": "agent-sbom:path", "value": str(item.get("path", ""))},
        ]
        properties.extend(
            {"name": "agent-sbom:capability", "value": capability}
            for capability in item.get("capabilities", [])
        )
        components.append(
            {
                "type": "file",
                "bom-ref": item.get("id"),
                "name": item.get("path"),
                "hashes": [{"alg": "SHA-256", "content": item.get("sha256", "")}],
                "properties": properties,
            }
        )
    dependencies: Dict[str, List[str]] = {}
    for relation in artifact.get("relationships", []):
        dependencies.setdefault(str(relation["from"]), []).append(str(relation["to"]))
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "agent-sbom", "version": __version__}]},
            "component": {"type": "application", "name": artifact.get("subject", {}).get("name", "project")},
            "properties": [{"name": "agent-sbom:schema", "value": SCHEMA_VERSION}],
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": sorted(values)} for ref, values in sorted(dependencies.items())
        ],
    }


def sarif(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    capabilities = sorted({item["rule"] for item in artifact.get("findings", [])})
    rules = [
        {
            "id": rule,
            "name": rule.replace("/", "_"),
            "shortDescription": {"text": "Heuristic evidence for %s" % rule},
            "helpUri": "https://github.com/nripankadas07/agent-sbom#heuristic-limits",
        }
        for rule in capabilities
    ]
    level = {"high": "error", "medium": "warning", "low": "note"}
    results = []
    for item in artifact.get("findings", []):
        results.append(
            {
                "ruleId": item["rule"],
                "level": level[item["severity"]],
                "message": {"text": "%s Evidence: %s" % (item["message"], item["evidence"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": item["path"]},
                            "region": {"startLine": item["line"]},
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "agent-sbom", "version": __version__, "rules": rules}}, "results": results}],
    }
