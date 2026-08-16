# agent-sbom

`agent-sbom` produces an inspectable, capability-aware software bill of
materials for agent projects. It scans agent skills, MCP manifests, prompts,
scripts, and configuration; preserves the exact file-and-line evidence behind
every claim; and emits stable JSON, a CycloneDX-like BOM, SARIF, Markdown, and a
single-file HTML report.

It has no runtime dependencies, runs offline on Python 3.9+, and deliberately
uses transparent lexical heuristics rather than an opaque model.

## Why

Ordinary dependency SBOMs answer “which packages are installed?” Agent systems
also need to answer “which files suggest filesystem, process, network,
credential, browser, write, or destructive capability?” This project adds that
review layer without pretending static text proves runtime behavior.

## Quick start

```bash
python -m pip install -e .
agent-sbom scan . --out artifacts/self-scan
agent-sbom demo --out artifacts/demo
```

Without installation:

```bash
PYTHONPATH=src python -m agent_sbom demo --out artifacts/demo
```

Open `artifacts/demo/report.html` in any browser. The bundled demo is inert:
its intentionally risky code is scanned, never executed.

## Commands

```text
agent-sbom scan PATH --out DIRECTORY
agent-sbom diff BEFORE_JSON AFTER_JSON [--out FILE|-]
agent-sbom demo --out DIRECTORY
```

Every scan bundle contains:

```text
agent-sbom.json      canonical agent-sbom/v1 artifact
bom.cdx.json         CycloneDX 1.6-shaped component inventory
findings.sarif       SARIF 2.1.0 findings
report.md            portable review report
report.html          self-contained visual report
checksums.sha256     deterministic artifact digests
```

`diff` accepts only complete `agent-sbom/v1` artifacts. It validates the
schema version, component and finding shapes, references, hashes, and summary
counts before comparing them; malformed or incompatible input exits with code
2 and is never partially interpreted.

## Heuristic limits

This is a review aid, not a malware verdict. A matched line can be a comment,
documentation, dead code, or safe wrapper. Dynamic imports, generated or
encoded programs, runtime downloads, and files beyond the scan limit can be
missed. Read the evidence, review the component, and use runtime isolation for
untrusted code. See [limitations](docs/limitations.md) and the
[architecture](docs/architecture.md).

## Development

```bash
make test
make demo
```

The fixture corpus contains benign and intentionally risky samples. New rules
must add both a positive and a counterexample fixture.

## Security and data handling

Scanning is local. No telemetry or network request exists in the scanner.
Evidence is truncated and common secret assignments are redacted, but source
snippets may still be sensitive. Treat reports with the same access controls as
the scanned repository. Markdown report fields are encoded as literals so a
repository name, path, or evidence line cannot create report structure or raw
HTML. See [SECURITY.md](SECURITY.md).

## License

MIT

See the [roadmap](ROADMAP.md), [research provenance](docs/research.md), and [AI-assistance disclosure](AI_ASSISTED.md).
