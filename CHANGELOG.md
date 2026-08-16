# Changelog

## 0.1.0 - 2026-08-16

- Initial deterministic scanner and `agent-sbom/v1` artifact.
- Capability evidence, component relationships, diff, CycloneDX, SARIF,
  Markdown, and HTML reports.
- Offline fixture demo and unit/integration tests.
- Symlink-safe traversal and one-pass bounded inspection with streaming hashes.
- Self-contained installed-wheel demo fixtures and clean-wheel regression coverage.
- Skip special files before opening and revalidate regular-file identity after
  a non-blocking, no-follow open.
- Validate complete artifact shape and `agent-sbom/v1` compatibility before
  diffing, with controlled CLI input errors.
- Encode all dynamic Markdown report fields as literals.
