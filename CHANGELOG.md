# Changelog

## 0.1.1 - 2026-08-16

- Stage complete report bundles and publish them through symlink-safe,
  descriptor-relative atomic renames with backup/rollback on failure; reject
  every unverified path symlink and non-regular artifact target, and fail closed
  when descriptor-relative operations are unavailable.
- Fail closed when a stable regular input file or walked directory cannot be
  read instead of silently publishing an incomplete scan.
- Require component capabilities, finding rules, severities, and canonical IDs
  to agree during artifact validation.
- Percent-encode SARIF artifact paths as URI references.
- Publish SPDX `License-Expression` and bundled license metadata in wheels.
- Traverse from a pinned root descriptor and reopen every descendant directory
  beneath it, rejecting ancestor symlink swaps and non-canonical/control-bearing
  artifact paths; validate supported component kinds and an empty project
  capability/tool set.
- Serialize cooperating bundle writers with a verified-directory advisory lock,
  reconcile renames that complete before reporting an error, and guard ownership
  across every descriptor/stream error path.
- Ship tests, fixtures, examples, demo goldens, and documentation in the sdist;
  build, extract, run its full suite, and build the release wheel from it in CI.

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
