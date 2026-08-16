# Limitations

- Findings are lexical evidence, not proof that a capability is reachable,
  malicious, safe, or declared correctly.
- Comments and examples can create false positives.
- Aliases, reflection, encoded commands, generated files, remote prompts, and
  runtime downloads can create false negatives.
- The scanner does not resolve transitive package behavior or vulnerabilities.
- JSON-with-comments is classified but not parsed as a manifest.
- Files larger than one megabyte are scanned only through their first megabyte.
- Binary formats are out of scope.
- Symbolic-link roots, files, and directories are skipped rather than followed.
- FIFOs, sockets, devices, and every other non-regular file are skipped without
  reading.
- A stable regular file or directory that cannot be read aborts the scan rather
  than being silently omitted.
- Evidence redaction recognizes common assignments, not every secret format.
- Markdown output encodes dynamic values as literals; HTML output escapes them.
- Output path components must not be symlinks, and named artifacts must be
  regular files when they already exist. Bundle publication stages all files
  and restores the original set after an in-process publication failure, but a
  concurrent reader can briefly observe sequential atomic renames.
- The directory lock is advisory: it serializes Agent SBOM writers using this
  implementation, not unrelated processes that ignore the lock. An abrupt
  process or host failure can leave private temporary/backup files and a
  partially published set for manual recovery.
- Secure output fails closed on platforms without descriptor-relative file,
  directory, stat, rename, unlink, and advisory-lock operations.

Use this report to decide what to inspect and sandbox. Do not use its absence of
findings as an authorization decision.
