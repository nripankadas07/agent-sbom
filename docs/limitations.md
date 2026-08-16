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
- Evidence redaction recognizes common assignments, not every secret format.
- Markdown output encodes dynamic values as literals; HTML output escapes them.

Use this report to decide what to inspect and sandbox. Do not use its absence of
findings as an authorization decision.
