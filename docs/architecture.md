# Architecture

The pipeline is intentionally linear and deterministic:

1. Walk text-like regular files in lexical path order while excluding build,
   vendor, symbolic-link, device, socket, and FIFO paths.
2. Classify each file as project metadata, agent skill, manifest, prompt,
   script, or document.
3. Apply an ordered set of inspectable regular-expression rules line by line.
4. Attach capability evidence to content-addressed component identifiers.
5. Build `contains` relationships from the project component to file
   components.
6. Serialize the canonical `agent-sbom/v1` artifact and derive all reports from
   it.

Each regular file is read once in fixed-size chunks. The full stream feeds its
SHA-256 digest while only the first one megabyte is retained for text rules.
Traversal checks file type without opening it. A non-blocking, no-follow open
then verifies the descriptor is still the same regular file, so a path swap
cannot turn inspection into a blocking FIFO read.

The canonical artifact never contains an absolute scan path, current time, or
random identifier. Given identical bytes and scanner version, it is stable
across machines. `diff` operates only on artifacts; it does not rescan or run
source code. Both inputs are first validated as complete `agent-sbom/v1`
artifacts, including cross-references and summary counts.

CycloneDX and SARIF are projections. `agent-sbom.json` remains the source of
truth because standard SBOM formats do not yet model every agent capability.
