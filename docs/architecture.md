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

The scan root is opened one path component at a time without following links.
Every queued descendant is reopened relative to that pinned root descriptor,
so swapping an already-visited ancestor for a symlink cannot redirect later
file opens. Descriptor and directory-entry identities are checked around each
open. Traversal errors and failures to open a stable regular file stop the scan;
race-replaced paths that are no longer the same regular inode are skipped.

The canonical artifact never contains an absolute scan path, current time, or
random identifier. Given identical bytes and scanner version, it is stable
across machines. `diff` operates only on artifacts; it does not rescan or run
source code. Both inputs are first validated as complete `agent-sbom/v1`
artifacts, including canonical control-free POSIX paths, supported component
kinds and capabilities, cross-references, the empty project component, and
summary counts.

The complete report bundle is staged in unique regular files and flushed before
publication. A verified-directory advisory lock serializes cooperating writers
from preflight through cleanup. Existing artifacts are moved to private
backups; publication uses descriptor-relative atomic renames and restores the
complete original set if any publication fails. If a rename completes and then
reports an error, source/target inode state is reconciled before the transaction
continues or rolls back. Temporary and backup files are then removed, and file
descriptors have explicit single-owner cleanup on every failure path. Every
directory component is identity-checked and must be a real directory; Darwin's `/var`
system alias is normalized only after ownership, target, and identity checks.
Pre-existing symlinks, FIFOs, devices, or directories at artifact filenames are
rejected before staging. Platforms without the required descriptor-relative
filesystem operations fail closed. SARIF paths are percent-encoded URI
references; canonical artifact paths remain readable POSIX relative strings.

The source distribution manifest includes the full tests, fixtures, examples,
documentation, and deterministic demo artifacts. Packaging tests extract that
sdist, run its suite in place, and build the installable wheel from the extracted
tree so missing release inputs fail CI.

CycloneDX and SARIF are projections. `agent-sbom.json` remains the source of
truth because standard SBOM formats do not yet model every agent capability.
