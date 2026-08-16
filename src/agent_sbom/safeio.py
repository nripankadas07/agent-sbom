"""Symlink-safe transactional text output helpers."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - exercised by the fail-closed mock
    fcntl = None  # type: ignore


Metadata = Tuple[int, int, int]


def _supports_descriptor_relative_io() -> bool:
    return all(
        function in os.supports_dir_fd
        for function in (os.open, os.mkdir, os.rename, os.stat, os.unlink)
    ) and os.stat in os.supports_follow_symlinks


def _identity(metadata: os.stat_result) -> Metadata:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _close_owned_fd(descriptor: int) -> None:
    """Close exactly once without masking an exception already in flight."""
    active_error = sys.exc_info()[0] is not None
    try:
        os.close(descriptor)
    except BaseException:
        if not active_error:
            raise


def _close_owned_handle(handle) -> None:
    """Close a stream exactly once without masking an active exception."""
    active_error = sys.exc_info()[0] is not None
    try:
        handle.close()
    except BaseException:
        if not active_error:
            raise


def _acquire_directory_lock(directory_fd: int) -> None:
    if fcntl is None or not hasattr(fcntl, "flock"):
        raise OSError("secure output requires advisory directory locking")
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
    except OSError as exc:
        raise OSError("cannot acquire secure output-directory lock: %s" % exc) from exc


def _release_directory_lock(directory_fd: int) -> None:
    active_error = sys.exc_info()[0] is not None
    if fcntl is None or not hasattr(fcntl, "flock"):
        if not active_error:
            raise OSError("secure output advisory lock became unavailable")
        return
    try:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
    except OSError as exc:
        if not active_error:
            raise OSError("cannot release secure output-directory lock: %s" % exc) from exc


def _normalize_verified_darwin_var_alias(path: Path) -> Path:
    """Normalize only Darwin's verified, root-owned /var system alias."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if sys.platform != "darwin" or len(absolute.parts) < 2 or absolute.parts[1] != "var":
        return absolute

    alias = Path("/var")
    expected = Path("/private/var")
    try:
        alias_before = alias.lstat()
        alias_target = os.readlink(str(alias))
        target_before = alias.stat()
        expected_target = expected.stat()
        alias_after = alias.lstat()
        target_after = alias.stat()
    except OSError:
        return absolute

    if (
        stat.S_ISLNK(alias_before.st_mode)
        and alias_before.st_uid == 0
        and alias_target in {"private/var", "/private/var"}
        and _identity(alias_before) == _identity(alias_after)
        and stat.S_ISDIR(target_before.st_mode)
        and target_before.st_uid == 0
        and _identity(target_before) == _identity(target_after)
        and _identity(target_before) == _identity(expected_target)
    ):
        return expected.joinpath(*absolute.parts[2:])
    return absolute


def _open_output_directory(path: Path) -> Tuple[Path, int]:
    """Create and identity-check every real output-directory component."""
    absolute = _normalize_verified_darwin_var_alias(path)
    components = absolute.parts[1:]
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(absolute.anchor or os.sep, flags)
    try:
        for component in components:
            try:
                os.mkdir(component, mode=0o755, dir_fd=descriptor)
            except FileExistsError:
                pass
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                raise ValueError(
                    "output path component must not be a symbolic link: %s" % component
                )
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError(
                    "output path component is not a real directory: %s" % component
                )
            child = os.open(component, flags, dir_fd=descriptor)
            try:
                opened = os.fstat(child)
                after = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or _identity(before) != _identity(opened)
                    or _identity(after) != _identity(opened)
                ):
                    raise ValueError(
                        "output path component changed during open: %s" % component
                    )
            except BaseException:
                owned_child = child
                child = -1
                _close_owned_fd(owned_child)
                raise
            owned_parent = descriptor
            descriptor = -1
            try:
                _close_owned_fd(owned_parent)
            except BaseException:
                owned_child = child
                child = -1
                _close_owned_fd(owned_child)
                raise
            descriptor = child
            child = -1
        return absolute, descriptor
    except BaseException:
        if descriptor >= 0:
            owned_descriptor = descriptor
            descriptor = -1
            _close_owned_fd(owned_descriptor)
        raise


def _metadata_at(directory_fd: int, name: str) -> Optional[Metadata]:
    try:
        return _identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False))
    except FileNotFoundError:
        return None


def _preflight_at(
    directory_fd: int, names: Mapping[str, str]
) -> Dict[str, Optional[Metadata]]:
    originals: Dict[str, Optional[Metadata]] = {}
    for name in names:
        if Path(name).name != name or name in {"", ".", ".."}:
            raise ValueError("output artifact name must be a plain filename: %r" % name)
        metadata = _metadata_at(directory_fd, name)
        if metadata is not None and not stat.S_ISREG(metadata[2]):
            raise ValueError("refusing to replace non-regular output artifact: %s" % name)
        originals[name] = metadata
    return originals


def _verify_at(directory_fd: int, name: str, expected: Optional[Metadata]) -> None:
    current = _metadata_at(directory_fd, name)
    if current != expected:
        raise ValueError("output artifact changed during publication: %s" % name)


def _create_stage_at(directory_fd: int, name: str, content: str) -> Tuple[str, Metadata]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    temporary = ""
    for _ in range(20):
        temporary = ".%s.tmp-%s" % (name, secrets.token_hex(8))
        try:
            descriptor = os.open(temporary, flags, 0o600, dir_fd=directory_fd)
            break
        except FileExistsError:
            continue
    else:
        raise OSError("could not allocate a unique output file for %s" % name)

    handle = None
    try:
        handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="")
        descriptor = -1
        try:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = _identity(os.fstat(handle.fileno()))
        finally:
            owned_handle = handle
            handle = None
            _close_owned_handle(owned_handle)
    except BaseException:
        if descriptor >= 0:
            owned_descriptor = descriptor
            descriptor = -1
            _close_owned_fd(owned_descriptor)
        if handle is not None:
            owned_handle = handle
            handle = None
            _close_owned_handle(owned_handle)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise
    return temporary, metadata


def _reserve_backup_at(directory_fd: int, name: str) -> Tuple[str, Metadata]:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    backup = ""
    try:
        for _ in range(20):
            backup = ".%s.bak-%s" % (name, secrets.token_hex(8))
            try:
                descriptor = os.open(backup, flags, 0o600, dir_fd=directory_fd)
                break
            except FileExistsError:
                continue
        else:
            raise OSError("could not allocate a unique backup file for %s" % name)
        metadata = _identity(os.fstat(descriptor))
        owned_descriptor = descriptor
        descriptor = -1
        _close_owned_fd(owned_descriptor)
        return backup, metadata
    except BaseException:
        if descriptor >= 0:
            owned_descriptor = descriptor
            descriptor = -1
            _close_owned_fd(owned_descriptor)
        if backup:
            try:
                os.unlink(backup, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        raise


def _rename_at(directory_fd: int, source: str, target: str) -> None:
    os.rename(
        source,
        target,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )


def _rename_reconciled_at(
    directory_fd: int,
    source: str,
    target: str,
    expected_source: Metadata,
    expected_target: Optional[Metadata],
) -> None:
    """Rename and reconcile the state if the syscall reports ambiguously."""
    _verify_at(directory_fd, source, expected_source)
    _verify_at(directory_fd, target, expected_target)
    try:
        _rename_at(directory_fd, source, target)
    except OSError as error:
        source_after = _metadata_at(directory_fd, source)
        target_after = _metadata_at(directory_fd, target)
        if source_after is None and target_after == expected_source:
            return
        if source_after == expected_source and target_after == expected_target:
            raise
        raise OSError(
            "filesystem rename state is ambiguous for %s -> %s" % (source, target)
        ) from error
    _verify_at(directory_fd, source, None)
    _verify_at(directory_fd, target, expected_source)


def _unlink_at(directory_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=directory_fd)
    except FileNotFoundError:
        pass


def _rollback_at(
    directory_fd: int,
    originals: Mapping[str, Optional[Metadata]],
    backups: Mapping[str, Tuple[str, Metadata]],
    backups_moved: List[str],
    published: List[str],
) -> List[str]:
    errors: List[str] = []
    mutated = list(dict.fromkeys(backups_moved + published))
    for name in reversed(mutated):
        try:
            _unlink_at(directory_fd, name)
        except OSError as error:
            errors.append("remove %s: %s" % (name, error))
    for name in reversed(backups_moved):
        backup, _ = backups[name]
        expected = originals[name]
        if expected is None:
            errors.append("restore %s: original metadata is missing" % name)
            continue
        try:
            _verify_at(directory_fd, backup, expected)
            _rename_reconciled_at(
                directory_fd,
                backup,
                name,
                expected,
                None,
            )
        except (OSError, ValueError) as error:
            errors.append("restore %s: %s" % (name, error))
    return errors


def _transactional_write_at(
    directory_fd: int,
    files: Mapping[str, str],
) -> None:
    originals = _preflight_at(directory_fd, files)
    stages: Dict[str, Tuple[str, Metadata]] = {}
    backups: Dict[str, Tuple[str, Metadata]] = {}
    backups_moved: List[str] = []
    published: List[str] = []
    try:
        for name, content in files.items():
            stages[name] = _create_stage_at(directory_fd, name, content)
        for name, expected in originals.items():
            _verify_at(directory_fd, name, expected)

        for name, expected in originals.items():
            if expected is None:
                continue
            backup, placeholder = _reserve_backup_at(directory_fd, name)
            backups[name] = (backup, placeholder)
            _verify_at(directory_fd, name, expected)
            _rename_reconciled_at(
                directory_fd, name, backup, expected, placeholder
            )
            backups_moved.append(name)
            _verify_at(directory_fd, backup, expected)

        for name in files:
            stage, expected = stages[name]
            _verify_at(directory_fd, stage, expected)
            _verify_at(directory_fd, name, None)
            _rename_reconciled_at(directory_fd, stage, name, expected, None)
            published.append(name)
            _verify_at(directory_fd, name, expected)

        try:
            os.fsync(directory_fd)
        except OSError:
            pass
    except BaseException as error:
        rollback_errors = _rollback_at(
            directory_fd, originals, backups, backups_moved, published
        )
        cleanup_errors: List[str] = []
        for stage, _ in stages.values():
            try:
                _unlink_at(directory_fd, stage)
            except OSError as cleanup_error:
                cleanup_errors.append("remove stage %s: %s" % (stage, cleanup_error))
        for name, (backup, _) in backups.items():
            if name not in backups_moved:
                try:
                    _unlink_at(directory_fd, backup)
                except OSError as cleanup_error:
                    cleanup_errors.append(
                        "remove backup %s: %s" % (backup, cleanup_error)
                    )
        try:
            os.fsync(directory_fd)
        except OSError:
            pass
        rollback_errors.extend(cleanup_errors)
        if rollback_errors:
            raise OSError(
                "output transaction rollback was incomplete: %s"
                % "; ".join(rollback_errors)
            ) from error
        raise

    for name, (backup, _) in backups.items():
        _verify_at(directory_fd, backup, originals[name])
    for backup, _ in backups.values():
        _unlink_at(directory_fd, backup)
    try:
        os.fsync(directory_fd)
    except OSError:
        pass


def write_text_files(output_value: str, files: Mapping[str, str]) -> Path:
    """Transactionally replace text artifacts without following path links."""
    output = Path(output_value)
    if not _supports_descriptor_relative_io():
        raise OSError(
            "secure output requires descriptor-relative filesystem operations"
        )
    directory_fd = -1
    try:
        _, directory_fd = _open_output_directory(output)
        _acquire_directory_lock(directory_fd)
        try:
            _transactional_write_at(directory_fd, files)
        finally:
            _release_directory_lock(directory_fd)
    finally:
        if directory_fd >= 0:
            owned_directory_fd = directory_fd
            directory_fd = -1
            _close_owned_fd(owned_directory_fd)
    return output


def write_text_file(path_value: str, content: str) -> Path:
    """Transactionally replace one text file without following path links."""
    path = Path(path_value)
    if not path.name:
        raise ValueError("output path must name a file")
    write_text_files(str(path.parent), {path.name: content})
    return path
