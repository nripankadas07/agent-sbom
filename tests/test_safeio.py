import errno
import multiprocessing
import os
import tempfile
import traceback
import unittest
from pathlib import Path
from queue import Empty
from unittest import mock

from agent_sbom import safeio


def _concurrent_writer(output, marker, start, results):
    try:
        if not start.wait(10):
            raise RuntimeError("concurrent writer start timed out")
        for iteration in range(5):
            safeio.write_text_files(
                output,
                {
                    name: "%s:%d:%s\n" % (marker, iteration, name)
                    for name in ("one.txt", "two.txt", "three.txt")
                },
            )
        results.put("")
    except BaseException:
        results.put(traceback.format_exc())


class SafeIOTests(unittest.TestCase):
    def assert_closed(self, descriptors):
        for descriptor in descriptors:
            with self.assertRaises(OSError) as raised:
                os.fstat(descriptor)
            self.assertEqual(raised.exception.errno, errno.EBADF)

    def test_concurrent_process_writers_publish_one_coherent_set(self):
        if safeio.fcntl is None or not hasattr(safeio.fcntl, "flock"):
            self.skipTest("advisory directory locks are unavailable")
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory() as temp:
            output = str(Path(temp) / "output")
            start = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=_concurrent_writer,
                    args=(output, "writer-%d" % index, start, results),
                )
                for index in range(4)
            ]
            try:
                for process in processes:
                    process.start()
                start.set()
                messages = [results.get(timeout=30) for _ in processes]
                for process in processes:
                    process.join(30)
                self.assertEqual(messages, [""] * len(processes), messages)
                self.assertTrue(all(process.exitcode == 0 for process in processes))
            except Empty as exc:
                self.fail("concurrent writer did not finish: %s" % exc)
            finally:
                for process in processes:
                    if process.is_alive():
                        process.terminate()
                    process.join(5)
                results.close()
                results.join_thread()

            values = [
                (Path(output) / name).read_text(encoding="utf-8").split(":")[:2]
                for name in ("one.txt", "two.txt", "three.txt")
            ]
            self.assertEqual(values[1:], values[:1] * 2)
            self.assertFalse(
                any(".tmp-" in path.name or ".bak-" in path.name for path in Path(output).iterdir())
            )

    def test_completed_rename_error_is_reconciled_without_residue(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            old = {"one.txt": "old-one\n", "two.txt": "old-two\n"}
            new = {"one.txt": "new-one\n", "two.txt": "new-two\n"}
            safeio.write_text_files(str(output), old)
            real_rename = safeio._rename_at
            injected = False

            def rename_then_throw(directory_fd, source, target):
                nonlocal injected
                real_rename(directory_fd, source, target)
                if not injected and ".tmp-" in source and not target.startswith("."):
                    injected = True
                    raise OSError("injected completed rename error")

            with mock.patch.object(safeio, "_rename_at", side_effect=rename_then_throw):
                safeio.write_text_files(str(output), new)

            self.assertTrue(injected)
            self.assertEqual(
                {name: (output / name).read_text(encoding="utf-8") for name in new},
                new,
            )
            self.assertFalse(
                any(".tmp-" in path.name or ".bak-" in path.name for path in output.iterdir())
            )

    def test_descriptor_ownership_survives_fdopen_fstat_and_close_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            directory_fd = os.open(temp, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                recorded = []
                real_open = os.open

                def record_open(*args, **kwargs):
                    descriptor = real_open(*args, **kwargs)
                    recorded.append(descriptor)
                    return descriptor

                with mock.patch.object(safeio.os, "open", side_effect=record_open), mock.patch.object(
                    safeio.os, "fdopen", side_effect=OSError("injected fdopen failure")
                ):
                    with self.assertRaisesRegex(OSError, "fdopen failure"):
                        safeio._create_stage_at(directory_fd, "fdopen.txt", "content")
                self.assert_closed(recorded)
                self.assertEqual(list(Path(temp).iterdir()), [])

                recorded = []
                with mock.patch.object(safeio.os, "open", side_effect=record_open), mock.patch.object(
                    safeio.os, "fstat", side_effect=OSError("injected fstat failure")
                ):
                    with self.assertRaisesRegex(OSError, "fstat failure"):
                        safeio._create_stage_at(directory_fd, "fstat.txt", "content")
                self.assert_closed(recorded)
                self.assertEqual(list(Path(temp).iterdir()), [])

                closed = []
                real_close = os.close

                def close_then_throw(descriptor):
                    real_close(descriptor)
                    closed.append(descriptor)
                    raise OSError("injected close ambiguity")

                with mock.patch.object(safeio.os, "close", side_effect=close_then_throw):
                    with self.assertRaisesRegex(OSError, "close ambiguity"):
                        safeio._reserve_backup_at(directory_fd, "close.txt")
                self.assertEqual(len(closed), 1)
                self.assert_closed(closed)
                self.assertEqual(list(Path(temp).iterdir()), [])
            finally:
                os.close(directory_fd)

    def test_directory_open_fstat_failure_closes_every_owned_descriptor(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "nested"
            opened = []
            real_open = os.open

            def record_open(*args, **kwargs):
                descriptor = real_open(*args, **kwargs)
                opened.append(descriptor)
                return descriptor

            with mock.patch.object(safeio.os, "open", side_effect=record_open), mock.patch.object(
                safeio.os, "fstat", side_effect=OSError("injected directory fstat failure")
            ):
                with self.assertRaisesRegex(OSError, "directory fstat failure"):
                    safeio._open_output_directory(output)
            self.assertGreaterEqual(len(opened), 2)
            self.assert_closed(opened)

    def test_missing_advisory_lock_fails_before_artifact_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "output"
            output.mkdir()
            victim = output / "one.txt"
            victim.write_text("original\n", encoding="utf-8")
            with mock.patch.object(safeio, "fcntl", None):
                with self.assertRaisesRegex(OSError, "advisory directory locking"):
                    safeio.write_text_files(str(output), {"one.txt": "replacement\n"})
            self.assertEqual(victim.read_text(encoding="utf-8"), "original\n")
            self.assertEqual([path.name for path in output.iterdir()], ["one.txt"])


if __name__ == "__main__":
    unittest.main()
