import io
import os
import shutil
import tarfile
import tempfile
import unittest
import zipfile

from ai_guard.core.safe_extract import ExtractPathError, extract_tar_archive, extract_zip_archive


class TestSafeExtractTar(unittest.TestCase):
    def test_extracts_benign_tar(self):
        td = tempfile.mkdtemp()
        try:
            tar_path = os.path.join(td, "good.tar")
            payload = b"hello"
            with tarfile.open(tar_path, "w") as tar:
                info = tarfile.TarInfo(name="safe/hello.txt")
                info.size = len(payload)
                tar.addfile(info, io.BytesIO(payload))
            out = os.path.join(td, "out")
            os.makedirs(out)
            extract_tar_archive(tar_path, out)
            p = os.path.join(out, "safe", "hello.txt")
            self.assertTrue(os.path.isfile(p))
            with open(p, "rb") as f:
                self.assertEqual(f.read(), payload)
        finally:
            shutil.rmtree(td)

    def test_rejects_parent_dir_in_tar(self):
        td = tempfile.mkdtemp()
        try:
            tar_path = os.path.join(td, "bad.tar")
            with tarfile.open(tar_path, "w") as tar:
                info = tarfile.TarInfo(name="../evil.txt")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
            out = os.path.join(td, "out")
            os.makedirs(out)
            with self.assertRaises(ExtractPathError):
                extract_tar_archive(tar_path, out)
        finally:
            shutil.rmtree(td)

    def test_rejects_absolute_path_in_tar(self):
        td = tempfile.mkdtemp()
        try:
            tar_path = os.path.join(td, "bad.tar")
            with tarfile.open(tar_path, "w") as tar:
                info = tarfile.TarInfo(name="/tmp/abs.txt")
                info.size = 0
                tar.addfile(info, io.BytesIO(b""))
            out = os.path.join(td, "out")
            os.makedirs(out)
            with self.assertRaises(ExtractPathError):
                extract_tar_archive(tar_path, out)
        finally:
            shutil.rmtree(td)


class TestSafeExtractZip(unittest.TestCase):
    def test_extracts_benign_zip(self):
        td = tempfile.mkdtemp()
        try:
            zip_path = os.path.join(td, "good.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("pkg/module.py", b"x = 1\n")
            out = os.path.join(td, "out")
            os.makedirs(out)
            extract_zip_archive(zip_path, out)
            p = os.path.join(out, "pkg", "module.py")
            self.assertTrue(os.path.isfile(p))
        finally:
            shutil.rmtree(td)

    def test_rejects_parent_dir_in_zip(self):
        td = tempfile.mkdtemp()
        try:
            zip_path = os.path.join(td, "bad.zip")
            with zipfile.ZipFile(zip_path, "w") as zf:
                zf.writestr("../evil.txt", b"no")
            out = os.path.join(td, "out")
            os.makedirs(out)
            with self.assertRaises(ExtractPathError):
                extract_zip_archive(zip_path, out)
        finally:
            shutil.rmtree(td)


class TestIngestionRegistry(unittest.TestCase):
    def test_npm_target(self):
        from ai_guard.core.ingestion import Target, TargetType

        t = Target("npm:lodash")
        self.assertEqual(t.type, TargetType.NPM_PACKAGE)
        self.assertEqual(t.registry_spec, "lodash")

    def test_npm_scoped(self):
        from ai_guard.core.ingestion import Target, TargetType

        t = Target("npm:@types/node")
        self.assertEqual(t.type, TargetType.NPM_PACKAGE)
        self.assertEqual(t.registry_spec, "@types/node")

    def test_pypi_target_strips_extras(self):
        from ai_guard.core.ingestion import Target, TargetType

        t = Target("pypi:requests[security]")
        self.assertEqual(t.type, TargetType.PYPI_PACKAGE)
        self.assertEqual(t.registry_spec, "requests")

    def test_empty_npm_unknown(self):
        from ai_guard.core.ingestion import Target, TargetType

        t = Target("npm:")
        self.assertEqual(t.type, TargetType.UNKNOWN)
