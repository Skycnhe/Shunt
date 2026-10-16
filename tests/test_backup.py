"""备份/恢复：文件名解析、非法 tar 拒绝、路径穿越防护"""
import io
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shunt import backup


class TestParseName(unittest.TestCase):
    def test_normal(self):
        self.assertEqual(backup._parse_name("shunt-backup-v7.11.1-20261016-194500.tar.gz"), "7.11.1")

    def test_version_with_dash(self):
        # 非贪婪匹配：版本号含 - 时仍正确解析
        self.assertEqual(backup._parse_name("shunt-backup-v7.11.1-beta-20261016-194500.tar.gz"),
                         "7.11.1-beta")

    def test_with_suffix(self):
        self.assertEqual(backup._parse_name("shunt-backup-v7.11.1-20261016-194500-2.tar.gz"),
                         "7.11.1")

    def test_invalid(self):
        self.assertIsNone(backup._parse_name("shunt-backup-v7.11.1.tar.gz"))
        self.assertIsNone(backup._parse_name("evil.tar.gz"))


class TestRestoreSafety(unittest.TestCase):
    def _make_tar(self, members):
        """members: [(name, kind)] kind in ('file', 'symlink', 'hardlink')"""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, kind in members:
                ti = tarfile.TarInfo(name)
                if kind == "symlink":
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = "/etc/passwd"
                elif kind == "hardlink":
                    ti.type = tarfile.LNKTYPE
                    ti.linkname = "server.py"
                else:
                    data = b"x"
                    ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data))
                    continue
                tf.addfile(ti)
        buf.seek(0)
        return buf.read()

    def test_reject_symlink(self):
        raw = self._make_tar([("server.py", "file"), ("evil", "symlink")])
        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "shunt-backup-v9.9.9-20261016-000000.tar.gz")
            with open(fp, "wb") as f:
                f.write(raw)
            # 劫持 BACKUP_DIR 到临时目录
            old = backup.BACKUP_DIR
            backup.BACKUP_DIR = td
            try:
                ok, msg = backup.restore("shunt-backup-v9.9.9-20261016-000000.tar.gz")
                self.assertFalse(ok)
                self.assertIn("非法链接", msg)
            finally:
                backup.BACKUP_DIR = old

    def test_reject_hardlink(self):
        raw = self._make_tar([("server.py", "file"), ("evil", "hardlink")])
        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "shunt-backup-v9.9.9-20261016-000001.tar.gz")
            with open(fp, "wb") as f:
                f.write(raw)
            old = backup.BACKUP_DIR
            backup.BACKUP_DIR = td
            try:
                ok, msg = backup.restore("shunt-backup-v9.9.9-20261016-000001.tar.gz")
                self.assertFalse(ok)
                self.assertIn("非法链接", msg)
            finally:
                backup.BACKUP_DIR = old

    def test_reject_dotdot(self):
        raw = self._make_tar([("../evil", "file")])
        with tempfile.TemporaryDirectory() as td:
            fp = os.path.join(td, "shunt-backup-v9.9.9-20261016-000002.tar.gz")
            with open(fp, "wb") as f:
                f.write(raw)
            old = backup.BACKUP_DIR
            backup.BACKUP_DIR = td
            try:
                ok, msg = backup.restore("shunt-backup-v9.9.9-20261016-000002.tar.gz")
                self.assertFalse(ok)
                self.assertIn("非法", msg)
            finally:
                backup.BACKUP_DIR = old

    def test_delete_rejects_traversal(self):
        ok, msg = backup.delete("../../etc/passwd")
        self.assertFalse(ok)
        ok, msg = backup.delete("..\\evil.tar.gz")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()
