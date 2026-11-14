"""Security and negative tests for rls_check.py (offline, no secrets in output, safe file handling).
Run: python3 -m unittest discover -s tests -v"""
import contextlib
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(HERE)
sys.path.insert(0, KIT)
import rls_check  # noqa: E402
from test_rls_check import fake_service_jwt  # noqa: E402

BAD = os.path.join(KIT, "examples", "bad-project")


def write(root, files):
    for rel, content in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(content, bytes) else "w"
        with open(path, mode) as fh:
            fh.write(content)


def run(*args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = rls_check.main(list(args))
    return code, out.getvalue()


class NoNetwork(unittest.TestCase):
    def test_runs_with_all_network_calls_blocked(self):
        def boom(*a, **k):
            raise AssertionError("network access attempted")
        with mock.patch.object(socket.socket, "connect", boom), \
                mock.patch.object(socket, "create_connection", boom), \
                mock.patch.object(socket, "getaddrinfo", boom):
            code, out = run(BAD, "--no-color")
        self.assertEqual(code, 1)
        self.assertIn("CRITICAL", out)

    def test_imports_no_network_modules(self):
        src = open(os.path.join(KIT, "rls_check.py"), encoding="utf-8").read()
        for mod in ("socket", "urllib", "http.client", "requests", "subprocess", "ssl"):
            self.assertNotIn("import " + mod, src)


class SecretsNeverPrinted(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.jwt = fake_service_jwt()
        self.sb = "sb_secret_" + "Zq9" * 12
        write(self.tmp.name, {
            "src/lib/admin.ts": 'export const k = "%s";\n' % self.jwt,
            "src/lib/other.ts": 'const s = "%s";\n' % self.sb,
            ".env.local": "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=%s\n" % self.jwt,
        })

    def tearDown(self):
        self.tmp.cleanup()

    def test_text_json_html_outputs_redact_values(self):
        html_path = os.path.join(self.tmp.name, "report.html")
        outputs = [run(self.tmp.name, "--no-color")[1], run(self.tmp.name, "--json")[1]]
        run(self.tmp.name, "--html", html_path)
        outputs.append(open(html_path, encoding="utf-8").read())
        for out in outputs:
            self.assertIn("KEY", out)
            self.assertNotIn(self.jwt, out)
            self.assertNotIn(self.jwt.split(".")[1], out)
            self.assertNotIn(self.sb, out)


class FileHandling(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proj = os.path.join(self.tmp.name, "project")
        self.outside = os.path.join(self.tmp.name, "outside")
        os.makedirs(self.proj)
        os.makedirs(self.outside)

    def tearDown(self):
        self.tmp.cleanup()

    def test_symlink_to_file_outside_project_is_not_read(self):
        write(self.outside, {"evil.sql": "create table public.outside_table (id int);\n"})
        os.makedirs(os.path.join(self.proj, "supabase", "migrations"))
        os.symlink(os.path.join(self.outside, "evil.sql"),
                   os.path.join(self.proj, "supabase", "migrations", "0001.sql"))
        code, out = run(self.proj, "--json")
        self.assertNotIn("outside_table", out)

    def test_symlinked_directory_is_not_followed(self):
        write(self.outside, {"supabase/migrations/0001.sql": "create table public.dir_table (id int);\n"})
        os.symlink(os.path.join(self.outside, "supabase"), os.path.join(self.proj, "supabase"))
        code, out = run(self.proj, "--json")
        self.assertNotIn("dir_table", out)

    def test_invalid_utf8_and_binary_files_do_not_crash(self):
        write(self.proj, {
            "supabase/migrations/0001.sql": b"create table public.t (id int);\n\xff\xfe\x00\x81 garbage\n",
            "src/blob.js": bytes(range(256)) * 10,
        })
        code, out = run(self.proj, "--json")
        data = json.loads(out)
        self.assertIn("findings", data)

    def test_oversized_file_is_skipped(self):
        big = "-- " + "x" * (rls_check.MAX_FILE_BYTES + 10) + "\ncreate table public.huge (id int);\n"
        write(self.proj, {"supabase/migrations/0001.sql": big})
        code, out = run(self.proj, "--json")
        self.assertNotIn("huge", out)

    def test_no_files_written_without_html_flag(self):
        write(self.proj, {"supabase/migrations/0001.sql": "create table public.t (id int);\n"})
        before = sorted(os.listdir(self.proj))
        run(self.proj, "--no-color")
        run(self.proj, "--json")
        self.assertEqual(before, sorted(os.listdir(self.proj)))

    def test_empty_project_reports_nothing_and_exits_zero(self):
        code, out = run(self.proj, "--no-color")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
