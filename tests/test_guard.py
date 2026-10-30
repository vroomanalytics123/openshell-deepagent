"""Tests for src/guard.py — stdlib only, no sandbox or agent deps.

Run: python3 -m unittest discover -s tests -v
"""

import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.guard import refusal_reason  # noqa: E402

REFUSED = [
    "rm -rf /etc/passwd",
    "rm -rf /",
    "rm -rf /usr/lib/x",
    "rm -fr /etc",
    "rm --recursive --force /var/log",
    "rm -rf /sandbox/../etc/passwd",  # lexical .. traversal
    "rm -rf /etc; echo done",  # compound: first segment refused
    "/bin/rm -rf /etc",
    "echo hi && rm -rf /root/.ssh",
]

ALLOWED = [
    "rm -rf /sandbox/old",
    "rm -rf /tmp/x",
    "rm -rf /workspace/y",
    "rm -rf relative/path",  # resolves inside /sandbox
    "rm -rf /sandbox/../tmp/x",  # resolves inside /tmp
    "python /sandbox/x.py",
    "curl https://example.com",  # network use is the sandbox policy's job
    "echo hello",
    "rm /sandbox/file",  # no recursive+force: not the destructive form
    "rm -r /sandbox/dir",  # recursive without force: interactive form
    "rm -rf ~",  # unresolvable target: fail open, documented
    "rm -rf $HOME/x",  # unresolvable target: fail open, documented
    "rm -rf 'unbalanced",  # unparseable: fail open, documented
]


class TestRefusalReason(unittest.TestCase):
    def test_refused(self):
        for cmd in REFUSED:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(refusal_reason(cmd), cmd)

    def test_allowed(self):
        for cmd in ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertIsNone(refusal_reason(cmd), cmd)


class FakeResult:
    def __init__(self):
        self.stdout = "ok"
        self.stderr = ""
        self.exit_code = 0


class FakeSession:
    def __init__(self):
        self.id = "fake"
        self.calls = []

    def exec(self, argv, timeout_seconds=None, stdin=None):
        self.calls.append(argv)
        return FakeResult()


def _install_stubs():
    """Stub heavy deps so src.backend imports without deepagents/openshell."""
    if "deepagents" in sys.modules:
        return

    class ExecuteResponse:
        def __init__(self, output, exit_code, truncated):
            self.output = output
            self.exit_code = exit_code
            self.truncated = truncated

    class FileDownloadResponse:
        def __init__(self, path, content, error):
            self.path, self.content, self.error = path, content, error

    class FileUploadResponse:
        def __init__(self, path, error):
            self.path, self.error = path, error

    class BaseSandbox:
        pass

    backends = types.ModuleType("deepagents.backends")
    backends.CompositeBackend = object
    backends.FilesystemBackend = object
    protocol = types.ModuleType("deepagents.backends.protocol")
    protocol.ExecuteResponse = ExecuteResponse
    protocol.FileDownloadResponse = FileDownloadResponse
    protocol.FileUploadResponse = FileUploadResponse
    sandbox_mod = types.ModuleType("deepagents.backends.sandbox")
    sandbox_mod.BaseSandbox = BaseSandbox
    deepagents = types.ModuleType("deepagents")
    deepagents.backends = backends
    openshell = types.ModuleType("openshell")
    openshell.SandboxClient = object
    openshell.SandboxSession = object
    sys.modules["deepagents"] = deepagents
    sys.modules["deepagents.backends"] = backends
    sys.modules["deepagents.backends.protocol"] = protocol
    sys.modules["deepagents.backends.sandbox"] = sandbox_mod
    sys.modules["openshell"] = openshell


class TestBackendIntegration(unittest.TestCase):
    def test_refused_command_never_reaches_session(self):
        _install_stubs()
        from src.backend import OpenShellBackend

        session = FakeSession()
        backend = OpenShellBackend(session)
        resp = backend.execute("rm -rf /etc/passwd")
        self.assertEqual(resp.exit_code, 1)
        self.assertIn("refused", resp.output)
        self.assertEqual(session.calls, [])

    def test_allowed_command_reaches_session_wrapped(self):
        _install_stubs()
        from src.backend import OpenShellBackend

        session = FakeSession()
        backend = OpenShellBackend(session)
        resp = backend.execute("python /sandbox/x.py")
        self.assertEqual(resp.exit_code, 0)
        self.assertEqual(session.calls, [["bash", "-c", "python /sandbox/x.py"]])


if __name__ == "__main__":
    unittest.main()
