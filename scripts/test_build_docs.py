# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise disposable mdBook inputs and strict build failure propagation."""

from pathlib import Path
import random
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import build_docs
from policy import ROOT


class DocumentationBuildTests(unittest.TestCase):
    def test_script_types_and_attributes(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        cases = [
            ('<SCRIPT nonce="example">window.value=1;</SCRIPT>', True),
            ('<script type="text/javascript">window.value=1;</script>', True),
            ('<script type="application/javascript">window.value=1;</script>', True),
            ('<script type="module">export const value=1;</script>', True),
            ('<script type="application/ld+json">{"value":1}</script>', False),
            ('<script type="application/json">{"value":1}</script>', False),
            ('<script src="local.js">ignored</script>', False),
            ('<p>No script</p>', False),
        ]
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            page = output / "index.html"
            for text, changed in cases:
                with self.subTest(text=text):
                    page.write_text(text)
                    build_docs.externalize_scripts(output)
                    self.assertEqual(page.read_text() != text, changed)
                    if "nonce" in text:
                        self.assertIn('nonce="example"', page.read_text())

    def test_bounded_script_text_round_trip(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        generator = random.Random(30)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            page = output / "index.html"
            for _ in range(64):
                code = "// " + "".join(generator.choices("abc<>\"'&;= /", k=128))
                page.write_text(f"<script>{code}</script>")
                build_docs.externalize_scripts(output)
                parser = build_docs.ScriptAttributes()
                parser.feed(page.read_text())
                script = output / parser.attributes["src"]
                self.assertEqual(script.read_text(), code)

    def test_theme_scripts_are_local_deduplicated_and_unchanged(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            nested = output / "guide" / "index.html"
            nested.parent.mkdir()
            code = 'window.example = "<value>";'
            text = f'<script>{code}</script><script type="application/json">{{"key":1}}</script><script src="local.js"></script>'
            for page in (output / "index.html", nested):
                page.write_text(text)
            build_docs.externalize_scripts(output)
            scripts = list((output / "assets" / "site-scripts").glob("*.js"))
            self.assertEqual(len(scripts), 1)
            self.assertEqual(scripts[0].read_text(), code)
            self.assertIn('<script src="assets/site-scripts/', (output / "index.html").read_text())
            self.assertIn('<script src="../assets/site-scripts/', nested.read_text())
            for page in (output / "index.html", nested):
                self.assertIn('<script type="application/json">{"key":1}</script>', page.read_text())
                self.assertIn('<script src="local.js"></script>', page.read_text())
                self.assertNotIn(f'<script>{code}</script>', page.read_text())
            before = nested.read_text()
            build_docs.externalize_scripts(output)
            self.assertEqual(nested.read_text(), before)

    def test_not_found_scripts_use_the_deployment_base_path(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as temporary:
            output = Path(temporary)
            page = output / "404.html"
            page.write_text("<script>window.example=1;</script>")
            build_docs.externalize_scripts(output, "https://example.org/anonce/")
            self.assertIn('<script src="/anonce/assets/site-scripts/', page.read_text())

    def test_configuration_disables_external_features_and_uses_local_paths(self):
        config = tomllib.loads((ROOT / "book.toml").read_text())
        self.assertEqual(config["book"]["src"], "source")
        self.assertEqual(config["build"]["build-dir"], "site")
        self.assertFalse(config["build"]["create-missing"])
        html = config["output"]["html"]
        self.assertEqual(html["theme"], "theme")
        self.assertFalse(html["mathjax-support"])
        self.assertFalse(html["smart-punctuation"])
        self.assertFalse(html["playground"]["runnable"])
        self.assertFalse(html["playground"]["copy-js"])
        self.assertTrue(html["search"]["enable"])

    def test_tracked_inputs_strict_command_exit_status_and_cleanup(self):
        scratch = ROOT / ".cache" / "tests"
        scratch.mkdir(parents=True, exist_ok=True)
        for result in (0, 3, "warning", "missing index", OSError("builder unavailable")):
            with self.subTest(result=result), tempfile.TemporaryDirectory(dir=scratch) as temporary:
                root = Path(temporary)
                configuration = (ROOT / "book.toml").read_text()
                (root / "book.toml").write_text(configuration)
                tracked = ["README.md", "SUMMARY.md", "docs/guide.md", "docs/openapi.yaml", "LICENSES/MIT.txt", "LICENSE"]
                theme = "docs/theme/fonts/fonts.css"
                for name in [*tracked, "Makefile", "untracked.md"]:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(name)
                (root / theme).parent.mkdir(parents=True)
                (root / theme).write_text("system fonts")
                listing = subprocess.CompletedProcess([], 0, "\x00".join([*tracked, theme, "Makefile", ""]).encode())
                configurations = []
                sources = []
                (root / "site").mkdir()
                (root / "site" / "old.html").write_text("previous site")
                (root / ".cache").mkdir()
                (root / ".cache" / "keep").write_text("unrelated cache")

                def run(command, **kwargs):
                    if command == ["mdbook", "--version"]:
                        return subprocess.CompletedProcess(command, 0, "mdbook v0.5.4\n", "")
                    self.assertEqual(command[:2], ["mdbook", "build"])
                    self.assertEqual(kwargs["cwd"], root)
                    self.assertEqual(kwargs["env"]["MDBOOK_LOG"], "info")
                    self.assertNotIn("MDBOOK_BOOK__SRC", kwargs["env"])
                    config = Path(command[2]) / "book.toml"
                    configurations.append(config)
                    self.assertEqual(config.read_text(), configuration)
                    source = config.parent / "source"
                    sources.append(source)
                    output = config.parent / "site"
                    self.assertEqual(output, config.parent / "site")
                    self.assertEqual((config.parent / "theme/fonts/fonts.css").read_text(), "system fonts")
                    output.mkdir()
                    if result != "missing index":
                        (output / "index.html").write_text("new site")
                    actual = sorted(p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file())
                    self.assertEqual(actual, sorted(tracked))
                    if isinstance(result, OSError):
                        raise result
                    return subprocess.CompletedProcess(command, result if isinstance(result, int) else 0, "", "WARN invalid input\n" if result == "warning" else "")

                with patch.object(build_docs, "ROOT", root), \
                        patch.object(build_docs, "git", return_value=listing), \
                        patch.object(build_docs, "copy_notices"), \
                        patch.object(build_docs.subprocess, "run", side_effect=run), \
                        patch.dict("os.environ", {"MDBOOK_BOOK__SRC": "/outside", "MDBOOK_LOG": "error"}), \
                        patch("sys.argv", ["build_docs.py", "--command", "mdbook"]):
                    if isinstance(result, OSError):
                        with self.assertRaises(OSError):
                            build_docs.main()
                    elif isinstance(result, str):
                        with self.assertRaises(ValueError):
                            build_docs.main()
                    else:
                        self.assertEqual(build_docs.main(), result)
                self.assertEqual(len(configurations), 1)
                self.assertFalse(configurations[0].exists())
                self.assertFalse(sources[0].parent.exists())
                self.assertEqual((root / ".cache" / "keep").read_text(), "unrelated cache")
                self.assertEqual((root / "site" / "old.html").exists(), result != 0)
                self.assertEqual((root / "site" / "index.html").exists(), result == 0)

    def test_wrong_builder_version_is_rejected(self):
        result = subprocess.CompletedProcess([], 0, "mdbook v0.0.0\n", "")
        with patch.object(build_docs.subprocess, "run", return_value=result), \
                patch("sys.argv", ["build_docs.py"]), self.assertRaises(ValueError):
            build_docs.main()

    def test_readme_links_use_rendered_index_names(self):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            output = Path(directory)
            page = output / "index.html"
            page.write_text('<a href="docs/README.html#scope">docs</a><a href="../README.html">home</a><a href="https://example.invalid/README.html">external</a>')
            build_docs.normalize_chapter_links(output)
            self.assertEqual(page.read_text(), '<a href="docs/index.html#scope">docs</a><a href="../index.html">home</a><a href="https://example.invalid/README.html">external</a>')
            missing = output / "404.html"
            missing.write_text('<base href="/anonce/"><h1 id="missing">Missing</h1><a href="#missing">heading</a>')
            build_docs.normalize_chapter_links(output)
            self.assertIn('href="404.html#missing"', missing.read_text())

    def test_rendered_links_anchors_resources_and_scripts(self):
        scratch = ROOT / ".cache/tests"
        scratch.mkdir(parents=True, exist_ok=True)
        cases = [
            ('<a href="guide.html#section">guide</a>', True),
            ('<a href="https://example.invalid/">reference</a>', True),
            ('<a href="guide.html#absent">guide</a>', False),
            ('<a href="absent.html">absent</a>', False),
            ('<a href="../outside">escape</a>', False),
            ('<a href="javascript:alert(1)">script</a>', False),
            ('<script src="https://example.invalid/code.js"></script>', False),
            ('<img src="//example.invalid/track.png">', False),
            ('<script>window.value=1;</script>', False),
            ('<button onclick="run()">button</button>', False),
        ]
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            output = Path(directory)
            (output / "guide.html").write_text('<h1 id="section">Section</h1>')
            for text, valid in cases:
                with self.subTest(text=text):
                    (output / "index.html").write_text(text)
                    if valid:
                        build_docs.validate_site(output, "/anonce/")
                    else:
                        with self.assertRaises(ValueError):
                            build_docs.validate_site(output, "/anonce/")
            (output / "index.html").write_text('<base href="/anonce/"><a href="guide.html#section">guide</a>')
            build_docs.validate_site(output, "/anonce/")
            (output / "remote.css").write_text('@import "https://example.invalid/font.css";')
            with self.assertRaises(ValueError):
                build_docs.validate_site(output, "/anonce/")


if __name__ == "__main__":
    unittest.main()
