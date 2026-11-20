"""Offline integrity checks for the vendored Bridge production bundle."""
from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path
from urllib.parse import unquote


BRIDGE = Path(__file__).resolve().parents[1] / "vendor" / "auth-bridge"
EXCLUDED_DIRECTORIES = {"node_modules", "tests", "test", "runtime", ".venv", "__pycache__"}
# Keep quoted strings intact while excluding commented-out module references.
COMMENTS = re.compile(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`)|//[^\n]*|/\*[\s\S]*?\*/''')
MODULE_REFERENCES = re.compile(
    r'''(?:^[ \t]*(?:import|export)\s+(?:[^;]*?\bfrom\s*)?|\bimport\s*\(\s*)(['"])(?P<module>[^'"]+)\1''',
    re.MULTILINE,
)


def production_modules():
    for directory, children, filenames in os.walk(BRIDGE):
        children[:] = sorted(name for name in children if name not in EXCLUDED_DIRECTORIES)
        for filename in sorted(filenames):
            if filename.endswith((".js", ".mjs")) and not filename.endswith((".test.js", ".test.mjs")):
                yield Path(directory) / filename


def module_references(source):
    source = COMMENTS.sub(lambda match: match.group(1) or "\n" * match.group(0).count("\n"), source)
    for match in MODULE_REFERENCES.finditer(source):
        specifier = match.group("module")
        if specifier.startswith(("./", "../")):
            yield specifier


class BridgeBundleTests(unittest.TestCase):
    def test_relative_production_module_dependencies_exist(self):
        modules = list(production_modules())
        self.assertTrue(modules, "Bridge production JavaScript is absent")
        missing = []
        for module in modules:
            for specifier in module_references(module.read_text(encoding="utf-8")):
                filename = unquote(specifier.split("?", 1)[0].split("#", 1)[0])
                if not (module.parent / filename).is_file():
                    missing.append(f"{module.relative_to(BRIDGE)} -> {specifier}")
        self.assertEqual(missing, [], "Missing Bridge production modules:\n" + "\n".join(missing))

    def test_scanner_covers_static_reexports_and_string_dynamic_imports(self):
        source = '''
            import {
                handler,
            } from './src/lib/static.js';
            import './side-effect.js';
            export { helper } from '../shared.js';
            const loaded = await import('./src/lib/dynamic.js');
            import packageName from 'external-package';
            // import './commented-out.js';
            /* const ignored = import('./commented-dynamic.js'); */
        '''
        self.assertEqual(list(module_references(source)), [
            "./src/lib/static.js", "./side-effect.js", "../shared.js", "./src/lib/dynamic.js",
        ])
        self.assertIn("./login-service/server.js", list(module_references((BRIDGE / "server.js").read_text())))

    def test_whitelisted_static_assets_exist_or_have_declared_dependencies(self):
        source = (BRIDGE / "src" / "converter.js").read_text(encoding="utf-8")
        mapping = re.search(r"const STATIC_FILES = Object\.freeze\(\{([\s\S]*?)\}\);", source)
        self.assertIsNotNone(mapping, "Bridge static resource whitelist is absent")
        assets = re.findall(r'''['"]([^'"]+)['"]\s*:\s*['"]([^'"]+)['"]''', mapping.group(1))
        self.assertTrue(assets, "Bridge static resource whitelist is empty")
        dependencies = json.loads((BRIDGE / "package.json").read_text())["dependencies"]
        for route, filename in assets:
            with self.subTest(route=route):
                target = (BRIDGE / "docs" / filename).resolve()
                parts = target.relative_to(BRIDGE.resolve()).parts
                if parts[0] == "node_modules":
                    package = "/".join(parts[1:3]) if parts[1].startswith("@") else parts[1]
                    self.assertIn(package, dependencies, f"Static asset dependency is undeclared: {filename}")
                else:
                    self.assertTrue(target.is_file(), f"Missing Bridge static asset: {route} -> {filename}")


if __name__ == "__main__":
    unittest.main()
