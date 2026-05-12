import unittest

from tests.conftest_path import FIXTURES  # noqa: F401
from scs import yaml_lite


class TestYamlLite(unittest.TestCase):
    def test_simple_map(self):
        d = yaml_lite.loads("a: 1\nb: hello\nc: true\n")
        self.assertEqual(d, {"a": 1, "b": "hello", "c": True})

    def test_nested(self):
        d = yaml_lite.loads("foo:\n  bar: 1\n  baz: two\n")
        self.assertEqual(d, {"foo": {"bar": 1, "baz": "two"}})

    def test_seq(self):
        d = yaml_lite.loads("- a\n- b\n- c\n")
        self.assertEqual(d, ["a", "b", "c"])

    def test_quoted(self):
        d = yaml_lite.loads('key: "value with: colon"\n')
        self.assertEqual(d, {"key": "value with: colon"})

    def test_workflow_uses(self):
        text = """
name: CI
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: npm install
"""
        d = yaml_lite.loads(text)
        self.assertEqual(d["name"], "CI")
        self.assertIn("build", d["jobs"])


if __name__ == "__main__":
    unittest.main()
