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

    def test_bom_stripped(self):
        # UTF-8 BOM at start should be silently dropped.
        d = yaml_lite.loads("﻿key: value\n")
        self.assertEqual(d, {"key": "value"})

    def test_empty_returns_none(self):
        self.assertIsNone(yaml_lite.loads(""))
        self.assertIsNone(yaml_lite.loads("   \n  \n"))

    def test_multidoc_separators(self):
        text = "a: 1\n---\nb: 2\n...\nc: 3\n"
        d = yaml_lite.loads(text)
        # Multi-doc returns a list.
        self.assertIsInstance(d, list)
        self.assertEqual(d[0], {"a": 1})
        self.assertEqual(d[1], {"b": 2})
        self.assertEqual(d[2], {"c": 3})

    def test_load_all_returns_list(self):
        # load_all always returns a list, even with one doc.
        out = yaml_lite.load_all("only: here\n")
        self.assertEqual(out, [{"only": "here"}])

    def test_block_scalar_literal(self):
        text = "msg: |\n  line one\n  line two\n"
        d = yaml_lite.loads(text)
        self.assertEqual(d["msg"], "line one\nline two")

    def test_block_scalar_folded(self):
        text = "msg: >\n  line one\n  line two\n"
        d = yaml_lite.loads(text)
        self.assertEqual(d["msg"], "line one line two")

    def test_inline_block_scalar_marker(self):
        # `key: |literal-text` form (rare).
        text = "key: |\n  raw text\n"
        d = yaml_lite.loads(text)
        self.assertEqual(d["key"], "raw text")

    def test_quoted_scalars_with_escapes(self):
        d = yaml_lite.loads('key: "with \\"escapes\\" and \\n newline"\n')
        self.assertEqual(d["key"], 'with "escapes" and \n newline')

    def test_single_quoted_with_doubled(self):
        # Single-quoted: `''` represents a single `'`.
        d = yaml_lite.loads("key: 'it''s here'\n")
        self.assertEqual(d["key"], "it's here")

    def test_scalar_types(self):
        d = yaml_lite.loads("i: 42\nf: 3.14\nt: true\nf2: false\nn: null\nz: ~\n")
        self.assertEqual(d, {"i": 42, "f": 3.14, "t": True, "f2": False, "n": None, "z": None})

    def test_flow_mapping_and_sequence(self):
        d = yaml_lite.loads("inline_map: {a: 1, b: 2}\ninline_seq: [x, y, z]\n")
        self.assertEqual(d["inline_map"], {"a": 1, "b": 2})
        self.assertEqual(d["inline_seq"], ["x", "y", "z"])

    def test_flow_split_top_respects_nested_brackets(self):
        # _split_top must NOT split commas inside nested {} or [].
        # yaml_lite is documented as not recursing flow scalars, so the inner
        # `{a: 1}` ends up as a string — but the splitter must keep it intact.
        d = yaml_lite.loads("nested: [{a: 1}, {b: 2}]\n")
        self.assertEqual(d["nested"], ["{a: 1}", "{b: 2}"])

    def test_seq_of_mappings_inline(self):
        text = "items:\n  - name: a\n    val: 1\n  - name: b\n    val: 2\n"
        d = yaml_lite.loads(text)
        self.assertEqual(d["items"], [{"name": "a", "val": 1}, {"name": "b", "val": 2}])

    def test_comment_after_value(self):
        d = yaml_lite.loads("key: value  # comment\nother: more\n")
        self.assertEqual(d["key"], "value")
        self.assertEqual(d["other"], "more")

    def test_hash_inside_quoted_value_not_a_comment(self):
        d = yaml_lite.loads('key: "v#alue"\n')
        self.assertEqual(d["key"], "v#alue")

    def test_key_with_empty_value_then_dedent(self):
        # `key:` with no value at end of doc → None.
        d = yaml_lite.loads("a: 1\nempty:\n")
        self.assertEqual(d, {"a": 1, "empty": None})


if __name__ == "__main__":
    unittest.main()
