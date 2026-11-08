"""The Grep pre-check's glob: read the way ripgrep reads it, and whatever it
cannot follow widens the scan to every file, never empties it (issue #1)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.globs import MAX_ALTERNATIVES, compile_glob, select  # noqa: E402

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # the suite skips what is not installed
    given = None

ROOT = Path("/repo/data")
FILES = [
    ROOT / "patients.csv",
    ROOT / "notes.txt",
    ROOT / "app.py",
    ROOT / "2026" / "nov" / "visits.csv",
    ROOT / "2026" / "nov" / "visits.tsv",
    ROOT / "archive" / "old.json",
]


def names(pattern):
    return sorted(f.relative_to(ROOT).as_posix() for f in select(FILES, ROOT, pattern))


class Braces(unittest.TestCase):
    def test_the_issue(self):
        self.assertEqual(names("*.{csv,txt}"), ["2026/nov/visits.csv", "notes.txt", "patients.csv"])

    def test_a_single_alternative(self):
        self.assertEqual(names("patients.{csv}"), ["patients.csv"])

    def test_nested(self):
        self.assertEqual(names("*.{json,{csv,tsv}}"), [
            "2026/nov/visits.csv", "2026/nov/visits.tsv", "archive/old.json", "patients.csv",
        ])

    def test_commas_between_globs_and_inside_braces(self):
        self.assertEqual(names("*.py,*.{csv,txt}"), ["2026/nov/visits.csv", "app.py", "notes.txt", "patients.csv"])

    def test_empty_alternative(self):
        self.assertEqual(names("visits.{csv,}"), ["2026/nov/visits.csv"])


class Paths(unittest.TestCase):
    def test_no_slash_matches_the_name_at_any_depth(self):
        self.assertEqual(names("*.csv"), ["2026/nov/visits.csv", "patients.csv"])

    def test_double_star_crosses_directories_or_none(self):
        self.assertEqual(names("**/*.csv"), ["2026/nov/visits.csv", "patients.csv"])
        self.assertEqual(names("2026/**/*.csv"), ["2026/nov/visits.csv"])
        self.assertEqual(names("2026/**"), ["2026/nov/visits.csv", "2026/nov/visits.tsv"])

    def test_a_path_is_matched_under_the_search_root(self):
        self.assertEqual(names("2026/nov/*.csv"), ["2026/nov/visits.csv"])
        self.assertEqual(names("./2026/nov/*.csv"), ["2026/nov/visits.csv"])
        self.assertEqual(names("/archive/*.json"), ["archive/old.json"])

    def test_star_stays_within_a_segment(self):
        self.assertEqual(names("2026/*.csv"), [])

    def test_classes_and_question_marks(self):
        self.assertEqual(names("visits.[ct]sv"), ["2026/nov/visits.csv", "2026/nov/visits.tsv"])
        self.assertEqual(names("visits.[!t]sv"), ["2026/nov/visits.csv"])
        self.assertEqual(names("app.p?"), ["app.py"])


class WhatItCannotFollowScansEverything(unittest.TestCase):
    everything = sorted(f.relative_to(ROOT).as_posix() for f in FILES)

    def test_no_glob(self):
        self.assertEqual(names(None), self.everything)
        self.assertEqual(names(""), self.everything)

    def test_unbalanced_braces(self):
        for pattern in ("*.{csv", "*.csv}", "{a,{b}", "}{"):
            with self.subTest(pattern=pattern):
                self.assertIsNone(compile_glob(pattern))
                self.assertEqual(names(pattern), self.everything)

    def test_negation(self):
        self.assertEqual(names("!*.py"), self.everything)
        self.assertEqual(names("*.txt,!*.py"), self.everything)

    def test_escapes(self):
        self.assertEqual(names(r"\{a\}.csv"), self.everything)

    def test_unclosed_class(self):
        self.assertEqual(names("visits.[csv"), self.everything)

    def test_too_many_alternatives(self):
        pattern = "".join("{a,b}" for _ in range(9))  # 512 alternatives
        self.assertIsNone(compile_glob(pattern))
        self.assertGreater(2 ** 9, MAX_ALTERNATIVES)


if given is not None:
    _word = st.text(alphabet="abcxyz", min_size=1, max_size=4)

    class Properties(unittest.TestCase):
        @settings(max_examples=300, deadline=None)
        @given(st.text(alphabet="abc*?[]{},!/.\\", max_size=24))
        def test_any_glob_selects_a_subset_or_everything(self, pattern):
            chosen = select(FILES, ROOT, pattern)
            self.assertTrue(set(chosen) <= set(FILES))
            if compile_glob(pattern) is None:
                self.assertEqual(chosen, FILES)

        @settings(max_examples=200, deadline=None)
        @given(_word, st.lists(_word, min_size=1, max_size=5), _word)
        def test_braces_select_what_their_alternatives_select(self, head, choices, tail):
            files = [ROOT / f"{head}{c}{tail}.csv" for c in choices] + [ROOT / "other.csv"]
            braced = select(files, ROOT, f"{head}{{{','.join(choices)}}}{tail}.csv")
            spelled = select(files, ROOT, ",".join(f"{head}{c}{tail}.csv" for c in choices))
            self.assertEqual(braced, spelled)
            self.assertTrue(all(f in braced for f in files[:-1]))


if __name__ == "__main__":
    unittest.main()
