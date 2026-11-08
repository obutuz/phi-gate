"""The Grep pre-check's glob: read the way ripgrep reads it, and whatever it
cannot follow widens the scan to every file, never empties it (issue #1)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from phi_gate.globs import MAX_ALTERNATIVES, compile_glob, named_segments, select  # noqa: E402

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
    return sorted(f.relative_to(ROOT).as_posix() for f in select(FILES, pattern))


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


class Generous(unittest.TestCase):
    """Where ripgrep's reading is uncertain, select more, never less."""

    def test_case_is_ignored(self):
        files = [ROOT / "PATIENTS.CSV", ROOT / "Visits.Csv"]
        self.assertEqual(select(files, "*.csv"), files)

    def test_unicode_normalisation_is_ignored(self):
        decomposed = ROOT / "Jose\u0301.csv"
        self.assertEqual(select([decomposed], "Jos\u00e9.csv"), [decomposed])

    def test_a_directory_glob_selects_what_is_under_it(self):
        self.assertEqual(names("nov"), ["2026/nov/visits.csv", "2026/nov/visits.tsv"])
        self.assertEqual(names("2026/"), ["2026/nov/visits.csv", "2026/nov/visits.tsv"])

    def test_a_glob_relative_to_the_working_directory(self):
        self.assertEqual(names("data/2026/**/*.csv"), ["2026/nov/visits.csv"])

    def test_whitespace_around_globs(self):
        self.assertEqual(names(" *.csv , *.txt "), ["2026/nov/visits.csv", "notes.txt", "patients.csv"])


class Hostile(unittest.TestCase):
    def test_empty_braces_scan_everything(self):
        self.assertIsNone(compile_glob("*.{}"))

    def test_too_many_double_stars_scan_everything(self):
        self.assertIsNone(compile_glob("/".join(["**"] * 12) + "/x.csv"))

    def test_an_overlong_pattern_scans_everything(self):
        self.assertIsNone(compile_glob("a" * 5000))

    def test_wildcard_runs_do_not_backtrack(self):
        import time

        deep = Path("/" + "/".join(["a" * 30] * 40) + "/" + "a" * 200 + ".txt")
        for pattern in ("*" * 200 + "b", "**/" * 8 + "*a*a*a*a*a*a*a*a*b", "*a" * 60 + "b"):
            started = time.monotonic()
            select([deep], pattern)
            self.assertLess(time.monotonic() - started, 1.0, pattern)

    def test_classes_with_brackets_and_carets(self):
        self.assertEqual(names("visits.[^t]sv"), ["2026/nov/visits.csv"])
        self.assertIsNone(compile_glob("visits.[]"))


class NamedSegments(unittest.TestCase):
    def test_literal_directories_a_glob_names(self):
        self.assertEqual(named_segments("build/**/*.{csv,txt}"), {"build"})
        self.assertEqual(named_segments("dist/out/*.csv,node_modules/x.json"),
                         {"dist", "out", "node_modules", "x.json"})
        self.assertEqual(named_segments("*.csv"), set())
        self.assertEqual(named_segments("!build"), set())
        self.assertEqual(named_segments(None), set())


if given is not None:
    _word = st.text(alphabet="abcxyz", min_size=1, max_size=4)

    class Properties(unittest.TestCase):
        @settings(max_examples=300, deadline=None)
        @given(st.text(alphabet="abc*?[]{},!/.\\", max_size=24))
        def test_any_glob_selects_a_subset_or_everything(self, pattern):
            chosen = select(FILES, pattern)
            self.assertTrue(set(chosen) <= set(FILES))
            if compile_glob(pattern) is None:
                self.assertEqual(chosen, FILES)

        @settings(max_examples=200, deadline=None)
        @given(_word, st.lists(_word, min_size=1, max_size=5), _word)
        def test_braces_select_what_their_alternatives_select(self, head, choices, tail):
            files = [ROOT / f"{head}{c}{tail}.csv" for c in choices] + [ROOT / "other.csv"]
            braced = select(files, f"{head}{{{','.join(choices)}}}{tail}.csv")
            spelled = select(files, ",".join(f"{head}{c}{tail}.csv" for c in choices))
            self.assertEqual(braced, spelled)
            self.assertTrue(all(f in braced for f in files[:-1]))


if __name__ == "__main__":
    unittest.main()
