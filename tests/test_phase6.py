"""Phase 6 tests that need NO window and NO tkinter, so they always run.

* N = 50 was added to the attack experiments.
* The weak-key warning text, and the tour banner texts, are built from plain functions.
* The new "notes" section of the Design page exists and holds no measured results.
* If tkinter is missing, `python gui.py` prints one friendly line (no traceback) and
  the two GUI test files are SKIPPED, not errored. That is tested by starting a
  fresh Python in which importing tkinter is made to fail.
"""

import os
import subprocess
import sys
import unittest

import attack
import cipher
import gui
import help_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_python_without_tkinter(code):
    """Run `code` in a new Python where `import tkinter` raises ImportError."""
    prelude = "import sys; sys.modules['tkinter'] = None\n"      # None in sys.modules = 'import fails'
    return subprocess.run([sys.executable, "-c", prelude + code], cwd=ROOT, capture_output=True, text=True,
                          timeout=120)


class TestFiftyLetterMessages(unittest.TestCase):
    def test_text_lengths_now_start_with_50(self):
        self.assertEqual(attack.TEXT_LENGTHS, [50, 100, 250, 500, 1000, 2500, 5000])
        self.assertEqual(attack.CRIB_SIZES, [10, 15, 20, 30, 40])        # the crib sizes did not change
        self.assertEqual(attack.TABLE3_LENGTH, 500)

    def test_the_saved_results_file_has_the_50_rows(self):
        data = gui.read_attack_csv()
        self.assertEqual([r["text_length"] for r in data["table1"]], attack.TEXT_LENGTHS)
        self.assertEqual([r["text_length"] for r in data["table2"]], attack.TEXT_LENGTHS)
        self.assertEqual([r["crib"] for r in data["table3"]], attack.CRIB_SIZES)
        self.assertEqual({r["trials"] for t in data.values() for r in t}, {100})

    def test_both_attacks_run_on_50_letters_without_crashing(self):
        corpus = attack.load_corpus()
        import random
        rng = random.Random(5)
        for _ in range(10):
            plaintext, _key, _rails, ciphertext = attack._make_trial(rng, corpus, 50)
            for found in (attack.frequency_attack(ciphertext),
                          attack.known_plaintext_attack(ciphertext, plaintext[:attack.DEFAULT_CRIB])):
                self.assertIn("ok", found)                    # a normal result or a clean failure, never an exception
                if found["ok"]:
                    self.assertEqual(len(found["plaintext"]), 50)

    def test_experiment_cell_count_and_row_counts(self):
        results = attack.run_experiments(trials=1)
        self.assertEqual([len(results[t]) for t in ("table1", "table2", "table3")], [7, 7, 5])
        self.assertEqual(results["table1"][0]["text_length"], 50)


class TestWeakKeyNoteText(unittest.TestCase):
    def test_few_different_letters_are_flagged(self):
        for key in ("AAAAAAAAAA", "aaaaaaaaaa", "ABABABABAB", "ABCABCABCABC", "aAaAaAaAaA"):
            self.assertEqual(gui.weak_key_note(key), gui.WEAK_KEY_NOTE, key)

    def test_four_or_more_different_letters_are_fine(self):
        for key in ("ABCDABCDABCD", "CRYPTOGRAPHY", "LEMONSQUEEZE", "abcdefghij"):
            self.assertEqual(gui.weak_key_note(key), "", key)

    def test_nothing_typed_is_not_a_warning(self):
        self.assertEqual(gui.weak_key_note(""), "")

    def test_the_exact_wording(self):
        self.assertEqual(gui.WEAK_KEY_NOTE, "Weak key: very few different letters. Allowed, but easy to break.")
        self.assertEqual(gui.WEAK_KEY_MIN_DISTINCT, 4)

    def test_a_weak_key_is_still_accepted_by_the_cipher(self):
        cipher.validate_key("AAAAAAAAAA", 4)                    # does not raise: only a warning, never a block
        stage1, final = cipher.custom_encrypt("DEFENDTHEEASTWALL", "AAAAAAAAAA", 4)
        self.assertEqual(stage1, "DEFENDTHEEASTWALL")           # the key A shifts by 0: Stage 1 changes nothing
        self.assertEqual(cipher.custom_decrypt(final, "AAAAAAAAAA", 4), "DEFENDTHEEASTWALL")


class TestBannerTexts(unittest.TestCase):
    def test_experiments_banner_reads_trials_from_the_data(self):
        data = gui.read_attack_csv()
        for t in data.values():
            for row in t:
                row["trials"] = 42
        self.assertIn("42 random trials", gui.experiments_banner(data))
        self.assertIsNone(gui.experiments_banner(None))

    def test_efficiency_banner_reads_slope_and_ratio_from_the_data(self):
        data = gui.read_benchmark_csv()
        for row in data["table_a"]:
            row["ratio"] = 2.0
        for fit in data["fits"]:
            fit["loglog_slope"] = 0.987
            fit["verdict"] = "linear (slope 0.987): doubling N roughly doubles the time, which is O(N)"
        text = gui.efficiency_banner(data)
        self.assertIn("0.99", text)
        self.assertIn("2.0 times the Shift cipher", text)
        self.assertIn("straight line", text)
        self.assertIsNone(gui.efficiency_banner(None))


class TestDesignPageNotes(unittest.TestCase):
    def test_the_long_explanations_are_on_the_design_page(self):
        document = help_text.build_help_document(gui.read_attack_csv(), gui.read_benchmark_csv())
        full = "\n".join(text for _, text in document)
        self.assertIn(help_text.SCREEN_NOTES_TITLE, full)
        for needed in ("START HERE", "Reveal truth", "fewer than four different letters", "custom us/char",
                       "removed when you lock", "python benchmark.py"):
            self.assertIn(needed, full)
        self.assertIn(help_text.SCREEN_NOTES_TEXT, help_text.STATIC_TEXT_BLOCKS)

    def test_the_notes_contain_no_measured_numbers(self):
        text = help_text.SCREEN_NOTES_TEXT
        for forbidden in ("%", " ms", "slope", "trials per row"):
            self.assertNotIn(forbidden, text)


class TestWithoutTkinter(unittest.TestCase):
    def test_gui_py_prints_one_friendly_line_and_no_traceback(self):
        done = run_python_without_tkinter("import runpy; runpy.run_path('gui.py', run_name='__main__')")
        self.assertEqual(done.returncode, 1)
        lines = [line for line in done.stderr.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, done.stderr)
        self.assertIn("This program needs tkinter", lines[0])
        self.assertNotIn("Traceback", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_gui_can_still_be_imported_without_tkinter(self):
        done = run_python_without_tkinter(
            "import gui; print(gui.tk is None, gui.weak_key_note('AAAAAAAAAA') != '')")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "True True")

    def test_the_gui_test_files_are_skipped_not_errored(self):
        # Test discovery is what `python -m unittest` uses; it turns a module-level SkipTest into a skip.
        code = ("import unittest\n"
                "suite = unittest.defaultTestLoader.discover('tests', pattern='test_gui_*.py', top_level_dir='.')\n"
                "result = unittest.TextTestRunner(verbosity=2).run(suite)\n"
                "print('SKIPPED', len(result.skipped), 'ERRORS', len(result.errors), 'FAILURES', len(result.failures),"
                " 'RUN', result.testsRun)\n")
        done = run_python_without_tkinter(code)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("SKIPPED 3 ERRORS 0 FAILURES 0 RUN 3", done.stdout + done.stderr)
        self.assertIn("tkinter is not installed", done.stderr)          # the reason is stated clearly


if __name__ == "__main__":
    unittest.main()
