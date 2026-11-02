"""Phase 6 tests that need NO window and NO tkinter, so they always run.

* N = 50 was added to the attack experiments.
* Weak keys are still accepted by the cipher (the GUI warning from Phase 6 was removed in Phase 7).
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


class TestWeakKeysAreStillAccepted(unittest.TestCase):
    """The GUI no longer WARNS about weak keys (Phase 7), but the cipher must keep accepting them (L6)."""

    def test_a_weak_key_is_still_accepted_by_the_cipher(self):
        cipher.validate_key("AAAAAAAAAA", 4)                    # does not raise
        stage1, final = cipher.custom_encrypt("DEFENDTHEEASTWALL", "AAAAAAAAAA", 4)
        self.assertEqual(stage1, "DEFENDTHEEASTWALL")           # the key A shifts by 0: Stage 1 changes nothing
        self.assertEqual(cipher.custom_decrypt(final, "AAAAAAAAAA", 4), "DEFENDTHEEASTWALL")


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
            "import gui; print(gui.tk is None, gui.letter_accuracy('ABCD', 'ABXD'))")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), "True 0.75")

    def test_the_gui_test_files_are_skipped_not_errored(self):
        # Test discovery is what `python -m unittest` uses; it turns a module-level SkipTest into a skip.
        code = ("import unittest\n"
                "suite = unittest.defaultTestLoader.discover('tests', pattern='test_gui_*.py', top_level_dir='.')\n"
                "result = unittest.TextTestRunner(verbosity=2).run(suite)\n"
                "print('SKIPPED', len(result.skipped), 'ERRORS', len(result.errors), 'FAILURES', len(result.failures),"
                " 'RUN', result.testsRun)\n")
        done = run_python_without_tkinter(code)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("SKIPPED 2 ERRORS 0 FAILURES 0 RUN 2", done.stdout + done.stderr)
        self.assertIn("tkinter is not installed", done.stderr)          # the reason is stated clearly


if __name__ == "__main__":
    unittest.main()
