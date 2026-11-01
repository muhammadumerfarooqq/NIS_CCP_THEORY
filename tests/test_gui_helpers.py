"""Tests for the parts of gui.py and help_text.py that need NO window, so they
always run (even on a computer with no display)."""

import csv
import os
import tempfile
import unittest

import attack
import benchmark
import cipher
import gui
import help_text

TINY_SETTINGS = {
    "name": "tiny", "sizes": [50, 100, 200], "table_b_n": 100, "table_c_n": 100,
    "key_lengths": [10, 20], "memory_sizes": [100, 200],
    "budget_s": 0.0, "min_repeats": 2, "max_repeats": 2,
}


class TestSelfTestChecks(unittest.TestCase):
    def test_all_checks_pass_on_the_real_cipher(self):
        checks, ms = gui.run_self_test_checks()
        self.assertTrue(all(passed for _, passed, _ in checks), [c for c in checks if not c[1]])
        self.assertGreater(ms, 0)
        names = " | ".join(name for name, _, _ in checks)
        for needed in ("Shift", "Vigenere", "Rail Fence", "300 random"):
            self.assertIn(needed, names)

    def test_a_broken_cipher_makes_the_self_test_fail(self):
        original = cipher.rail_decrypt
        cipher.rail_decrypt = lambda ct, rails: ct          # deliberately wrong
        try:
            checks, _ = gui.run_self_test_checks()
        finally:
            cipher.rail_decrypt = original
        self.assertTrue(any(not passed for _, passed, _ in checks))
        self.assertTrue(all(passed for _, passed, _ in gui.run_self_test_checks()[0]))   # and it recovers


class TestSmallHelpers(unittest.TestCase):
    def test_letter_accuracy(self):
        self.assertEqual(gui.letter_accuracy("ABCD", "ABXD"), 0.75)
        self.assertEqual(gui.letter_accuracy("ABCD", "ABCD"), 1.0)
        self.assertEqual(gui.letter_accuracy("ABCD", "ABC"), 0.0)
        self.assertEqual(gui.letter_accuracy("ABCD", None), 0.0)

    def test_nice_ceiling(self):
        for value, expected in ((33.6, 50), (0.331, 0.5), (1.0, 1), (120, 200), (7, 10), (0.04, 0.05), (0, 1)):
            self.assertAlmostEqual(gui.nice_ceiling(value), expected, msg=value)

    def test_protected_paths(self):
        self.assertTrue(gui.is_protected(attack.RESULTS_PATH))
        self.assertTrue(gui.is_protected(benchmark.RESULTS_PATH))
        self.assertTrue(gui.is_protected(os.path.join(os.path.dirname(attack.RESULTS_PATH), "..", "results",
                                                      "attack_results.csv")))
        self.assertFalse(gui.is_protected(os.path.join(os.path.dirname(attack.RESULTS_PATH), "attack_results_gui.csv")))

    def test_table_rows_are_formatted_like_the_command_line_programs(self):
        rows = attack.run_experiments(trials=1)
        for name, vary in (("table1", "text_length"), ("table2", "text_length"), ("table3", "crib")):
            printed = attack.format_table("t", rows[name], vary).splitlines()[3:]
            self.assertEqual(len(printed), len(rows[name]))
            for line, row in zip(printed, rows[name]):
                self.assertEqual(line.split(), gui.format_attack_row(row, vary))
        results = benchmark.run_benchmarks(TINY_SETTINGS)
        printed = benchmark.format_rows(
            "t", [("N", "n", "d", 8), ("a", "shift_enc_ms", ".4f", 13), ("b", "custom_enc_ms", ".4f", 14),
                  ("c", "custom_dec_ms", ".4f", 14), ("d", "ratio", ".2f", 10), ("e", "us_per_char", ".4f", 15)],
            results["table_a"]).splitlines()[3:]
        for line, row in zip(printed, results["table_a"]):
            self.assertEqual(line.split(), gui.format_speed_row(row))


class TestCsvReaders(unittest.TestCase):
    def test_read_the_real_attack_csv(self):
        data = gui.read_attack_csv()
        self.assertEqual([len(data[t]) for t in ("table1", "table2", "table3")], [6, 6, 5])
        first = data["table1"][0]
        self.assertEqual(first["text_length"], 100)
        self.assertEqual(first["crib"], "")
        self.assertIsInstance(first["exact_pct"], float)
        self.assertEqual(data["table3"][0]["crib"], 10)

    def test_attack_csv_round_trips_through_write_csv(self):
        rows = attack.run_experiments(trials=1)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "x_gui.csv")
            attack.write_csv(rows, path)
            back = gui.read_attack_csv(path)
        self.assertEqual([r["text_length"] for r in back["table1"]], attack.TEXT_LENGTHS)
        for name in rows:
            for a, b in zip(rows[name], back[name]):
                self.assertAlmostEqual(a["exact_pct"], b["exact_pct"])
                self.assertAlmostEqual(a["median_ms"], b["median_ms"])

    def test_read_the_real_benchmark_csv(self):
        data = gui.read_benchmark_csv()
        self.assertEqual([r["n"] for r in data["table_a"]], benchmark.FULL_SETTINGS["sizes"])
        self.assertEqual([f["name"] for f in data["fits"]], ["Shift enc", "Custom enc", "Custom dec"])
        for row in data["table_a"]:
            self.assertGreater(row["custom_enc_ms"], 0)
        self.assertTrue(data["memory"])

    def test_benchmark_csv_round_trips_through_write_csv(self):
        results = benchmark.run_benchmarks(TINY_SETTINGS)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "b.csv")
            benchmark.write_csv(results, path)
            back = gui.read_benchmark_csv(path)
        self.assertEqual([r["n"] for r in back["table_a"]], TINY_SETTINGS["sizes"])
        for a, b in zip(results["table_a"], back["table_a"]):
            self.assertAlmostEqual(a["custom_enc_ms"], b["custom_enc_ms"])
            self.assertAlmostEqual(a["ratio"], b["ratio"])
        self.assertEqual(len(back["memory"]), 4)

    def test_missing_and_malformed_files(self):
        missing = os.path.join(tempfile.gettempdir(), "definitely_not_here_123.csv")
        with self.assertRaises(FileNotFoundError):
            gui.read_attack_csv(missing)
        with self.assertRaises(FileNotFoundError):
            gui.read_benchmark_csv(missing)
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.csv")
            with open(bad, "w", newline="") as fh:
                csv.writer(fh).writerows([["table", "x"], ["table1", "1"]])
            with self.assertRaises(ValueError):
                gui.read_attack_csv(bad)
            with self.assertRaises(ValueError):
                gui.read_benchmark_csv(bad)


class TestHelpText(unittest.TestCase):
    def test_static_text_contains_no_measured_results(self):
        for block in help_text.STATIC_TEXT_BLOCKS:
            self.assertNotIn("%", block)
            self.assertNotIn(" ms", block)
            self.assertNotIn("slope", block)
        # The worked examples are there.
        self.assertIn("D (3) + C (2) = 5  ->  F", help_text.STAGE1_TEXT)
        self.assertIn("JEENO", help_text.STAGE1_TEXT)
        self.assertIn("AEIBDFHJCG", help_text.STAGE2_TEXT)

    def test_missing_csv_is_stated_not_invented(self):
        attack_text = help_text.attack_results_lines(None)
        speed_text = help_text.speed_results_lines(None)
        self.assertIn("was not found", attack_text)
        self.assertIn("was not found", speed_text)
        self.assertFalse(any(ch.isdigit() for ch in attack_text.replace("attack.py", "")))
        self.assertFalse(any(ch.isdigit() for ch in speed_text.replace("benchmark.py", "")))
        document = help_text.build_help_document(None, None)
        full = "\n".join(text for _, text in document)
        self.assertIn("python attack.py", full)
        self.assertIn("python benchmark.py", full)

    def test_numbers_come_from_the_data_that_is_passed_in(self):
        attack_data = {
            "table1": [{"text_length": 777, "crib": "", "trials": 4242, "exact_pct": 61.3, "key_acc_pct": 62.7,
                        "rails_pct": 63.9}],
            "table2": [{"text_length": 778, "crib": 31, "trials": 4242, "exact_pct": 71.1, "key_acc_pct": 72.2,
                        "rails_pct": 73.3}],
            "table3": [{"text_length": 779, "crib": 12, "trials": 4242, "exact_pct": 81.4, "key_acc_pct": 82.5,
                        "rails_pct": 83.6}],
        }
        speed_data = {
            "table_a": [{"n": 11, "us_per_char": 0.123}, {"n": 99999, "us_per_char": 0.456}],
            "fits": [{"name": "Custom enc", "loglog_slope": 1.234, "r_squared": 0.98765, "verdict": "VERDICT TEXT"}],
            "memory": [{"name": "Custom enc", "n": 5555, "peak_kb": 321.0, "bytes_per_char": 59.1}],
        }
        text = help_text.attack_results_lines(attack_data) + help_text.speed_results_lines(speed_data)
        for expected in ("4242 trials per row", "61.3", "73.3", "crib of 31", "779 letters", "83.6",
                         "0.123", "0.456", "1.234", "0.98765", "VERDICT TEXT", "5555", "321.0"):
            self.assertIn(expected, text)

    def test_code_constants_in_the_explanations_are_not_hard_coded(self):
        text = help_text.attacks_text()
        self.assertIn(f"at least {attack.MIN_CHECKS} comparisons", text)
        self.assertIn(f"{cipher.MIN_RAILS} to {cipher.MAX_RAILS}", text)
        self.assertIn(f"only {cipher.MAX_RAILS - cipher.MIN_RAILS + 1} possible keys", help_text.limitations_text())

    def test_document_structure(self):
        document = help_text.build_help_document(gui.read_attack_csv(), gui.read_benchmark_csv())
        styles = {style for style, _ in document}
        self.assertTrue({"title", "heading", "stage1", "stage2", "body", "mono", "note"} <= styles)
        full = "\n".join(text for _, text in document)
        for needed in ("Shift cipher", "O(N + k)", "Index of Coincidence", "Chi-squared", "crib",
                       "periodicity", "undoes Stage 2 first", "Classical ciphers are not secure"):
            self.assertIn(needed, full)


if __name__ == "__main__":
    unittest.main()
