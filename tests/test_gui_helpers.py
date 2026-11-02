"""Tests for the parts of gui.py and help_text.py that need NO window, so they
always run (even on a computer with no display)."""

import csv
import os
import tempfile
import unittest

try:
    import tkinter       # this file tests gui.py, which is only useful with tkinter
except ImportError as error:
    raise unittest.SkipTest(f"tkinter is not installed: {error}")

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


class TestSmallHelpers(unittest.TestCase):
    def test_letter_accuracy(self):
        self.assertEqual(gui.letter_accuracy("ABCD", "ABXD"), 0.75)
        self.assertEqual(gui.letter_accuracy("ABCD", "ABCD"), 1.0)
        self.assertEqual(gui.letter_accuracy("ABCD", "ABC"), 0.0)
        self.assertEqual(gui.letter_accuracy("ABCD", None), 0.0)

    def test_nice_ceiling(self):
        for value, expected in ((33.6, 50), (0.331, 0.5), (1.0, 1), (120, 200), (7, 10), (0.04, 0.05), (0, 1)):
            self.assertAlmostEqual(gui.nice_ceiling(value), expected, msg=value)

    def test_speed_rows_are_formatted_like_the_benchmark_program_prints_them(self):
        results = benchmark.run_benchmarks(TINY_SETTINGS)
        printed = benchmark.format_rows(
            "t", [("N", "n", "d", 8), ("a", "shift_enc_ms", ".4f", 13), ("b", "custom_enc_ms", ".4f", 14),
                  ("c", "custom_dec_ms", ".4f", 14), ("d", "ratio", ".2f", 10), ("e", "us_per_char", ".4f", 15)],
            results["table_a"]).splitlines()[3:]
        for line, row in zip(printed, results["table_a"]):
            self.assertEqual(line.split(), gui.format_speed_row(row))


class TestAttackSummary(unittest.TestCase):
    """The ONE table on the Attack tab is Table 1 and Table 2 of attack_results.csv side by side."""

    def test_columns_come_from_the_real_csv_columns(self):
        data = gui.read_attack_csv()
        summary = gui.attack_summary(data)
        self.assertEqual(summary["trials"], data["table1"][0]["trials"])
        self.assertEqual(summary["crib"], data["table2"][0]["crib"])
        self.assertEqual(len(summary["rows"]), len(data["table1"]))
        for row, freq, kpa in zip(summary["rows"], data["table1"], data["table2"]):
            self.assertEqual(row, [str(freq["text_length"]), f"{freq['exact_pct']:.1f}", f"{freq['median_ms']:.2f}",
                                   f"{kpa['exact_pct']:.1f}", f"{kpa['median_ms']:.2f}"])
            self.assertEqual(freq["text_length"], kpa["text_length"])

    def test_the_numbers_match_what_attack_py_prints(self):
        results = attack.run_experiments(trials=1)
        summary = gui.attack_summary(results)
        printed = {name: attack.format_table("t", results[name], "text_length").splitlines()[3:]
                   for name in ("table1", "table2")}
        for row, line1, line2 in zip(summary["rows"], printed["table1"], printed["table2"]):
            n, exact1, _text, _key, _rails, ms1, _guesses = line1.split()
            _n, exact2, _text, _key, _rails, ms2, _guesses = line2.split()
            self.assertEqual(row, [n, exact1, ms1, exact2, ms2])

    def test_a_length_missing_from_table_2_shows_a_dash(self):
        data = gui.read_attack_csv()
        data["table2"] = [r for r in data["table2"] if r["text_length"] != 50]
        self.assertEqual(gui.attack_summary(data)["rows"][0][3:], ["-", "-"])


class TestCsvReaders(unittest.TestCase):
    def test_read_the_real_attack_csv(self):
        data = gui.read_attack_csv()
        self.assertEqual([len(data[t]) for t in ("table1", "table2", "table3")], [7, 7, 5])
        first = data["table1"][0]
        self.assertEqual(first["text_length"], 50)
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


class TestDesignLines(unittest.TestCase):
    def lines(self, attack_data="real", speed_data="real"):
        attack_data = gui.read_attack_csv() if attack_data == "real" else attack_data
        speed_data = gui.read_benchmark_csv() if speed_data == "real" else speed_data
        return help_text.design_lines(attack_data, speed_data)

    def test_the_page_is_short_and_has_the_wanted_content(self):
        lines = self.lines()
        self.assertLessEqual(len(lines), 14)                        # one screen, no scrolling
        text = "\n".join(t for _, t in lines)
        for needed in ("Two stages, applied in order.", "Stage 1 - Vigenere (substitution)",
                       "Stage 2 - Rail Fence (transposition)", "Unlock = undo Stage 2 first, then Stage 1.",
                       "Why combine:", "Key: at least 10 letters for Stage 1, plus rails 2 to 10 for Stage 2.",
                       "Speed: both stages are O(N).", "Attack: frequency attack works from about"):
            self.assertIn(needed, text)
        self.assertEqual({style for style, _ in lines}, {"title", "stage1", "stage2", "example", "body"})

    def test_the_examples_are_the_lecture_answers_and_come_from_cipher_py(self):
        self.assertEqual(help_text.stage1_example(), ("HELLO + key CAT = JEENO", True))
        self.assertEqual(help_text.stage2_example(), ("ABCDEFGHIJ on 3 rails = AEIBDFHJCG", True))
        self.assertEqual(cipher.vigenere_encrypt("HELLO", "CAT"), "JEENO")
        self.assertEqual(cipher.rail_encrypt("ABCDEFGHIJ", 3), "AEIBDFHJCG")
        shown = [text for style, text in self.lines() if style == "example"]
        self.assertEqual(shown, ["HELLO + key CAT = JEENO", "ABCDEFGHIJ on 3 rails = AEIBDFHJCG"])

    def test_a_cipher_that_disagrees_gives_a_red_warning_instead_of_the_example(self):
        real_vigenere, real_rail = cipher.vigenere_encrypt, cipher.rail_encrypt
        try:
            cipher.vigenere_encrypt = lambda text, key: "WRONG"
            styles = [style for style, _ in self.lines()]
            self.assertEqual(styles.count("warning"), 1)
            warning = [t for style, t in self.lines() if style == "warning"][0]
            self.assertIn("Stage 1 example does not match cipher.py", warning)
            cipher.vigenere_encrypt = real_vigenere
            cipher.rail_encrypt = lambda text, rails: text[::-1]
            warning = [t for style, t in self.lines() if style == "warning"][0]
            self.assertIn("Stage 2 example does not match cipher.py", warning)
        finally:
            cipher.vigenere_encrypt, cipher.rail_encrypt = real_vigenere, real_rail
        self.assertNotIn("warning", [style for style, _ in self.lines()])        # and it recovers

    def test_numbers_come_from_the_data_that_is_passed_in(self):
        attack_data = {"table1": [{"text_length": 70, "exact_pct": 79.9}, {"text_length": 90, "exact_pct": 80.0},
                                  {"text_length": 110, "exact_pct": 100.0}],
                       "table2": [], "table3": []}
        speed_data = {"table_a": [{"ratio": 3.0}, {"ratio": 5.0}, {"ratio": 4.0}]}
        text = "\n".join(t for _, t in self.lines(attack_data, speed_data))
        self.assertIn("Custom is about 4.0 times slower than Shift.", text)          # median of 3, 5, 4
        self.assertIn("frequency attack works from about 90 letters", text)         # 80 percent counts, 79.9 does not
        self.assertIn(f"key length + {attack.MIN_CHECKS} letters", text)           # from the code's own constant

    def test_the_real_files_give_the_real_numbers(self):
        attack_data, speed_data = gui.read_attack_csv(), gui.read_benchmark_csv()
        text = "\n".join(t for _, t in help_text.design_lines(attack_data, speed_data))
        good = [r["text_length"] for r in attack_data["table1"] if r["exact_pct"] >= 80]
        self.assertIn(f"works from about {min(good)} letters", text)
        ratios = sorted(r["ratio"] for r in speed_data["table_a"])
        middle = (ratios[len(ratios) // 2 - 1] + ratios[len(ratios) // 2]) / 2
        self.assertIn(f"about {middle:.1f} times slower", text)

    def test_no_frequency_success_reaches_the_target(self):
        data = {"table1": [{"text_length": 100, "exact_pct": 10.0}], "table2": [], "table3": []}
        self.assertIn("did not reach 80 percent", help_text.attack_line(data))

    def test_missing_csv_is_stated_not_invented(self):
        text = "\n".join(t for _, t in help_text.design_lines(None, None))
        self.assertIn("results/benchmark_results.csv was not found", text)
        self.assertIn("results/attack_results.csv was not found", text)
        self.assertNotIn("times slower", text)
        self.assertNotIn("works from about", text)
        self.assertIn("Stage 1 - Vigenere", text)                                    # the fixed words are still there


if __name__ == "__main__":
    unittest.main()
