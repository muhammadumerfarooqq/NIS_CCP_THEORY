import contextlib
import csv
import io
import os
import tempfile
import unittest
from unittest import mock

import benchmark
import cipher

# A tiny settings block: very few repeats and tiny sizes, so the test is fast.
TINY_SETTINGS = {
    "name": "tiny",
    "sizes": [50, 100, 200],
    "table_b_n": 100,
    "table_c_n": 100,
    "key_lengths": [10, 20],
    "memory_sizes": [100, 200],
    "budget_s": 0.0,
    "min_repeats": 2,
    "max_repeats": 2,
}


class TestMaths(unittest.TestCase):
    def test_linear_fit_recovers_slope_and_intercept(self):
        xs = [0, 1, 2, 3, 4]
        ys = [2 * x + 1 for x in xs]          # y = 2x + 1
        slope, intercept, r_squared = benchmark.linear_fit(xs, ys)
        self.assertAlmostEqual(slope, 2.0, places=9)
        self.assertAlmostEqual(intercept, 1.0, places=9)
        self.assertAlmostEqual(r_squared, 1.0, places=9)

    def test_loglog_slope_of_straight_proportion_is_one(self):
        xs = [100, 1000, 10000, 100000]
        self.assertAlmostEqual(benchmark.loglog_slope(xs, [3 * x for x in xs]), 1.0, delta=1e-9)

    def test_loglog_slope_of_square_is_two(self):
        xs = [10, 100, 1000]
        self.assertAlmostEqual(benchmark.loglog_slope(xs, [x * x for x in xs]), 2.0, delta=1e-9)

    def test_linear_fit_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            benchmark.linear_fit([1], [1])
        with self.assertRaises(ValueError):
            benchmark.linear_fit([2, 2, 2], [1, 2, 3])


class TestVerdict(unittest.TestCase):
    def test_slope_one_is_linear(self):
        self.assertEqual(benchmark.classify_slope(1.0), "linear")

    def test_slope_two_is_not_linear(self):
        self.assertNotEqual(benchmark.classify_slope(2.0), "linear")
        self.assertEqual(benchmark.classify_slope(2.0), "super-linear")

    def test_slope_below_range_is_sub_linear(self):
        self.assertEqual(benchmark.classify_slope(0.5), "sub-linear")

    def test_description_is_derived_from_the_slope(self):
        self.assertTrue(benchmark.describe_slope(1.0).startswith("linear"))
        self.assertTrue(benchmark.describe_slope(2.0).startswith("super-linear"))

    def test_description_names_the_quantity(self):
        self.assertIn("the time", benchmark.describe_slope(1.0))
        self.assertIn("the memory", benchmark.describe_slope(1.0, "memory"))


class TestTinyBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = benchmark.run_benchmarks(TINY_SETTINGS)

    def test_all_sections_present(self):
        self.assertEqual(
            set(self.results),
            {"table_a", "table_b", "table_c_rails", "table_c_key",
             "fits", "memory", "memory_scaling"})

    def test_table_a_has_expected_keys_and_positive_times(self):
        self.assertEqual([r["n"] for r in self.results["table_a"]], TINY_SETTINGS["sizes"])
        for row in self.results["table_a"]:
            for key in ("shift_enc_ms", "custom_enc_ms", "custom_dec_ms", "ratio", "us_per_char"):
                self.assertGreater(row[key], 0, key)
            self.assertEqual(row["custom_enc_repeats"], 2)

    def test_table_b_and_c_shapes(self):
        self.assertEqual(len(self.results["table_b"]), 4)
        for row in self.results["table_b"]:
            self.assertGreater(row["median_ms"], 0)
        self.assertEqual(len(self.results["table_c_rails"]), 9)            # rails 2..10
        self.assertEqual([r["rails"] for r in self.results["table_c_rails"]], list(range(2, 11)))
        self.assertEqual([r["key_length"] for r in self.results["table_c_key"]],
                         TINY_SETTINGS["key_lengths"])
        for row in self.results["table_c_rails"] + self.results["table_c_key"]:
            self.assertGreater(row["median_ms"], 0)

    def test_fits_and_memory(self):
        self.assertEqual([f["name"] for f in self.results["fits"]],
                         ["Shift enc", "Custom enc", "Custom dec"])
        for fit in self.results["fits"]:
            self.assertIn(fit["verdict"].split(" ")[0], {"linear", "sub-linear", "super-linear"})
        self.assertEqual(len(self.results["memory"]), 4)                  # 2 sizes x 2 functions
        for row in self.results["memory"]:
            self.assertGreater(row["peak_kb"], 0)
        self.assertEqual(len(self.results["memory_scaling"]), 2)

    def test_csv_is_written_to_the_given_path_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "bench.csv")                  # folder is created
            benchmark.write_csv(self.results, path)
            with open(path, newline="") as fh:
                rows = list(csv.DictReader(fh))
        self.assertGreater(len(rows), 20)
        self.assertEqual(list(rows[0]), benchmark.CSV_FIELDS)
        self.assertEqual({r["table"] for r in rows},
                         {"A", "B", "C_rails", "C_key", "fit", "memory", "memory_scaling"})


class TestRoundTripAbort(unittest.TestCase):
    def test_good_functions_pass(self):
        benchmark.verify_round_trip("HELLOWORLD", "ABCDEFGHIJKL", 3)

    def test_broken_custom_decrypt_aborts(self):
        def broken_decrypt(ct, key, rails):
            return ct[::-1]                        # does not undo the encryption
        with self.assertRaises(benchmark.RoundTripError):
            benchmark.verify_round_trip("HELLOWORLD", "ABCDEFGHIJKL", 3,
                                        custom_decrypt=broken_decrypt)

    def test_broken_shift_decrypt_aborts(self):
        with self.assertRaises(benchmark.RoundTripError):
            benchmark.verify_round_trip("HELLOWORLD", "ABCDEFGHIJKL", 3,
                                        shift_decrypt=lambda ct, k: ct)

    def test_whole_benchmark_aborts_if_the_cipher_is_broken(self):
        with mock.patch.object(cipher, "custom_decrypt", lambda ct, key, rails: "WRONG"):
            with self.assertRaises(benchmark.RoundTripError):
                benchmark.run_benchmarks(TINY_SETTINGS)

    def test_main_turns_the_abort_into_a_loud_exit(self):
        with mock.patch.object(cipher, "custom_decrypt", lambda ct, key, rails: "WRONG"):
            with self.assertRaises(SystemExit) as caught, \
                    contextlib.redirect_stdout(io.StringIO()):
                benchmark.main(["--quick"])
        self.assertIn("ABORT", str(caught.exception))


class TestMeasure(unittest.TestCase):
    def test_gc_is_restored_and_summary_is_sane(self):
        import gc
        before = gc.isenabled()
        result = benchmark.measure(lambda: sum(range(100)), TINY_SETTINGS)
        self.assertEqual(gc.isenabled(), before)
        self.assertEqual(result["repeats"], 2)
        self.assertGreaterEqual(result["iqr_ms"], 0)

    def test_summarise_ignores_an_outlier(self):
        median, iqr = benchmark.summarise([1, 2, 3, 4, 100])
        self.assertEqual(median, 3)
        self.assertLess(iqr, 10)


if __name__ == "__main__":
    unittest.main()
