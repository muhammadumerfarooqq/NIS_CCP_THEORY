"""Phase 5: the optional progress / cancel callbacks added to attack.py and
benchmark.py. The old ways of calling the functions must keep working and give
exactly the same results."""

import inspect
import unittest

import attack
import benchmark

# Same tiny settings idea as tests/test_benchmark.py: fast to run.
TINY_SETTINGS = {
    "name": "tiny",
    "sizes": [50, 100],
    "table_b_n": 100,
    "table_c_n": 100,
    "key_lengths": [10, 20],
    "memory_sizes": [100, 200],
    "budget_s": 0.0,
    "min_repeats": 2,
    "max_repeats": 2,
}


def without_timing(results):
    """Drop the machine-dependent timing column so two runs can be compared."""
    return {table: [{k: v for k, v in row.items() if k != "median_ms"} for row in rows]
            for table, rows in results.items()}


class TestAttackProgress(unittest.TestCase):
    def test_defaults_are_unchanged(self):
        params = inspect.signature(attack.run_experiments).parameters
        self.assertEqual(list(params), ["trials", "seed", "progress"])
        self.assertEqual(params["trials"].default, 100)
        self.assertEqual(params["seed"].default, 486)
        self.assertIsNone(params["progress"].default)

    def test_old_call_styles_still_work_and_progress_changes_nothing(self):
        plain = attack.run_experiments(trials=1)                 # old keyword call
        positional = attack.run_experiments(1, 486)               # old positional call
        calls = []
        with_progress = attack.run_experiments(
            trials=1, seed=486, progress=lambda done, total: calls.append((done, total)))
        self.assertEqual(without_timing(plain), without_timing(positional))
        self.assertEqual(without_timing(plain), without_timing(with_progress))
        self.assertEqual(list(plain), ["table1", "table2", "table3"])
        self.assertEqual([len(plain[t]) for t in plain], [7, 7, 5])

    def test_progress_reports_every_cell(self):
        calls = []
        attack.run_experiments(trials=1, progress=lambda d, t: calls.append((d, t)))
        self.assertEqual(calls, [(i, 19) for i in range(1, 20)])

    def test_callback_can_cancel(self):
        calls = []

        def stop_after_two(done, total):
            calls.append(done)
            if done == 2:
                raise attack.CancelledError()

        with self.assertRaises(attack.CancelledError):
            attack.run_experiments(trials=1, progress=stop_after_two)
        self.assertEqual(calls, [1, 2])                           # it really stopped

    def test_cancelled_error_is_its_own_exception(self):
        self.assertTrue(issubclass(attack.CancelledError, Exception))
        self.assertFalse(issubclass(attack.CancelledError, SystemExit))


class TestBenchmarkProgress(unittest.TestCase):
    def test_defaults_are_unchanged(self):
        params = inspect.signature(benchmark.run_benchmarks).parameters
        self.assertEqual(list(params), ["settings", "progress"])
        self.assertIsNone(params["progress"].default)

    def test_old_call_still_works(self):
        results = benchmark.run_benchmarks(TINY_SETTINGS)         # the old one-argument call
        self.assertEqual(len(results["table_a"]), 2)

    def test_count_cells_matches_what_really_runs(self):
        calls = []
        benchmark.run_benchmarks(TINY_SETTINGS, progress=lambda d, t: calls.append((d, t)))
        total = benchmark.count_cells(TINY_SETTINGS)
        self.assertEqual(len(calls), total)
        self.assertEqual(calls[-1], (total, total))
        self.assertEqual([d for d, _ in calls], list(range(1, total + 1)))
        self.assertEqual({t for _, t in calls}, {total})

    def test_count_cells_for_the_full_settings(self):
        # 3*6 (Table A) + 4 (B) + 9 + 4 (C) + 2*2 (memory) = 39
        self.assertEqual(benchmark.count_cells(benchmark.FULL_SETTINGS), 39)

    def test_callback_can_cancel_and_gc_is_left_enabled(self):
        import gc
        was_enabled = gc.isenabled()

        def stop_after_three(done, total):
            if done == 3:
                raise benchmark.CancelledError()

        with self.assertRaises(benchmark.CancelledError):
            benchmark.run_benchmarks(TINY_SETTINGS, progress=stop_after_three)
        self.assertEqual(gc.isenabled(), was_enabled)             # timing never left GC off


if __name__ == "__main__":
    unittest.main()
