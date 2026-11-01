import contextlib
import inspect
import io
import os
import random
import string
import tempfile
import unittest
from unittest import mock

import attack
import cipher

CORPUS = attack.load_corpus()

# (corpus offset, key, rails) - fixed before any attack was run.
FREQ_CASES = [
    (100, "KXVQMZPLTWNBRHDYAE", 4),     # key length 18
    (6000, "JWBFODCUSRYHNGI", 7),       # key length 15
    (12000, "QPLMZTVXCEKSB", 2),        # key length 13
]
KPA_CASES = [
    (300, "HGTRQWNZLBVCXMDFAPKS", 3),   # key length 20
    (9000, "OUZYEJTIBNRGWM", 9),        # key length 14
    (20000, "SDFKLQWEPOXCV", 6),        # key length 13
]


def make_case(offset, key, rails, n):
    plaintext = CORPUS[offset:offset + n]
    _, ciphertext = cipher.custom_encrypt(plaintext, key, rails)
    return plaintext, ciphertext


class TestFrequencyAttack(unittest.TestCase):
    def test_recovers_exact_plaintext(self):
        for offset, key, rails in FREQ_CASES:
            with self.subTest(key=key, rails=rails):
                plaintext, ciphertext = make_case(offset, key, rails, 2500)
                found = attack.frequency_attack(ciphertext)  # ciphertext only
                self.assertTrue(found["ok"])
                self.assertEqual(found["plaintext"], plaintext)
                self.assertEqual(found["rails"], rails)
                self.assertEqual(found["key"], key)
                self.assertEqual(found["guesses"], 9 * 16)


class TestKnownPlaintextAttack(unittest.TestCase):
    def test_recovers_exact_plaintext(self):
        for offset, key, rails in KPA_CASES:
            with self.subTest(key=key, rails=rails):
                plaintext, ciphertext = make_case(offset, key, rails, 500)
                found = attack.known_plaintext_attack(ciphertext, plaintext[:30])
                self.assertTrue(found["ok"])
                self.assertEqual(found["plaintext"], plaintext)
                self.assertEqual(found["rails"], rails)
                self.assertEqual(found["key"], key)

    def test_short_crib_fails_cleanly(self):
        plaintext, ciphertext = make_case(0, "KXVQMZPLTWNBRHDYAE", 4, 500)
        for size in (0, 1, 9):
            with self.subTest(crib_size=size):
                found = attack.known_plaintext_attack(ciphertext, plaintext[:size])
                self.assertFalse(found["ok"])
                self.assertIn("crib too short", found["error"])
                self.assertIsNone(found["plaintext"])
                self.assertEqual(found["guesses"], 0)


class TestKnownPlaintextNonEnglish(unittest.TestCase):
    """Phase 3: the crib must be used as evidence, not just English scoring."""

    def test_random_letter_plaintext_is_recovered_exactly(self):
        rng = random.Random(486)
        for trial in range(20):
            plaintext = "".join(rng.choices(string.ascii_uppercase, k=500))
            key = "".join(rng.choices(string.ascii_uppercase, k=rng.randint(10, 20)))
            rails = rng.randint(2, 10)
            _, ciphertext = cipher.custom_encrypt(plaintext, key, rails)
            with self.subTest(trial=trial, key_length=len(key), rails=rails):
                found = attack.known_plaintext_attack(ciphertext, plaintext[:30])
                self.assertTrue(found["ok"])
                self.assertEqual(found["plaintext"], plaintext)
                self.assertEqual(found["rails"], rails)

    def test_random_letters_key_12_crib_20_is_recovered_exactly(self):
        # Crib 20 vs key 12 gives 8 periodicity checks (>= MIN_CHECKS).
        rng = random.Random(486)
        for trial in range(20):
            plaintext = "".join(rng.choices(string.ascii_uppercase, k=500))
            key = "".join(rng.choices(string.ascii_uppercase, k=12))
            rails = rng.randint(2, 10)
            _, ciphertext = cipher.custom_encrypt(plaintext, key, rails)
            with self.subTest(trial=trial, rails=rails):
                found = attack.known_plaintext_attack(ciphertext, plaintext[:20])
                self.assertTrue(found["ok"])
                self.assertEqual(found["plaintext"], plaintext)
                self.assertEqual(found["rails"], rails)
                self.assertEqual(found["key"], key)

    def test_failure_result_has_same_shape_as_success(self):
        plaintext, ciphertext = make_case(0, "KXVQMZPLTWNBRHDYAE", 4, 500)
        good = attack.known_plaintext_attack(ciphertext, plaintext[:30])
        bad = attack.known_plaintext_attack(ciphertext, plaintext[:9])
        self.assertEqual(set(bad), set(good))
        self.assertFalse(bad["ok"])


class TestThreatModel(unittest.TestCase):
    def test_attack_signatures_take_no_secrets(self):
        freq = list(inspect.signature(attack.frequency_attack).parameters)
        kpa = list(inspect.signature(attack.known_plaintext_attack).parameters)
        self.assertEqual(freq, ["ciphertext"])
        self.assertEqual(kpa, ["ciphertext", "crib"])
        for name in freq + kpa:
            for secret in ("key", "rail", "length"):
                self.assertNotIn(secret, name.lower())


class TestQuickCsvPath(unittest.TestCase):
    """Phase 4: --quick must write its own file, never the full-run CSV."""

    def test_quick_does_not_overwrite_full_csv(self):
        row = {"text_length": 100, "crib": "", "trials": 1, "exact_pct": 0.0,
               "plaintext_acc_pct": 0.0, "key_acc_pct": 0.0, "rails_pct": 0.0,
               "median_ms": 1.0, "median_guesses": 144}
        fake = {"table1": [row], "table2": [row], "table3": [row]}
        trials_seen = []

        def fake_run_experiments(trials=100, seed=486):
            trials_seen.append(trials)  # remember what main() asked for
            return fake

        real_csv = os.path.join(os.path.dirname(attack.RESULTS_PATH), "attack_results.csv")

        def read_bytes(path):
            # The file's bytes, or None if it does not exist (file always closed).
            if not os.path.exists(path):
                return None
            with open(path, "rb") as fh:
                return fh.read()

        real_before = read_bytes(real_csv)

        with tempfile.TemporaryDirectory() as tmp:
            full = os.path.join(tmp, "attack_results.csv")
            quick = os.path.join(tmp, "attack_results_quick.csv")
            with open(full, "w") as fh:
                fh.write("SENTINEL")
            with mock.patch.object(attack, "RESULTS_PATH", full), \
                    mock.patch.object(attack, "RESULTS_PATH_QUICK", quick), \
                    mock.patch.object(attack, "run_experiments", fake_run_experiments), \
                    contextlib.redirect_stdout(io.StringIO()):
                attack.main(["--quick"])
                # The quick run wrote the quick file and left the full file alone.
                self.assertTrue(os.path.exists(quick))
                with open(full) as fh:
                    self.assertEqual(fh.read(), "SENTINEL")
                # A normal run writes the full file.
                attack.main([])
                with open(full) as fh:
                    self.assertTrue(fh.read().startswith("table,"))
        self.assertEqual(trials_seen, [10, 100])

        # And the real results folder was never touched by this test.
        self.assertEqual(real_before, read_bytes(real_csv))


class TestEnglishFreq(unittest.TestCase):
    def test_sums_to_one(self):
        self.assertAlmostEqual(sum(attack.ENGLISH_FREQ.values()), 1.0, delta=0.001)
        self.assertEqual(len(attack.ENGLISH_FREQ), 26)


if __name__ == "__main__":
    unittest.main()
