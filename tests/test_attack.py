import inspect
import unittest

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


class TestThreatModel(unittest.TestCase):
    def test_attack_signatures_take_no_secrets(self):
        freq = list(inspect.signature(attack.frequency_attack).parameters)
        kpa = list(inspect.signature(attack.known_plaintext_attack).parameters)
        self.assertEqual(freq, ["ciphertext"])
        self.assertEqual(kpa, ["ciphertext", "crib"])
        for name in freq + kpa:
            for secret in ("key", "rail", "length"):
                self.assertNotIn(secret, name.lower())


class TestEnglishFreq(unittest.TestCase):
    def test_sums_to_one(self):
        self.assertAlmostEqual(sum(attack.ENGLISH_FREQ.values()), 1.0, delta=0.001)
        self.assertEqual(len(attack.ENGLISH_FREQ), 26)


if __name__ == "__main__":
    unittest.main()
