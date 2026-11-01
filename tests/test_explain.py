import copy
import random
import string
import unittest

import cipher
import explain

PLAIN = "DEFENDTHEEASTWALLOFTHECASTLE"
KEY = "CRYPTOGRAPHY"
STAGE1 = "FVDTGRZYETHQVNYAECLKHTJYUKJT"


class TestVigenereSteps(unittest.TestCase):
    def test_first_rows_match_the_lecture_example(self):
        working = explain.vigenere_steps(PLAIN, KEY)
        sums = [(r["in_letter"], r["key_letter"], r["out_letter"]) for r in working["rows"][:6]]
        # D+C=F, E+R=V, F+Y=D, E+P=T, N+T=G, D+O=R
        self.assertEqual(sums, [("D", "C", "F"), ("E", "R", "V"), ("F", "Y", "D"),
                                ("E", "P", "T"), ("N", "T", "G"), ("D", "O", "R")])
        self.assertEqual([r["op"] for r in working["rows"]], ["+"] * 15)
        self.assertEqual(len(working["rows"]), 15)                # the default limit
        self.assertTrue(working["matches_cipher"])
        self.assertIn("mod 26", working["formula"])

    def test_numbers_in_a_row(self):
        row = explain.vigenere_steps(PLAIN, KEY)["rows"][0]
        self.assertEqual((row["in_num"], row["key_num"], row["raw"], row["result_num"]), (3, 2, 5, 5))
        self.assertEqual(explain.describe_row(row), "D (3) + C (2) = 5  ->  F")

    def test_wrapping_row_shows_mod(self):
        # "HELLO" with key CAT: L(11) + T(19) = 30, mod 26 = 4 -> E
        row = explain.vigenere_steps("HELLO", "CAT")["rows"][2]
        self.assertEqual(explain.describe_row(row), "L (11) + T (19) = 30, mod 26 = 4  ->  E")
        self.assertEqual("".join(r["out_letter"] for r in explain.vigenere_steps("HELLO", "CAT")["rows"]),
                         "JEENO")

    def test_rows_agree_with_cipher_for_the_whole_message(self):
        working = explain.vigenere_steps(PLAIN, KEY, limit=100)
        self.assertEqual("".join(r["out_letter"] for r in working["rows"]), STAGE1)

    def test_decrypt_working_reverses(self):
        working = explain.vigenere_steps(STAGE1, KEY, decrypt=True)
        self.assertEqual("".join(r["out_letter"] for r in working["rows"]), PLAIN[:15])
        self.assertEqual({r["op"] for r in working["rows"]}, {"-"})
        self.assertIn("-", working["formula"])
        # B - C = -1, mod 26 = 25 -> Z
        row = explain.vigenere_steps("B", "CAT", decrypt=True)["rows"][0]
        self.assertEqual(explain.describe_row(row), "B (1) - C (2) = -1, mod 26 = 25  ->  Z")

    def test_lowercase_key_is_accepted(self):
        self.assertEqual(explain.vigenere_steps("HELLO", "cat")["rows"][0]["key_letter"], "C")

    def test_bad_input_is_rejected(self):
        with self.assertRaises(ValueError):
            explain.vigenere_steps("hello", KEY)
        with self.assertRaises(ValueError):
            explain.vigenere_steps("HELLO", "")
        with self.assertRaises(ValueError):
            explain.vigenere_steps("HELLO", "K3Y")

    def test_empty_text_gives_no_rows(self):
        self.assertEqual(explain.vigenere_steps("", KEY)["rows"], [])

    def test_runtime_check_raises_if_a_row_is_tampered_with(self):
        rows = copy.deepcopy(explain.vigenere_steps(PLAIN, KEY)["rows"])
        explain.check_vigenere_rows(PLAIN, KEY, rows)             # untouched: fine
        for field, wrong in (("out_letter", "Z"), ("raw", 99), ("key_letter", "Q"), ("in_num", 0)):
            tampered = copy.deepcopy(rows)
            tampered[3][field] = wrong
            with self.subTest(field=field):
                with self.assertRaises(explain.ExplainMismatchError):
                    explain.check_vigenere_rows(PLAIN, KEY, tampered)

    def test_check_catches_a_row_that_is_self_consistent_but_not_the_cipher(self):
        # A consistent-looking row for a different key letter still has to fail.
        rows = copy.deepcopy(explain.vigenere_steps(PLAIN, KEY)["rows"])
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_vigenere_rows(PLAIN, "CRYPTOGRAPHZ", rows)   # wrong key given to the check


class TestRailGrid(unittest.TestCase):
    TEXT = "WEAREDISCOVEREDFLEEATONCE"

    def test_lecture_example_three_rails(self):
        working = explain.rail_grid(self.TEXT, 3)
        self.assertEqual(working["rail_strings"], ["WECRLTE", "ERDSOEEFEAOC", "AIVDEN"])
        self.assertEqual(working["joined"], "WECRLTEERDSOEEFEAOCAIVDEN")
        self.assertEqual(working["joined"], cipher.rail_encrypt(self.TEXT, 3))
        self.assertFalse(working["truncated"])
        self.assertTrue(working["matches_cipher"])
        # The grid itself: 3 rows of 25 cells, one letter per column.
        self.assertEqual(len(working["grid"]), 3)
        self.assertEqual({len(row) for row in working["grid"]}, {25})
        self.assertEqual(working["grid"][0][:9], "W...E...C")

    def test_small_example_in_the_comments(self):
        working = explain.rail_grid("ABCDEFGHIJ", 3)
        self.assertEqual(working["grid"], ["A...E...I.", ".B.D.F.H.J", "..C...G..."])
        self.assertEqual(working["rail_strings"], ["AEI", "BDFHJ", "CG"])
        self.assertEqual(working["joined"], "AEIBDFHJCG")

    def test_decrypt_working_reverses(self):
        ciphertext = "WECRLTEERDSOEEFEAOCAIVDEN"
        working = explain.rail_grid(ciphertext, 3, decrypt=True)
        self.assertEqual(working["rail_strings"], ["WECRLTE", "ERDSOEEFEAOC", "AIVDEN"])
        self.assertEqual(working["joined"], self.TEXT)
        self.assertEqual(working["joined"], cipher.rail_decrypt(ciphertext, 3))
        self.assertTrue(working["decrypt"])

    def test_long_text_is_cut_at_the_limit(self):
        text = (string.ascii_uppercase * 4)[:100]
        working = explain.rail_grid(text, 4)
        self.assertEqual(working["shown"], 40)
        self.assertEqual(working["total"], 100)
        self.assertTrue(working["truncated"])
        self.assertEqual(working["joined"], cipher.rail_encrypt(text[:40], 4))

    def test_every_rails_value_and_length_agrees_with_cipher(self):
        rng = random.Random(486)
        for rails in range(2, 11):
            for n in (0, 1, 2, 3, 9, 17, 40):
                text = "".join(rng.choices(string.ascii_uppercase, k=n))
                for decrypt in (False, True):
                    with self.subTest(rails=rails, n=n, decrypt=decrypt):
                        working = explain.rail_grid(text, rails, decrypt=decrypt)
                        expected = (cipher.rail_decrypt if decrypt else cipher.rail_encrypt)(text, rails)
                        self.assertEqual(working["joined"], expected)

    def test_round_trip_through_the_two_workings(self):
        text = "".join(random.Random(7).choices(string.ascii_uppercase, k=40))
        locked = explain.rail_grid(text, 5)["joined"]
        self.assertEqual(explain.rail_grid(locked, 5, decrypt=True)["joined"], text)

    def test_pattern_matches_the_real_rail_order(self):
        # The independent zigzag formula must put every position on the rail
        # that cipher.rail_order uses.
        for rails in range(2, 11):
            n = 57
            order = cipher.rail_order(n, rails)
            pattern = explain.rail_pattern(n, rails)
            by_rail = sorted(range(n), key=lambda i: (pattern[i], i))
            self.assertEqual(by_rail, order, rails)

    def test_bad_input_is_rejected(self):
        with self.assertRaises(ValueError):
            explain.rail_grid("ABC", 1)
        with self.assertRaises(ValueError):
            explain.rail_grid("abc", 3)

    def test_runtime_check_raises_if_the_working_is_tampered_with(self):
        working = explain.rail_grid(self.TEXT, 3)
        explain.check_rail_grid(self.TEXT, working)                # untouched: fine

        wrong_joined = copy.deepcopy(working)
        wrong_joined["joined"] = "X" + working["joined"][1:]
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_rail_grid(self.TEXT, wrong_joined)

        wrong_grid = copy.deepcopy(working)
        wrong_grid["grid"][0] = "Z" + wrong_grid["grid"][0][1:]
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_rail_grid(self.TEXT, wrong_grid)

        wrong_strings = copy.deepcopy(working)
        wrong_strings["rail_strings"][1] = "Q" + wrong_strings["rail_strings"][1][1:]
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_rail_grid(self.TEXT, wrong_strings)

        two_in_a_column = copy.deepcopy(working)
        row = two_in_a_column["grid"][1]
        two_in_a_column["grid"][1] = "Q" + row[1:]                 # column 1 now has two letters
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_rail_grid(self.TEXT, two_in_a_column)

    def test_decrypt_check_also_catches_tampering(self):
        working = explain.rail_grid("WECRLTEERDSOEEFEAOCAIVDEN", 3, decrypt=True)
        bad = copy.deepcopy(working)
        bad["joined"] = bad["joined"][::-1]
        with self.assertRaises(explain.ExplainMismatchError):
            explain.check_rail_grid("WECRLTEERDSOEEFEAOCAIVDEN", bad)


if __name__ == "__main__":
    unittest.main()
