import random
import string
import unittest

from cipher import (
    custom_decrypt,
    custom_encrypt,
    rail_decrypt,
    rail_encrypt,
    rail_order,
    sanitize,
    shift_decrypt,
    shift_encrypt,
    validate_key,
    vigenere_decrypt,
    vigenere_encrypt,
)


class TestKnownVectors(unittest.TestCase):
    def test_shift_encrypt(self):
        self.assertEqual(shift_encrypt("WEWILLMEETATMIDNIGHT", 11), "HPHTWWXPPELEXTOYTRSE")

    def test_shift_decrypt(self):
        self.assertEqual(shift_decrypt("COTEWXQIVBUQI", 16), "MYDOGHASFLEAS")

    def test_vigenere_encrypt(self):
        self.assertEqual(
            vigenere_encrypt("THISCRYPTOSYSTEMISNOTSECURE", "CIPHER"),
            "VPXZGIAXIVWPUBTTMJPWIZITWZT",
        )

    def test_vigenere_decrypt_trickem(self):
        self.assertEqual(vigenere_decrypt("FPLQQLMLWTGKW", "TRICKEM"), "MYDOGHASFLEAS")

    def test_vigenere_decrypt_wonderland(self):
        self.assertEqual(
            vigenere_decrypt("WZVFINLSOHCWAQMERTBJAHIHVPEIEHZCS", "WONDERLAND"),
            "ALICEWASBEGINNINGTOGETVERYTIREDOF",
        )

    def test_rail_fence(self):
        ct = rail_encrypt("WEAREDISCOVEREDFLEEATONCE", 3)
        self.assertEqual(ct, "WECRLTEERDSOEEFEAOCAIVDEN")
        self.assertEqual(rail_decrypt(ct, 3), "WEAREDISCOVEREDFLEEATONCE")

    def test_custom_cipher(self):
        stage1, final = custom_encrypt("DEFENDTHEEASTWALLOFTHECASTLE", "CRYPTOGRAPHY", 5)
        self.assertEqual(stage1, "FVDTGRZYETHQVNYAECLKHTJYUKJT")
        self.assertEqual(final, "FEEUVYTACYKDZHYLJJTRQNKTTGVH")
        self.assertEqual(
            custom_decrypt(final, "CRYPTOGRAPHY", 5), "DEFENDTHEEASTWALLOFTHECASTLE"
        )


class TestRoundTrip(unittest.TestCase):
    def test_random_round_trips(self):
        random.seed(486)
        for _ in range(5000):
            text = "".join(random.choices(string.ascii_uppercase, k=random.randint(0, 400)))
            key = "".join(random.choices(string.ascii_uppercase, k=random.randint(10, 25)))
            rails = random.randint(2, 10)

            order = rail_order(len(text), rails)
            self.assertEqual(sorted(order), list(range(len(text))))

            stage1, final = custom_encrypt(text, key, rails)
            self.assertEqual(len(stage1), len(text))
            self.assertEqual(len(final), len(text))
            self.assertEqual(custom_decrypt(final, key, rails), text)


class TestEdgeCases(unittest.TestCase):
    def test_short_texts(self):
        key = "ABCDEFGHIJ"
        for text in ("", "A", "AB", "ABC"):
            for rails in (2, 3, 10):
                with self.subTest(text=text, rails=rails):
                    self.assertEqual(
                        sorted(rail_order(len(text), rails)), list(range(len(text)))
                    )
                    self.assertEqual(rail_decrypt(rail_encrypt(text, rails), rails), text)
                    _, final = custom_encrypt(text, key, rails)
                    self.assertEqual(custom_decrypt(final, key, rails), text)


class TestSanitize(unittest.TestCase):
    def test_sanitize(self):
        self.assertEqual(sanitize("Hello, World 123"), ("HELLOWORLD", 6))


class TestValidateKey(unittest.TestCase):
    def test_rejects_short_key(self):
        with self.assertRaises(ValueError):
            validate_key("ABCDEFGHI", 3)  # 9 letters

    def test_rejects_digits_in_key(self):
        with self.assertRaises(ValueError):
            validate_key("ABCDEFGHI1", 3)

    def test_rejects_rails_too_low(self):
        with self.assertRaises(ValueError):
            validate_key("ABCDEFGHIJ", 1)

    def test_rejects_rails_too_high(self):
        with self.assertRaises(ValueError):
            validate_key("ABCDEFGHIJ", 11)

    def test_accepts_valid_input(self):
        validate_key("ABCDEFGHIJ", 2)
        validate_key("abcdefghij", 10)


if __name__ == "__main__":
    unittest.main()
