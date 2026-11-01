"""Two-stage classical cipher: Stage 1 Vigenere, Stage 2 Rail Fence.

Only the 26 letters A-Z are supported. Use sanitize() first to strip other
characters. The key and the number of rails are two separate inputs.

Standard library only. N below always means the length of the input text and
k the length of the key; every function is O(N) (O(N + k) where the key is
processed too, which is still linear in the input size).
"""

import string

ALPHABET = string.ascii_uppercase
MIN_KEY_LENGTH = 10
MIN_RAILS = 2
MAX_RAILS = 10


# --------------------------------------------------------------------------
# Input handling
# --------------------------------------------------------------------------

def sanitize(text):
    """Keep only A-Z, uppercased. Return (clean_text, removed_count).

    Time complexity: O(N) - one pass over the text.
    """
    # Filter on the original characters (ASCII letters only) before uppercasing:
    # some Unicode letters expand when uppercased ("ß" -> "SS").
    clean = "".join(ch.upper() for ch in text if ch.isascii() and ch.isalpha())
    return clean, len(text) - len(clean)


def validate_key(key, rails):
    """Raise ValueError with a friendly message if key or rails is unusable.

    key must be letters only (A-Z, either case) and at least 10 letters long.
    rails must be an int from 2 to 10. They are checked as separate inputs.

    Time complexity: O(k) - one pass over the key; the rails check is O(1).
    """
    if not isinstance(key, str):
        raise ValueError("The key must be text made of letters only.")
    if not key or not key.isascii() or not key.isalpha():
        raise ValueError(
            "The key must contain letters only (A-Z). "
            "Remove any digits, spaces or symbols."
        )
    if len(key) < MIN_KEY_LENGTH:
        raise ValueError(
            f"The key is too short ({len(key)} letters). "
            f"Please use at least {MIN_KEY_LENGTH} letters."
        )
    if isinstance(rails, bool) or not isinstance(rails, int):
        raise ValueError("The number of rails must be a whole number.")
    if not MIN_RAILS <= rails <= MAX_RAILS:
        raise ValueError(
            f"The number of rails must be between {MIN_RAILS} and {MAX_RAILS}."
        )


def _check_letters(text, what):
    """Raise ValueError unless text is all A-Z. O(N)."""
    if not all("A" <= ch <= "Z" for ch in text):
        raise ValueError(f"The {what} must contain only uppercase letters A-Z.")


def _key_shifts(key):
    """Convert a key to a list of 0..25 shifts. O(k)."""
    if not key:
        raise ValueError("The key must not be empty.")
    if not key.isascii() or not key.isalpha():
        raise ValueError("The key must contain letters only (A-Z).")
    return [ord(ch) - 65 for ch in key.upper()]


# --------------------------------------------------------------------------
# Shift cipher (baseline for later comparison)
# --------------------------------------------------------------------------

def shift_encrypt(pt, k):
    """Caesar/Shift cipher: C = (P + k) mod 26.

    Time complexity: O(N).
    """
    _check_letters(pt, "text")
    return "".join(chr((ord(ch) - 65 + k) % 26 + 65) for ch in pt)


def shift_decrypt(ct, k):
    """Inverse of shift_encrypt: P = (C - k) mod 26.

    Time complexity: O(N).
    """
    return shift_encrypt(ct, -k)


# --------------------------------------------------------------------------
# Stage 1: Vigenere
# --------------------------------------------------------------------------

def vigenere_encrypt(pt, key):
    """Vigenere: C = (P + K) mod 26, with the key repeating.

    Time complexity: O(N + k), i.e. O(N) for a key no longer than the text.
    """
    _check_letters(pt, "text")
    shifts = _key_shifts(key)
    k = len(shifts)
    return "".join(
        chr((ord(ch) - 65 + shifts[i % k]) % 26 + 65) for i, ch in enumerate(pt)
    )


def vigenere_decrypt(ct, key):
    """Vigenere: P = (C - K) mod 26, with the key repeating.

    Time complexity: O(N + k), i.e. O(N) for a key no longer than the text.
    """
    _check_letters(ct, "text")
    shifts = _key_shifts(key)
    k = len(shifts)
    return "".join(
        chr((ord(ch) - 65 - shifts[i % k]) % 26 + 65) for i, ch in enumerate(ct)
    )


# --------------------------------------------------------------------------
# Stage 2: Rail Fence
# --------------------------------------------------------------------------

def rail_order(n, rails):
    """Index permutation of a zigzag read-off for a text of length n.

    Returns a list `order` where order[i] is the position in the plaintext of
    the character that lands at position i of the ciphertext (rail 0 first,
    then rail 1, ...). Encrypt: ct[i] = pt[order[i]]. Decrypt: pt[order[i]] = ct[i].

    Time complexity: O(n) - each index is bucketed onto its rail once.
    """
    if isinstance(rails, bool) or not isinstance(rails, int) or rails < 2:
        raise ValueError("The number of rails must be a whole number, at least 2.")
    buckets = [[] for _ in range(rails)]
    rail, step = 0, 1
    for i in range(n):
        buckets[rail].append(i)
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        rail += step
    return [i for bucket in buckets for i in bucket]


def rail_encrypt(pt, rails):
    """Rail Fence encryption using rail_order.

    Time complexity: O(N).
    """
    order = rail_order(len(pt), rails)
    return "".join(pt[i] for i in order)


def rail_decrypt(ct, rails):
    """Rail Fence decryption using rail_order.

    Time complexity: O(N).
    """
    order = rail_order(len(ct), rails)
    out = [""] * len(ct)
    for pos, ch in zip(order, ct):
        out[pos] = ch
    return "".join(out)


# --------------------------------------------------------------------------
# Combined cipher
# --------------------------------------------------------------------------

def custom_encrypt(pt, key, rails):
    """Vigenere then Rail Fence. Returns (stage1, final).

    Raises ValueError (via validate_key) for a bad key or rails.

    Time complexity: O(N + k) overall, i.e. O(N).
    """
    validate_key(key, rails)
    stage1 = vigenere_encrypt(pt, key)
    return stage1, rail_encrypt(stage1, rails)


def custom_decrypt(ct, key, rails):
    """Undo Rail Fence first, then Vigenere. Returns the plaintext.

    Raises ValueError (via validate_key) for a bad key or rails.

    Time complexity: O(N + k) overall, i.e. O(N).
    """
    validate_key(key, rails)
    return vigenere_decrypt(rail_decrypt(ct, rails), key)
