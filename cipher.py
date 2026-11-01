"""Two-stage classical cipher: Stage 1 Vigenere, Stage 2 Rail Fence.

Only the 26 letters A-Z are supported. Use sanitize() first to strip other
characters. The key and the number of rails are two separate inputs.

Standard library only. N below always means the length of the input text and
k the length of the key; every function is O(N) (O(N + k) where the key is
processed too, which is still linear in the input size).

How to read this file (top to bottom):
    1. INPUT CHECKS     clean the text, make sure the key and rails are valid
    2. SHIFT BASELINE   the simplest cipher, kept for comparison
    3. STAGE 1          Vigenere   (substitution: changes WHAT each letter is)
    4. STAGE 2          Rail Fence (transposition: changes WHERE each letter is)
    5. COMBINED CIPHER  Stage 1 followed by Stage 2 (and the reverse to decrypt)
"""

import string

# The 26 capital letters "ABCDEFGHIJKLMNOPQRSTUVWXYZ". Letter A is number 0,
# B is 1, ... Z is 25. All the cipher maths below uses these numbers.
ALPHABET = string.ascii_uppercase
# Rules for a valid key (these are the project's rules, checked by validate_key).
MIN_KEY_LENGTH = 10
MIN_RAILS = 2
MAX_RAILS = 10


# ==========================================================================
# ===== INPUT CHECKS (clean the text, validate the key and the rails) =====
# ==========================================================================

def sanitize(text):
    """Keep only A-Z, uppercased. Return (clean_text, removed_count).

    Time complexity: O(N) - one pass over the text.
    """
    # Keep a character only if it is a plain English letter (a-z or A-Z).
    # Spaces, digits, punctuation and accented letters are dropped.
    # We test the ORIGINAL character first and uppercase it afterwards, because
    # some Unicode letters grow when uppercased ("ß" -> "SS"), which would
    # make the "how many were removed" count wrong.
    clean = "".join(ch.upper() for ch in text if ch.isascii() and ch.isalpha())
    # Removed count = how many characters we started with minus how many survived.
    return clean, len(text) - len(clean)


def validate_key(key, rails):
    """Raise ValueError with a friendly message if key or rails is unusable.

    key must be letters only (A-Z, either case) and at least 10 letters long.
    rails must be an int from 2 to 10. They are checked as separate inputs.

    Time complexity: O(k) - one pass over the key; the rails check is O(1).
    """
    # --- Check the key ---
    # Is the key text at all? (Stops things like None or a number.)
    if not isinstance(key, str):
        raise ValueError("The key must be text made of letters only.")
    # Empty, non-ASCII or containing anything that is not a letter (digits,
    # spaces, symbols) is rejected. isalpha() is True only for letters.
    if not key or not key.isascii() or not key.isalpha():
        raise ValueError(
            "The key must contain letters only (A-Z). "
            "Remove any digits, spaces or symbols."
        )
    # A short key repeats too quickly and is easy to attack, so we insist on 10+.
    if len(key) < MIN_KEY_LENGTH:
        raise ValueError(
            f"The key is too short ({len(key)} letters). "
            f"Please use at least {MIN_KEY_LENGTH} letters."
        )
    # --- Check the rails (a separate input from the key) ---
    # True/False count as ints in Python, so we reject them explicitly.
    if isinstance(rails, bool) or not isinstance(rails, int):
        raise ValueError("The number of rails must be a whole number.")
    if not MIN_RAILS <= rails <= MAX_RAILS:
        raise ValueError(
            f"The number of rails must be between {MIN_RAILS} and {MAX_RAILS}."
        )


def _check_letters(text, what):
    """Raise ValueError unless text is all A-Z. O(N)."""
    # all(...) is True only if EVERY character is a capital letter A..Z.
    # The cipher maths below only works on capitals, so we refuse anything else
    # instead of silently producing a wrong answer.
    if not all("A" <= ch <= "Z" for ch in text):
        raise ValueError(f"The {what} must contain only uppercase letters A-Z.")


def _key_shifts(key):
    """Convert a key to a list of 0..25 shifts. O(k)."""
    if not key:
        raise ValueError("The key must not be empty.")
    if not key.isascii() or not key.isalpha():
        raise ValueError("The key must contain letters only (A-Z).")
    # Turn each key letter into a number: A->0, B->1, ..., Z->25.
    # ord("A") is 65, so ord(letter) - 65 gives the letter's position.
    # Example: "CAT" -> [2, 0, 19]. (The key is uppercased first, so "cat" works too.)
    return [ord(ch) - 65 for ch in key.upper()]


# ==========================================================================
# ===== SHIFT BASELINE (Caesar cipher: every letter moves the same amount) =====
# ==========================================================================

def shift_encrypt(pt, k):
    """Caesar/Shift cipher: C = (P + k) mod 26.

    Time complexity: O(N).
    """
    _check_letters(pt, "text")
    # For each letter: ord(ch) - 65 makes it a number 0..25, "+ k" moves it
    # k places along the alphabet, "% 26" wraps around the end (Z + 1 -> A),
    # and "+ 65" turns the number back into a capital letter.
    # Example with k = 3: "X" is 23, 23 + 3 = 26, 26 % 26 = 0 -> "A".
    return "".join(chr((ord(ch) - 65 + k) % 26 + 65) for ch in pt)


def shift_decrypt(ct, k):
    """Inverse of shift_encrypt: P = (C - k) mod 26.

    Time complexity: O(N).
    """
    # Decrypting is just encrypting with the opposite shift (-k).
    return shift_encrypt(ct, -k)


# ==========================================================================
# ===== STAGE 1: VIGENERE (substitution: changes WHAT each letter is) =====
# ==========================================================================
# A Vigenere cipher is a Caesar shift whose amount changes from letter to
# letter. The key says how far to shift each letter, and the key repeats.
#
# Worked example (key "CAT" = shifts [2, 0, 19], plaintext "HELLO"):
#     H(7)  + C(2)  =  9  -> J
#     E(4)  + A(0)  =  4  -> E
#     L(11) + T(19) = 30  -> 30 mod 26 = 4  -> E     (wraps past Z)
#     L(11) + C(2)  = 13  -> N                       (the key starts over)
#     O(14) + A(0)  = 14  -> O
#     "HELLO" -> "JEENO"
# Another tiny one: D(3) + C(2) = 5 -> F.

def vigenere_encrypt(pt, key):
    """Vigenere: C = (P + K) mod 26, with the key repeating.

    Time complexity: O(N + k), i.e. O(N) for a key no longer than the text.
    """
    _check_letters(pt, "text")
    # The key as numbers, e.g. "CAT" -> [2, 0, 19].
    shifts = _key_shifts(key)
    # k = how many key letters there are (the key's length).
    k = len(shifts)
    # i is the position of the plaintext letter (0, 1, 2, ...).
    # i % k is the matching key position: it counts 0, 1, ..., k-1, then goes
    # back to 0, which is exactly how the key "repeats" along the message.
    # Then it is the same recipe as the Shift cipher, with this letter's own
    # shift: letter number + shift, wrapped with % 26, turned back into a letter.
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
    # Same as encryption but we SUBTRACT the shift to undo it.
    # If the subtraction goes below 0 (e.g. B(1) - C(2) = -1), Python's %
    # still gives a number from 0 to 25 (-1 % 26 = 25 -> "Z"), so no special
    # handling is needed.
    # Check: "F"(5) - C(2) = 3 -> "D", which undoes D + C -> F from above.
    return "".join(
        chr((ord(ch) - 65 - shifts[i % k]) % 26 + 65) for i, ch in enumerate(ct)
    )


# ==========================================================================
# ===== STAGE 2: RAIL FENCE (transposition: changes WHERE each letter is) =====
# ==========================================================================
# Rail Fence does not change any letter. It only shuffles their positions.
# The message is written in a zigzag down and up across `rails` rows, and then
# the rows are read off one after another.
#
# Worked example: "ABCDEFGHIJ" with 3 rails. Each letter sits on a rail, and
# the rail number goes 0, 1, 2, 1, 0, 1, 2, 1, 0, 1 (down, then up, ...):
#
#   position: 0 1 2 3 4 5 6 7 8 9
#   rail 0:   A . . . E . . . I .
#   rail 1:   . B . D . F . H . J
#   rail 2:   . . C . . . G . . .
#
# Reading rail 0, then rail 1, then rail 2 gives "AEI" + "BDFHJ" + "CG"
# = "AEIBDFHJCG". The same thing as a list of positions (the "order"):
#   order = [0, 4, 8,  1, 3, 5, 7, 9,  2, 6]
# Encrypting: ciphertext[i] = plaintext[order[i]]  (pick letters in that order).
# Decrypting: put ciphertext[i] back at position order[i]  (reverse the pick).

def rail_order(n, rails):
    """Index permutation of a zigzag read-off for a text of length n.

    Returns a list `order` where order[i] is the position in the plaintext of
    the character that lands at position i of the ciphertext (rail 0 first,
    then rail 1, ...). Encrypt: ct[i] = pt[order[i]]. Decrypt: pt[order[i]] = ct[i].

    Time complexity: O(n) - each index is bucketed onto its rail once.
    """
    # A zigzag needs at least 2 rails (with 1 rail there is nothing to bounce between).
    if isinstance(rails, bool) or not isinstance(rails, int) or rails < 2:
        raise ValueError("The number of rails must be a whole number, at least 2.")
    # One empty "bucket" (list) per rail. We will drop each position number
    # into the bucket of the rail it lands on.
    buckets = [[] for _ in range(rails)]
    # rail = the rail we are on now (start at the top, rail 0).
    # step = which way we are moving: +1 means down, -1 means up.
    rail, step = 0, 1
    for i in range(n):
        # Position i of the message lands on the current rail.
        buckets[rail].append(i)
        # Bounce: at the top rail turn downward, at the bottom rail turn upward.
        if rail == 0:
            step = 1
        elif rail == rails - 1:
            step = -1
        # Move to the next rail for the next letter.
        rail += step
    # Read the rails one after another (top rail first). Joining the buckets
    # in order gives the "order" list from the drawing above.
    return [i for bucket in buckets for i in bucket]


def rail_encrypt(pt, rails):
    """Rail Fence encryption using rail_order.

    Time complexity: O(N).
    """
    # How the positions are read off, rail by rail.
    order = rail_order(len(pt), rails)
    # Build the ciphertext by taking plaintext letters in that order.
    return "".join(pt[i] for i in order)


def rail_decrypt(ct, rails):
    """Rail Fence decryption using rail_order.

    Time complexity: O(N).
    """
    # The ciphertext was made by reading positions in this exact order, so the
    # same order tells us where every ciphertext letter came from.
    order = rail_order(len(ct), rails)
    # An empty row of slots, one per letter, to be filled back in.
    out = [""] * len(ct)
    # zip pairs them up: the first ciphertext letter with order[0], the second
    # with order[1], and so on. Each letter goes back to its original position.
    for pos, ch in zip(order, ct):
        out[pos] = ch
    return "".join(out)


# ==========================================================================
# ===== COMBINED CIPHER (Stage 1 Vigenere, then Stage 2 Rail Fence) =====
# ==========================================================================
# Encrypt:  plaintext --Vigenere--> stage1 --Rail Fence--> final ciphertext
# Decrypt:  final ciphertext --undo Rail Fence--> stage1 --undo Vigenere--> plaintext
# Decryption must undo the stages in the REVERSE order, like taking off socks
# and then shoes after putting on socks and then shoes.

def custom_encrypt(pt, key, rails):
    """Vigenere then Rail Fence. Returns (stage1, final).

    Raises ValueError (via validate_key) for a bad key or rails.

    Time complexity: O(N + k) overall, i.e. O(N).
    """
    # Refuse a bad key or rails before doing any work.
    validate_key(key, rails)
    # Stage 1: change what each letter is.
    stage1 = vigenere_encrypt(pt, key)
    # Stage 2: shuffle where the letters are. We return both so callers can
    # show the intermediate result.
    return stage1, rail_encrypt(stage1, rails)


def custom_decrypt(ct, key, rails):
    """Undo Rail Fence first, then Vigenere. Returns the plaintext.

    Raises ValueError (via validate_key) for a bad key or rails.

    Time complexity: O(N + k) overall, i.e. O(N).
    """
    validate_key(key, rails)
    # Last stage undone first (Rail Fence), then the first stage (Vigenere).
    return vigenere_decrypt(rail_decrypt(ct, rails), key)
