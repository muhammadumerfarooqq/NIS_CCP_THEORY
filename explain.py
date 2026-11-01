"""Produces the "show working" data for the GUI: pure logic, no tkinter.

The GUI can show, letter by letter, HOW the two stages lock a message. This
file builds that data. It is kept separate from the window code so it can be
unit-tested without opening a window.

    vigenere_steps(...)   Stage 1 (Vigenere): one table row per letter
    rail_grid(...)        Stage 2 (Rail Fence): the zigzag grid

TRUST CHECK: the working is worked out here by simple arithmetic, written
independently of cipher.py. Every row and grid is then compared with what the
REAL functions in cipher.py produce. If they ever disagree, an
ExplainMismatchError is raised, so the GUI can never show working that does
not match the real cipher.

Only the 26 capital letters A-Z are supported (use cipher.sanitize first).
Standard library only.

How to read this file (top to bottom):
    1. SETTINGS AND ERRORS
    2. STAGE 1: VIGENERE WORKING   (substitution: changes WHAT each letter is)
    3. STAGE 2: RAIL FENCE WORKING (transposition: changes WHERE each letter is)
"""

import cipher


# ==========================================================================
# ===== SETTINGS AND ERRORS =====
# ==========================================================================

VIGENERE_LIMIT = 15     # how many letters the Vigenere table shows
RAIL_LIMIT = 40         # how many letters the Rail Fence grid shows


class ExplainMismatchError(Exception):
    """The working did not match what cipher.py really produces."""


def _need_capitals(text, what):
    # True only for a string of capital letters A-Z (an empty string is fine).
    if not isinstance(text, str) or (text and not (text.isascii() and text.isalpha() and text.isupper())):
        raise ValueError(f"The {what} must contain only capital letters A-Z.")


# ==========================================================================
# ===== STAGE 1: VIGENERE WORKING (substitution: changes WHAT each letter is) =====
# ==========================================================================
# Each letter becomes a number (A=0 ... Z=25). The key letter, also a number,
# is added (locking) or subtracted (unlocking), and "mod 26" wraps the result
# back into 0..25. The key repeats along the message.
#
# Worked example, locking "D" with key letter "C":
#     D = 3,  C = 2,   3 + 2 = 5,   5 mod 26 = 5,   5 = F      ->  D + C = F
# Example that wraps round the end of the alphabet ("L" with key letter "T"):
#     L = 11, T = 19,  11 + 19 = 30,  30 mod 26 = 4,  4 = E    ->  L + T = E
# Unlocking subtracts instead; "B" with key letter "C":
#     B = 1,  C = 2,   1 - 2 = -1,   -1 mod 26 = 25,  25 = Z   ->  B - C = Z

def vigenere_steps(text, key, decrypt=False, limit=VIGENERE_LIMIT):
    """Working for the first `limit` letters of a Vigenere lock (or unlock).

    `text` is the plaintext when locking, or the Stage-1 ciphertext when
    unlocking. Returns a dict:
        formula         the rule in words
        rows            list of dicts, one per letter, with the keys
                        pos, in_letter, in_num, key_letter, key_num, op,
                        raw, result_num, out_letter
        decrypt, shown, total
        matches_cipher  True (if it were False an error would have been raised)
    Raises ExplainMismatchError if any row disagrees with cipher.py.
    """
    _need_capitals(text, "text")
    if not isinstance(key, str) or not key or not (key.isascii() and key.isalpha()):
        raise ValueError("The key must contain letters only (A-Z).")
    key = key.upper()

    rows = []
    for i, letter in enumerate(text[:limit]):
        # The key repeats: position i uses key letter number (i mod key length).
        # Example, key "CAT": positions 0,1,2,3,4 use C,A,T,C,A.
        key_letter = key[i % len(key)]
        in_num = ord(letter) - 65           # A -> 0, B -> 1, ... Z -> 25
        key_num = ord(key_letter) - 65
        raw = in_num - key_num if decrypt else in_num + key_num
        result_num = raw % 26               # wrap round the alphabet
        rows.append({
            "pos": i + 1,                   # position counted from 1 for humans
            "in_letter": letter, "in_num": in_num,
            "key_letter": key_letter, "key_num": key_num,
            "op": "-" if decrypt else "+",
            "raw": raw,                     # before the wrap-around
            "result_num": result_num,
            "out_letter": chr(65 + result_num),
        })

    # The trust check: compare every row with the real cipher.
    check_vigenere_rows(text, key, rows, decrypt)
    sign = "-" if decrypt else "+"
    return {
        "formula": f"result = (letter {sign} key letter) mod 26,   A=0, B=1, ... Z=25",
        "rows": rows,
        "decrypt": decrypt,
        "shown": len(rows),
        "total": len(text),
        "matches_cipher": True,
    }


def check_vigenere_rows(text, key, rows, decrypt=False):
    """Raise ExplainMismatchError unless every row is right.

    A row must (1) describe the right input and key letters, (2) do its
    arithmetic correctly, and (3) end in the same letter that the real
    cipher.vigenere_encrypt / vigenere_decrypt produces at that position.
    """
    key = key.upper()
    real = cipher.vigenere_decrypt(text, key) if decrypt else cipher.vigenere_encrypt(text, key)
    if len(rows) > len(text):
        raise ExplainMismatchError("The working has more rows than the text has letters.")
    for i, row in enumerate(rows):
        where = f"row {i + 1}"
        key_letter = key[i % len(key)]
        in_num, key_num = ord(text[i]) - 65, ord(key_letter) - 65
        raw = in_num - key_num if decrypt else in_num + key_num
        expected = {
            "pos": i + 1, "in_letter": text[i], "in_num": in_num,
            "key_letter": key_letter, "key_num": key_num,
            "op": "-" if decrypt else "+", "raw": raw,
            "result_num": raw % 26, "out_letter": chr(65 + raw % 26),
        }
        for name, value in expected.items():
            if row.get(name) != value:
                raise ExplainMismatchError(
                    f"Vigenere {where}: '{name}' is {row.get(name)!r}, expected {value!r}.")
        # Finally the letter from the REAL cipher at this position.
        if row["out_letter"] != real[i]:
            raise ExplainMismatchError(
                f"Vigenere {where}: working gives {row['out_letter']} but cipher.py gives {real[i]}.")


def describe_row(row):
    """One row as a sentence-like string.

    Worked examples:
        "D (3) + C (2) = 5  ->  F"
        "L (11) + T (19) = 30, mod 26 = 4  ->  E"
    """
    text = f"{row['in_letter']} ({row['in_num']}) {row['op']} {row['key_letter']} ({row['key_num']}) = {row['raw']}"
    if row["raw"] != row["result_num"]:
        text += f", mod 26 = {row['result_num']}"
    return f"{text}  ->  {row['out_letter']}"


# ==========================================================================
# ===== STAGE 2: RAIL FENCE WORKING (transposition: changes WHERE each letter is) =====
# ==========================================================================
# The letters are written in a zigzag down and up across `rails` rows and then
# read off row by row. Nothing about the letters changes, only their order.
#
# Worked example, "ABCDEFGHIJ" on 3 rails (rail numbers 0 1 2 1 0 1 2 1 0 1):
#     rail 1:  A . . . E . . . I .      reads  AEI
#     rail 2:  . B . D . F . H . J      reads  BDFHJ
#     rail 3:  . . C . . . G . . .      reads  CG
#     joined:  AEIBDFHJCG
# Unlocking splits "AEIBDFHJCG" back into AEI / BDFHJ / CG (the rail lengths
# come from the zigzag pattern), puts each piece back on its rail, and reads
# the columns left to right: ABCDEFGHIJ.

def rail_pattern(n, rails):
    """Which rail (0-based) each of n positions sits on, as a list.

    The zigzag repeats every 2*(rails-1) positions, so the rail of position i
    comes straight from i mod that period. Worked example, 3 rails (period 4):
        position: 0 1 2 3 4 5 6 7
        i mod 4 : 0 1 2 3 0 1 2 3
        rail    : 0 1 2 1 0 1 2 1     (a 3 on the way up becomes 4-3 = 1)
    This is written independently of cipher.rail_order on purpose, so the two
    can check each other.
    """
    period = 2 * (rails - 1)
    pattern = []
    for i in range(n):
        r = i % period
        pattern.append(r if r < rails else period - r)
    return pattern


def rail_grid(text, rails, limit=RAIL_LIMIT, decrypt=False):
    """Working for the zigzag grid of the first `limit` letters of `text`.

    Locking (decrypt=False): `text` is the Stage-1 text. The grid shows each
    letter on its rail; reading the rails one after another gives `joined`.
    Unlocking (decrypt=True): `text` is the final ciphertext. It is cut into
    rail pieces, each piece is put back on its rail, and reading the columns
    left to right gives `joined` (the text with Stage 2 undone).

    If the text is longer than `limit`, only its first `limit` letters are
    shown and treated as a short message of their own (`truncated` is True).

    Returns a dict: rails, shown, total, truncated, decrypt, pattern,
    grid (list of strings, one per rail, '.' = empty cell), rail_strings,
    joined, matches_cipher. Raises ExplainMismatchError if the result
    disagrees with cipher.rail_encrypt / rail_decrypt.
    """
    _need_capitals(text, "text")
    if isinstance(rails, bool) or not isinstance(rails, int) or rails < 2:
        raise ValueError("The number of rails must be a whole number, at least 2.")
    shown = text[:limit]
    n = len(shown)
    pattern = rail_pattern(n, rails)
    cells = [["."] * n for _ in range(rails)]       # '.' means an empty cell

    if not decrypt:
        # Put each letter on its rail, then read the rails top to bottom.
        for i, letter in enumerate(shown):
            cells[pattern[i]][i] = letter
        rail_strings = ["".join(c for c in row if c != ".") for row in cells]
        joined = "".join(rail_strings)
    else:
        # How many letters sit on each rail tells us where to cut the text.
        # Example: pattern 0 1 2 1 0 1 2 1 0 1 -> rail lengths 3, 5, 2, so
        # "AEIBDFHJCG" is cut into "AEI" | "BDFHJ" | "CG".
        rail_strings, start = [], 0
        for r in range(rails):
            size = pattern.count(r)
            rail_strings.append(shown[start:start + size])
            start += size
        # Put each piece back on its rail, left to right...
        taken = [0] * rails
        for i in range(n):
            r = pattern[i]
            cells[r][i] = rail_strings[r][taken[r]]
            taken[r] += 1
        # ...then read the columns left to right: the zigzag order.
        joined = "".join(cells[pattern[i]][i] for i in range(n))

    result = {
        "rails": rails, "shown": n, "total": len(text), "truncated": len(text) > limit,
        "decrypt": decrypt, "pattern": pattern,
        "grid": ["".join(row) for row in cells],
        "rail_strings": rail_strings, "joined": joined, "matches_cipher": True,
    }
    check_rail_grid(shown, result)
    return result


def check_rail_grid(shown, result):
    """Raise ExplainMismatchError unless the grid result is right.

    `shown` is the text the grid was built from. The grid must have one letter
    in every column, its rows must match `rail_strings`, and the joined result
    must equal what the real cipher.rail_encrypt / rail_decrypt gives.
    """
    rails, grid, decrypt = result["rails"], result["grid"], result["decrypt"]
    n = len(shown)
    if len(grid) != rails or any(len(row) != n for row in grid):
        raise ExplainMismatchError("Rail Fence grid has the wrong shape.")

    # Read the grid two ways: column by column, and row by row.
    columns = []
    for i in range(n):
        letters = [row[i] for row in grid if row[i] != "."]
        if len(letters) != 1:
            raise ExplainMismatchError(f"Rail Fence column {i + 1} should hold exactly one letter.")
        columns.append(letters[0])
    by_column = "".join(columns)
    row_pieces = [row.replace(".", "") for row in grid]
    by_row = "".join(row_pieces)

    if row_pieces != result["rail_strings"]:
        raise ExplainMismatchError("Rail Fence rail strings do not match the grid rows.")
    if decrypt:
        real = cipher.rail_decrypt(shown, rails)
        ok = by_row == shown and by_column == real and result["joined"] == real
    else:
        real = cipher.rail_encrypt(shown, rails)
        ok = by_column == shown and by_row == real and result["joined"] == real
    if not ok:
        raise ExplainMismatchError(
            f"Rail Fence working does not match cipher.py (cipher.py gives {real!r}).")
