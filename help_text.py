"""The words for the Design tab of the GUI ("Req 1 / Deliverable 1 - Design"). No tkinter in here.

The tab is ONE short screen. design_lines() returns its lines as (style, text) pairs and
the GUI turns the style names into fonts and colours.

Two kinds of text:

* FIXED WORDS: the explanation of the two stages. The two worked examples in it
  (HELLO + key CAT = JEENO, and ABCDEFGHIJ on 3 rails = AEIBDFHJCG) are NOT typed in:
  they are run through cipher.py every time, and if cipher.py ever disagrees, a red
  warning is shown instead of the example.
* NUMBERS: the speed ratio and the message length from which the frequency attack
  works are READ from the saved results (the CSV data passed in), never typed in.
  If a results file is missing, the line says so instead of inventing a number.

Standard library only.
"""

import statistics

import attack
import cipher

# The frequency attack "works" from the smallest message length whose exact-plaintext
# success rate in the saved results reaches this many percent.
WORKS_FROM_PERCENT = 80.0

# The two worked examples: what goes in and what the lecture says comes out.
STAGE1_EXAMPLE = {"plain": "HELLO", "key": "CAT", "expected": "JEENO"}
STAGE2_EXAMPLE = {"plain": "ABCDEFGHIJ", "rails": 3, "expected": "AEIBDFHJCG"}


def stage1_example():
    """Run the Stage 1 example through cipher.py. Returns (text to show, True if it matches the lecture answer).

    Worked example: HELLO with key CAT gives  ("HELLO + key CAT = JEENO", True).
    """
    got = cipher.vigenere_encrypt(STAGE1_EXAMPLE["plain"], STAGE1_EXAMPLE["key"])
    return f"{STAGE1_EXAMPLE['plain']} + key {STAGE1_EXAMPLE['key']} = {got}", got == STAGE1_EXAMPLE["expected"]


def stage2_example():
    """Run the Stage 2 example through cipher.py. Returns (text to show, True if it matches the lecture answer).

    Worked example: ABCDEFGHIJ on 3 rails gives  ("ABCDEFGHIJ on 3 rails = AEIBDFHJCG", True).
    """
    got = cipher.rail_encrypt(STAGE2_EXAMPLE["plain"], STAGE2_EXAMPLE["rails"])
    return (f"{STAGE2_EXAMPLE['plain']} on {STAGE2_EXAMPLE['rails']} rails = {got}",
            got == STAGE2_EXAMPLE["expected"])


def speed_line(speed_data):
    """The Speed line. `speed_data` is what gui.read_benchmark_csv returns, or None if the file is missing.

    The ratio is the median of the custom/shift ratios in Table A (one per message size).
    """
    start = "Speed: both stages are O(N)."
    if not speed_data:
        return f"{start} (results/benchmark_results.csv was not found, so there is no speed ratio to show.)"
    ratio = statistics.median(row["ratio"] for row in speed_data["table_a"])
    return f"{start} Custom is about {ratio:.1f} times slower than Shift."


def attack_line(attack_data):
    """The Attack line. `attack_data` is what gui.read_attack_csv returns, or None if the file is missing.

    "Works from" = the smallest message length whose exact-plaintext success rate (Table 1,
    frequency attack) is at least WORKS_FROM_PERCENT in the saved results.
    """
    crib = f"known-plaintext needs a crib of at least key length + {attack.MIN_CHECKS} letters."
    if not attack_data:
        return ("Attack: no saved attack results (results/attack_results.csv was not found); "
                f"{crib}")
    good = [row["text_length"] for row in attack_data["table1"] if row["exact_pct"] >= WORKS_FROM_PERCENT]
    if good:
        frequency = f"frequency attack works from about {min(good)} letters"
    else:
        frequency = f"frequency attack did not reach {WORKS_FROM_PERCENT:.0f} percent in the saved results"
    return f"Attack: {frequency}; {crib}"


def design_lines(attack_data=None, speed_data=None):
    """The whole Design page as a list of (style, text) pairs, about a dozen short lines.

    Styles: "title", "stage1" (blue), "stage2" (orange), "example" (fixed-width), "body",
    and "warning" (red; replaces an example that disagrees with cipher.py).
    """
    lines = [("title", "Two stages, applied in order."),
             ("stage1", "Stage 1 - Vigenere (substitution): changes WHAT each letter is. "
                        "Add the key letter, wrap after Z.")]
    text, matches = stage1_example()
    lines.append(("example", text) if matches else
                 ("warning", f"WARNING: the Stage 1 example does not match cipher.py ({text}). Do not rely on this page."))
    lines.append(("stage2", "Stage 2 - Rail Fence (transposition): changes WHERE each letter is. "
                            "Write in a zigzag over r rails, read row by row."))
    text, matches = stage2_example()
    lines.append(("example", text) if matches else
                 ("warning", f"WARNING: the Stage 2 example does not match cipher.py ({text}). Do not rely on this page."))
    lines += [
        ("body", "Unlock = undo Stage 2 first, then Stage 1."),
        ("body", "Why combine: Stage 1 hides which letter is which, Stage 2 hides the order. "
                 "An attacker must solve both."),
        ("body", f"Key: at least {cipher.MIN_KEY_LENGTH} letters for Stage 1, "
                 f"plus rails {cipher.MIN_RAILS} to {cipher.MAX_RAILS} for Stage 2."),
        ("body", speed_line(speed_data)),
        ("body", attack_line(attack_data)),
    ]
    return lines
