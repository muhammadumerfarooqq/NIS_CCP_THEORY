"""The words for the "How It Works" tab of the GUI. No tkinter in here.

Two kinds of text:

* STATIC TEXT (the constants below): explanations that never change, such as
  the formulas and the worked examples. They contain NO measured results.
* RESULTS TEXT (built by results_section): every number about how well the
  attacks work or how fast the cipher is is READ from the results CSV files
  at runtime and passed in. Nothing is typed in by hand, so this text can never
  drift away from the real results. If a CSV file is missing, the text says so
  instead of inventing numbers.

build_help_document(...) joins everything into a list of (style, text) pairs;
the GUI turns the style names into fonts and colours.

Standard library only.
"""

import attack
import cipher


# ==========================================================================
# ===== STATIC TEXT (explanations, formulas and worked examples) =====
# ==========================================================================

TITLE = "How It Works"

WHAT_IT_DOES = (
    "This program locks (encrypts) a message using two classical ciphers, one after "
    "the other, and unlocks it again. It can also try to break its own cipher with "
    "two attacks, and it can time itself.\n\n"
    "    Stage 1 - Vigenere   (substitution):  changes WHAT each letter is.\n"
    "    Stage 2 - Rail Fence (transposition): changes WHERE each letter is.\n\n"
    "Only the 26 letters A-Z are used. Spaces, digits, punctuation and accents are "
    "removed when you lock, and they cannot be brought back when you unlock."
)

STAGE1_TITLE = "Stage 1 - Vigenere (substitution: changes WHAT each letter is)"
STAGE1_TEXT = (
    "Every letter becomes a number: A=0, B=1, ... Z=25. The key is a word, and its "
    "letters are numbers too. The key repeats along the message.\n\n"
    "    locking:    result = (letter + key letter) mod 26\n"
    "    unlocking:  result = (letter - key letter) mod 26\n\n"
    "'mod 26' means 'wrap round the alphabet': after Z comes A again.\n\n"
    "Tiny example:   D (3) + C (2) = 5  ->  F\n\n"
    "Longer example: lock HELLO with the key CAT (the key repeats: C A T C A)\n"
    "    H (7)  + C (2)  =  9              ->  J\n"
    "    E (4)  + A (0)  =  4              ->  E\n"
    "    L (11) + T (19) = 30, mod 26 = 4  ->  E\n"
    "    L (11) + C (2)  = 13              ->  N\n"
    "    O (14) + A (0)  = 14              ->  O\n"
    "    so HELLO becomes JEENO."
)

STAGE2_TITLE = "Stage 2 - Rail Fence (transposition: changes WHERE each letter is)"
STAGE2_TEXT = (
    "The letters are written in a zigzag down and up across a number of rows (the "
    "'rails'), and then read off row by row. No letter changes, only the order.\n\n"
    "Example: ABCDEFGHIJ on 3 rails\n\n"
    "    position:  0 1 2 3 4 5 6 7 8 9\n"
    "    rail 1:    A . . . E . . . I .      reads  AEI\n"
    "    rail 2:    . B . D . F . H . J      reads  BDFHJ\n"
    "    rail 3:    . . C . . . G . . .      reads  CG\n\n"
    "    joined:    AEIBDFHJCG"
)

ORDER_TITLE = "Why unlocking undoes Stage 2 first"
ORDER_TEXT = (
    "Locking does Stage 1, then Stage 2. To undo it you must go backwards, last "
    "step first: first undo Stage 2 (Rail Fence), then undo Stage 1 (Vigenere). It "
    "is like putting on socks and then shoes: to undo it, shoes come off first."
)

COMPLEXITY_TITLE = "How fast does it grow? (complexity)"
COMPLEXITY_TEXT = (
    "N is the message length and k the key length.\n\n"
    "    Shift cipher (the baseline)   O(N)\n"
    "    Vigenere (Stage 1)            O(N + k)\n"
    "    Rail Fence (Stage 2)          O(N)\n"
    "    Both stages together          O(N + k), which is O(N) for a fixed key length\n\n"
    "O(N) means: double the message and the work roughly doubles. The 'Speed Test' "
    "tab measures this, and the measured numbers are shown at the bottom of this page."
)

ATTACKS_TITLE = "The two attacks, in plain words"


def attacks_text():
    """The attack explanation. The only numbers here come from the code's own
    constants (so they cannot drift), not from measured results."""
    return (
        "The attacker knows the method (Vigenere, then Rail Fence) and has the "
        "ciphertext, but not the key, the key length or the number of rails. The "
        f"attacker may try every rails value ({cipher.MIN_RAILS} to {cipher.MAX_RAILS}) "
        "because those are public.\n\n"
        "Frequency attack (ciphertext only)\n"
        "  1. Guess a number of rails and undo Rail Fence.\n"
        "  2. Guess the key length. A Vigenere key of length L shifts letters 1, L+1, "
        "2L+1, ... all by the same amount, so every L-th letter forms a 'column' that is "
        "just a Caesar cipher of English.\n"
        "  3. Index of Coincidence (IC): the chance that two letters picked from a text "
        "are the same. English has many E's and T's, so its IC is high; a jumble of "
        "random letters has a low IC. The right key length makes every column look like "
        "shifted English, so the average IC of the columns is high.\n"
        "  4. Chi-squared: a score for how far a text's letter counts are from normal "
        "English (lower is closer). For each column try all 26 shifts and keep the one "
        "that looks most like English. The 26 best shifts spell the key.\n\n"
        "Known-plaintext attack (ciphertext plus a crib)\n"
        "  A crib is the first few letters of the message, known to the attacker. Since "
        "cipher = plain + key (mod 26), cipher - plain gives the key. That reveals the "
        "first letters of the key stream.\n"
        "  The real key repeats every L letters, so the key stream must repeat too. "
        "That is the periodicity check: a wrong rails guess or a wrong key length gives "
        "a stream that does not repeat. A guess is trusted ('verified') only if it "
        f"repeats perfectly over at least {attack.MIN_CHECKS} comparisons, because "
        "passing that few by luck is very unlikely. This needs a crib at least "
        f"{attack.MIN_CHECKS} letters longer than the key. If nothing can be verified, "
        "the attack falls back to picking the most English-looking guess, which only "
        "works when the message really is English-like."
    )


def limitations_text():
    """A short honest list. Only code constants appear as numbers."""
    return (
        "  * Only the letters A-Z are supported; other characters are lost on locking.\n"
        f"  * Rail Fence has only {cipher.MAX_RAILS - cipher.MIN_RAILS + 1} possible keys "
        f"({cipher.MIN_RAILS} to {cipher.MAX_RAILS} rails), so it adds almost no secrecy; "
        "an attacker just tries them all.\n"
        "  * Vigenere with a short or repeating key can be broken with the Index of "
        "Coincidence (Kasiski / IC).\n"
        "  * Classical ciphers are not secure against modern attacks. Do not use this to "
        "protect real data.\n"
        "  * The frequency attack needs enough text for every key letter, so it fails on "
        "short messages.\n"
        "  * The known-plaintext attack needs a crib clearly longer than the key.\n"
        "  * The test messages come from one author's English prose, so real texts may "
        "behave differently.\n"
        "  * Timings depend on this machine and on the Python version.\n"
        "The full list, with the defence and the planned fix for each, is in "
        "docs/LIMITATIONS.md."
    )


LIMITATIONS_TITLE = "The main limitations (honest list)"
RESULTS_TITLE = "Measured results (read from the results files each time you open this tab)"

# The names of all static text blocks, so a test can check them for results.
STATIC_TEXT_BLOCKS = [WHAT_IT_DOES, STAGE1_TEXT, STAGE2_TEXT, ORDER_TEXT, COMPLEXITY_TEXT]


# ==========================================================================
# ===== RESULTS TEXT (every number here is read from the CSV data) =====
# ==========================================================================

MISSING_ATTACK = ("results/attack_results.csv was not found, so no attack results are "
                  "shown. Run  python attack.py  to create it.")
MISSING_SPEED = ("results/benchmark_results.csv was not found, so no speed results are "
                 "shown. Run  python benchmark.py  to create it.")


def _table_lines(title, rows, vary, label):
    """A small fixed-width table. Worked example of one line:
    '    500     84.0     98.9    100.0'  (N, exact %, key accuracy %, rails %)."""
    lines = [title, f"  {label:>8} {'exact %':>9} {'key acc %':>10} {'rails %':>9}"]
    for r in rows:
        lines.append(f"  {r[vary]:>8} {r['exact_pct']:>9.1f} {r['key_acc_pct']:>10.1f} {r['rails_pct']:>9.1f}")
    return "\n".join(lines)


def attack_results_lines(attack_data):
    """Text for the attack results. `attack_data` is the dict read from
    attack_results.csv ({"table1": rows, ...}) or None if the file is missing."""
    if not attack_data:
        return MISSING_ATTACK
    trials = attack_data["table1"][0]["trials"]
    crib = attack_data["table2"][0]["crib"]
    n3 = attack_data["table3"][0]["text_length"]
    return "\n\n".join([
        f"Attack results (from results/attack_results.csv, {trials} trials per row)",
        _table_lines("Frequency attack, ciphertext only, by message length:",
                     attack_data["table1"], "text_length", "N"),
        _table_lines(f"Known-plaintext attack with a crib of {crib} letters, by message length:",
                     attack_data["table2"], "text_length", "N"),
        _table_lines(f"Known-plaintext attack, message of {n3} letters, by crib size:",
                     attack_data["table3"], "crib", "crib M"),
    ])


def speed_results_lines(speed_data):
    """Text for the speed results. `speed_data` is the dict read from
    benchmark_results.csv ({"table_a", "fits", "memory"}) or None if missing."""
    if not speed_data:
        return MISSING_SPEED
    table_a = speed_data["table_a"]
    per_char = [r["us_per_char"] for r in table_a]
    lines = [
        "Speed results (from results/benchmark_results.csv; timings depend on the machine they were made on)",
        f"  The two-stage cipher cost {min(per_char):.3f} to {max(per_char):.3f} microseconds per "
        f"character for messages of {table_a[0]['n']} to {table_a[-1]['n']} letters.",
    ]
    for fit in speed_data["fits"]:
        lines.append(f"  {fit['name']}: log-log slope {fit['loglog_slope']:.3f}, "
                     f"R^2 {fit['r_squared']:.5f} -> {fit['verdict']}")
    for m in speed_data["memory"]:
        lines.append(f"  Memory, {m['name']}, N = {m['n']}: peak {m['peak_kb']:.1f} KB "
                     f"({m['bytes_per_char']:.1f} bytes per character)")
    return "\n".join(lines)


def build_help_document(attack_data=None, speed_data=None):
    """The whole How It Works page as a list of (style, text) pairs.

    Styles: "title", "heading", "stage1", "stage2" (coloured headings),
    "body", "mono" (fixed-width), "note". attack_data / speed_data come from
    the CSV readers in gui.py, or are None when a file is missing.
    """
    return [
        ("title", TITLE),
        ("body", WHAT_IT_DOES),
        ("stage1", STAGE1_TITLE),
        ("mono", STAGE1_TEXT),
        ("stage2", STAGE2_TITLE),
        ("mono", STAGE2_TEXT),
        ("heading", ORDER_TITLE),
        ("body", ORDER_TEXT),
        ("heading", COMPLEXITY_TITLE),
        ("mono", COMPLEXITY_TEXT),
        ("heading", ATTACKS_TITLE),
        ("body", attacks_text()),
        ("heading", LIMITATIONS_TITLE),
        ("body", limitations_text()),
        ("heading", RESULTS_TITLE),
        ("mono", attack_results_lines(attack_data) + "\n\n" + speed_results_lines(speed_data)),
        ("note", "These numbers are not typed into the program. If you re-run attack.py or "
                 "benchmark.py, they change here the next time you open this tab."),
    ]
