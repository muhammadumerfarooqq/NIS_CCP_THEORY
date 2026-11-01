"""Desktop window for the Vigenere + Rail Fence cipher.   Start it with:

    python gui.py

One window, four tabs (named after the course project's requirements):
    Req 2 - Encrypt & Decrypt           lock and unlock a message, with optional step-by-step working
    Req 3 / Deliverable 2 - Attack      try the two attacks, and run the experiments
    Req 4 - Efficiency                  time the cipher and see the growth is linear
    Req 1 / Deliverable 1 - Design      plain-English explanation, with numbers read from the results files

The START HERE button (top right) starts a 5-step guided tour through the real buttons.

SAFETY RULES this program follows:
    * No network, no local server, no eval/exec.
    * The key is never saved anywhere. It lives only in the window while you use it.
    * Files are written only through a Save dialog that you confirm, and the
      protected result files (results/attack_results.csv and so on) are never
      overwritten from here.
    * Standard library only (tkinter + ttk).

How to read this file (top to bottom):
    1. SETTINGS                colours, fonts, paths
    2. SELF-TEST               checks the cipher against known answers
    3. HELPERS                 pure functions: CSV readers, number formatting, chart drawing, working text
    4. THE APP                 class App, in sections:
         window frame, TAB 1 (Lock / Unlock), TAB 2 (Break It), TAB 3 (Speed Test),
         TAB 4 (How It Works), background jobs, closing
    5. START-UP                main()

The handlers (do_encrypt, do_decrypt, run_attack, ...) do not need a mouse:
the buttons just call them, and the tests call them directly.
"""

import csv
import math
import os
import queue
import random
import statistics
import string
import threading
import time

# tkinter ships with most Python installs, but not all (some Linux systems
# need a separate "python3-tk" package). If it is missing we do NOT crash
# with a traceback: main() prints one friendly line instead, and the
# window-free helpers in this file can still be imported.
try:
    import tkinter as tk
    from tkinter import filedialog, ttk
    from tkinter import font as tkfont
    TKINTER_ERROR = None
except ImportError as _error:
    tk = filedialog = ttk = tkfont = None
    TKINTER_ERROR = str(_error)

import attack
import benchmark
import cipher
import explain
import help_text


# ==========================================================================
# ===== SETTINGS (colours, fonts, paths) =====
# ==========================================================================

APP_TITLE = "CT-486 NIS CCP - Vigenere + Rail Fence"

# Calm light colours. Stage 1 (Vigenere) is always BLUE and Stage 2 (Rail
# Fence) is always ORANGE, wherever the window mentions them.
BG = "#f3f5f8"            # window background
PANEL = "#ffffff"         # white panels
TEXT = "#1f2937"          # normal text
MUTED = "#6b7280"         # grey helper text
GREEN = "#15803d"         # good / yes
RED = "#c0262d"           # errors / no
STAGE1_BG, STAGE1_FG = "#dbeafe", "#1d4ed8"      # Stage 1 - Vigenere (blue)
STAGE2_BG, STAGE2_FG = "#ffedd5", "#c2410c"      # Stage 2 - Rail Fence (orange)
NEUTRAL_BG = "#eef1f5"    # boxes that belong to neither stage

FONT_LABEL = ("Segoe UI", 11)
FONT_BOLD = ("Segoe UI", 11, "bold")
FONT_SMALL = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 15, "bold")
FONT_MONO = ("Consolas", 11)

# Where the saved results live (the same files attack.py and benchmark.py write).
ATTACK_CSV = attack.RESULTS_PATH
BENCH_CSV = benchmark.RESULTS_PATH
# Files this window will never write to, even if the user picks one in a Save dialog.
PROTECTED_FILES = [attack.RESULTS_PATH, attack.RESULTS_PATH_QUICK,
                   benchmark.RESULTS_PATH, benchmark.RESULTS_PATH_QUICK]

SAMPLE_MESSAGE = "Defend the east wall of the castle. Meet at dawn, by the old bridge!"
SAMPLE_KEY = "CRYPTOGRAPHY"
SAMPLE_RAILS = 5
DEFAULT_TEST_LENGTH = 500          # the message length the Attack tab starts with

# The four main tabs, in order, named after the course project's requirements.
# "·" is a middle dot. If the long names would not fit the smallest window
# (950 pixels wide) the shorter names are used instead (see _choose_tab_titles).
TAB_LOCK, TAB_ATTACK, TAB_EFFICIENCY, TAB_DESIGN = 0, 1, 2, 3
TAB_TITLES_LONG = ["Req 2 · Encrypt & Decrypt", "Req 3 · Deliverable 2 · Attack",
                   "Req 4 · Efficiency", "Req 1 · Deliverable 1 · Design"]
TAB_TITLES_SHORT = ["Req 2: Encrypt/Decrypt", "Req 3 + Del. 2: Attack",
                    "Req 4: Efficiency", "Req 1 + Del. 1: Design"]

# What the status bar says when a tab is opened and nothing has happened there yet.
READY_MESSAGES = {
    TAB_LOCK: f"Ready. Type a message, a key of at least {cipher.MIN_KEY_LENGTH} letters, and press Lock.",
    TAB_ATTACK: "Ready. Make a test message, pick an attack and press Run attack.",
    TAB_EFFICIENCY: "Ready. Load the saved results, or press Run to measure on this machine.",
    TAB_DESIGN: "Ready. This page explains the design; its numbers come from the saved results files.",
}

# A key with fewer different letters than this gets an orange warning (it is still allowed).
WEAK_KEY_MIN_DISTINCT = 4
WEAK_KEY_NOTE = "Weak key: very few different letters. Allowed, but easy to break."
WEAK_FG = "#b45309"                 # orange-brown text for the weak-key note

# The guided tour ("START HERE"): a purple banner, so it is not mistaken for a cipher stage.
TOUR_STEPS = 5
TOUR_BG, TOUR_FG, TOUR_EDGE = "#ede9fe", "#4c1d95", "#8b5cf6"


# ==========================================================================
# ===== SELF-TEST (checks the cipher against known answers) =====
# ==========================================================================
# The "lecture vectors" are the same known answers that tests/test_cipher.py
# uses. A cipher that passes them, plus 300 random lock/unlock round trips, is
# very likely correct.

def run_self_test_checks():
    """Run the checks. Returns (checks, elapsed_ms).

    `checks` is a list of (name, passed, detail) tuples. No window is involved,
    so this can be tested on its own.
    """
    start = time.perf_counter()
    checks = []

    def check(name, test):
        # Run one check. A crash counts as a failure, with the error as detail.
        try:
            passed, detail = test()
        except Exception as error:                      # a broken cipher must not stop the list
            passed, detail = False, f"error: {error}"
        checks.append((name, bool(passed), detail))

    def equal(got, expected):
        return got == expected, "" if got == expected else f"got {got!r}, expected {expected!r}"

    check("Shift: WEWILLMEETATMIDNIGHT, k=11",
          lambda: equal(cipher.shift_encrypt("WEWILLMEETATMIDNIGHT", 11), "HPHTWWXPPELEXTOYTRSE"))
    check("Shift unlock: COTEWXQIVBUQI, k=16",
          lambda: equal(cipher.shift_decrypt("COTEWXQIVBUQI", 16), "MYDOGHASFLEAS"))
    check("Stage 1 Vigenere lock: key CIPHER",
          lambda: equal(cipher.vigenere_encrypt("THISCRYPTOSYSTEMISNOTSECURE", "CIPHER"),
                        "VPXZGIAXIVWPUBTTMJPWIZITWZT"))
    check("Stage 1 Vigenere unlock: key TRICKEM",
          lambda: equal(cipher.vigenere_decrypt("FPLQQLMLWTGKW", "TRICKEM"), "MYDOGHASFLEAS"))
    check("Stage 1 Vigenere unlock: key WONDERLAND",
          lambda: equal(cipher.vigenere_decrypt("WZVFINLSOHCWAQMERTBJAHIHVPEIEHZCS", "WONDERLAND"),
                        "ALICEWASBEGINNINGTOGETVERYTIREDOF"))
    check("Stage 2 Rail Fence lock: 3 rails",
          lambda: equal(cipher.rail_encrypt("WEAREDISCOVEREDFLEEATONCE", 3), "WECRLTEERDSOEEFEAOCAIVDEN"))
    check("Stage 2 Rail Fence unlock: 3 rails",
          lambda: equal(cipher.rail_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3), "WEAREDISCOVEREDFLEEATONCE"))
    check("Both stages, lock: key CRYPTOGRAPHY, 5 rails",
          lambda: equal(cipher.custom_encrypt("DEFENDTHEEASTWALLOFTHECASTLE", "CRYPTOGRAPHY", 5),
                        ("FVDTGRZYETHQVNYAECLKHTJYUKJT", "FEEUVYTACYKDZHYLJJTRQNKTTGVH")))
    check("Both stages, unlock",
          lambda: equal(cipher.custom_decrypt("FEEUVYTACYKDZHYLJJTRQNKTTGVH", "CRYPTOGRAPHY", 5),
                        "DEFENDTHEEASTWALLOFTHECASTLE"))
    check("Cleaning: 'Hello, World 123'",
          lambda: equal(cipher.sanitize("Hello, World 123"), ("HELLOWORLD", 6)))

    def rejects_bad_keys():
        bad = [("ABCDEFGHI", 3), ("ABCDEFGHI1", 3), ("ABCDEFGHIJ", 1), ("ABCDEFGHIJ", 11)]
        failures = []
        for key, rails in bad:
            try:
                cipher.validate_key(key, rails)
                failures.append((key, rails))           # it should have raised ValueError
            except ValueError:
                pass
        return not failures, f"accepted: {failures}" if failures else ""
    check("Bad keys are refused (short, digits, rails 1 and 11)", rejects_bad_keys)

    def random_round_trips():
        rng = random.Random(486)                        # fixed seed: same 300 every time
        bad = 0
        for _ in range(300):
            text = "".join(rng.choices(string.ascii_uppercase, k=rng.randint(0, 400)))
            key = "".join(rng.choices(string.ascii_uppercase, k=rng.randint(10, 25)))
            rails = rng.randint(2, 10)
            order = cipher.rail_order(len(text), rails)
            _, final = cipher.custom_encrypt(text, key, rails)
            if sorted(order) != list(range(len(text))) or cipher.custom_decrypt(final, key, rails) != text:
                bad += 1
        return bad == 0, f"{300 - bad} of 300 round trips worked"
    check("300 random lock/unlock round trips (seed 486)", random_round_trips)

    return checks, (time.perf_counter() - start) * 1000


# ==========================================================================
# ===== HELPERS (pure functions: no window needed) =====
# ==========================================================================

def letter_accuracy(truth, guess):
    """Share of positions where `guess` has the right letter (0.0 to 1.0).

    Worked example: truth "ABCD", guess "ABXD" -> 3 of 4 right = 0.75.
    A missing guess or one of the wrong length counts as 0.
    """
    if not guess or len(guess) != len(truth):
        return 0.0
    return sum(a == b for a, b in zip(truth, guess)) / len(truth)


def is_protected(path):
    """True if `path` is one of the result files this window must never overwrite."""
    wanted = os.path.normcase(os.path.abspath(path))
    return any(wanted == os.path.normcase(os.path.abspath(p)) for p in PROTECTED_FILES)


def nice_ceiling(value):
    """Round a number UP to 1, 2 or 5 times a power of ten (for chart axes).

    Worked examples: 33.6 -> 50,   0.331 -> 0.5,   1.0 -> 1,   120 -> 200.
    """
    if value <= 0:
        return 1.0
    base = 10 ** math.floor(math.log10(value))
    for multiple in (1, 2, 5, 10):
        if value <= multiple * base * (1 + 1e-12):
            return multiple * base
    return 10 * base


def _short_number(v):
    """Compact axis label: 100000 -> '100k', 2500 -> '2.5k', 0.5 -> '0.5'."""
    return f"{v / 1000:g}k" if v >= 1000 else f"{v:.3g}"


def format_attack_row(row, vary):
    """One experiment row as the strings shown in a table; same decimals as
    attack.format_table prints. `vary` is 'text_length' or 'crib'."""
    return [str(row[vary]), f"{row['exact_pct']:.1f}", f"{row['plaintext_acc_pct']:.1f}",
            f"{row['key_acc_pct']:.1f}", f"{row['rails_pct']:.1f}",
            f"{row['median_ms']:.2f}", f"{row['median_guesses']:.0f}"]


def format_speed_row(row):
    """One Table A row as strings; same decimals as benchmark prints."""
    return [str(row["n"]), f"{row['shift_enc_ms']:.4f}", f"{row['custom_enc_ms']:.4f}",
            f"{row['custom_dec_ms']:.4f}", f"{row['ratio']:.2f}", f"{row['us_per_char']:.4f}"]


def weak_key_note(key):
    """The orange warning for a key with very few different letters, or "" if the key is fine.

    Worked examples:  "AAAAAAAAAA" -> warning (1 different letter)
                      "ABABABABAB" -> warning (2 different letters)
                      "CRYPTOGRAPHY" -> "" (8 different letters)
                      "" -> ""  (nothing typed yet, so nothing to warn about)
    It is only a warning: validate_key still accepts the key and Lock still works.
    """
    different = {ch.upper() for ch in key if ch.isascii() and ch.isalpha()}
    if different and len(different) < WEAK_KEY_MIN_DISTINCT:
        return WEAK_KEY_NOTE
    return ""


def experiments_banner(results):
    """Tour step 4 text. The number of trials is READ from the loaded results
    (never typed in). `results` is what read_attack_csv returns, or None."""
    if not results:
        return None
    trials = results["table1"][0]["trials"]
    return (f"Experiments: these tables are success rates over {trials} random trials for "
            "each message length (the third table varies the crib size instead).")


def efficiency_banner(data):
    """Tour step 5 text. Every number is READ from the loaded speed results
    (`data` is what read_benchmark_csv returns, or None).

    "A straight line" is only claimed if the saved verdict for locking says
    "linear"; otherwise the saved verdict is quoted as it is.
    """
    if not data:
        return None
    fits = {fit["name"]: fit for fit in data["fits"]}
    fit = fits.get("Custom enc") or data["fits"][0]
    ratio = statistics.median(row["ratio"] for row in data["table_a"])
    sizes = len(data["table_a"])
    if fit["verdict"].startswith("linear"):
        growth = (f"Efficiency: time grows in a straight line with the message length (O(N)); "
                  f"the log-log slope of locking is {fit['loglog_slope']:.2f}, where 1.00 is perfectly linear.")
    else:
        growth = f"Efficiency: {fit['name']}: {fit['verdict']}."
    return f"{growth} The two-stage cipher costs about {ratio:.1f} times the Shift cipher (median of {sizes} sizes)."


def read_attack_csv(path=ATTACK_CSV):
    """Read attack_results.csv into {"table1": rows, "table2": rows, "table3": rows}.

    Each row has the same keys (and number types) that attack.run_experiments
    returns. Raises FileNotFoundError if the file is missing and ValueError if
    it is not in the expected format.
    """
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    tables = {"table1": [], "table2": [], "table3": []}
    try:
        for r in rows:
            tables[r["table"]].append({
                "text_length": int(r["text_length"]),
                "crib": int(r["crib"]) if r["crib"] != "" else "",
                "trials": int(r["trials"]),
                "exact_pct": float(r["exact_pct"]),
                "plaintext_acc_pct": float(r["plaintext_acc_pct"]),
                "key_acc_pct": float(r["key_acc_pct"]),
                "rails_pct": float(r["rails_pct"]),
                "median_ms": float(r["median_ms"]),
                "median_guesses": float(r["median_guesses"]),
            })
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError(f"{os.path.basename(path)} is not in the expected format ({error!r}).")
    if not all(tables.values()):
        raise ValueError(f"{os.path.basename(path)} is missing one of the three tables.")
    return tables


def read_benchmark_csv(path=BENCH_CSV):
    """Read benchmark_results.csv into {"table_a": rows, "fits": rows, "memory": rows}.

    The file is in "long format" (one row per measurement); this turns it back
    into the table shapes benchmark.run_benchmarks returns.
    """
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    try:
        by_size = {}
        fits, memory = [], []
        for r in rows:
            if r["table"] == "A":
                entry = by_size.setdefault(int(r["n"]), {"n": int(r["n"])})
                entry[r["case"] + "_ms"] = float(r["median_ms"])
                if r["case"] == "custom_enc":
                    entry["ratio"] = float(r["ratio"])
                    entry["us_per_char"] = float(r["us_per_char"])
            elif r["table"] == "fit":
                fits.append({"name": r["case"], "a_ms_per_char": float(r["a_ms_per_char"]),
                             "b_ms": float(r["b_ms"]), "r_squared": float(r["r_squared"]),
                             "loglog_slope": float(r["loglog_slope"]), "verdict": r["verdict"]})
            elif r["table"] == "memory":
                memory.append({"name": r["case"], "n": int(r["n"]), "peak_kb": float(r["peak_kb"]),
                               "bytes_per_char": float(r["bytes_per_char"])})
        table_a = [by_size[n] for n in sorted(by_size)]
        needed = ("shift_enc_ms", "custom_enc_ms", "custom_dec_ms", "ratio", "us_per_char")
        if not table_a or not fits or not memory or any(k not in e for e in table_a for k in needed):
            raise ValueError("a table is missing")
    except (KeyError, ValueError, TypeError) as error:
        raise ValueError(f"{os.path.basename(path)} is not in the expected format ({error!r}).")
    return {"table_a": table_a, "fits": fits, "memory": memory}


def draw_line_chart(canvas, title, x_label, y_label, series, default_size=(430, 230)):
    """Draw a simple line chart on a tk Canvas.

    `series` is a list of dicts: {"name": ..., "color": ..., "points": [(x, y), ...]}.
    Both axes start at 0 and end at a "nice" number (see nice_ceiling), so a
    straight line from the corner means "time grows in proportion to N".
    """
    canvas.delete("all")
    width = canvas.winfo_width() if canvas.winfo_width() > 50 else default_size[0]
    height = canvas.winfo_height() if canvas.winfo_height() > 50 else default_size[1]
    left, right, top, bottom = 66, width - 16, 30, height - 44     # the plot area, in pixels

    canvas.create_text(width / 2, 12, text=title, font=FONT_BOLD, fill=TEXT)
    points = [p for s in series for p in s["points"]]
    if not points:
        canvas.create_text(width / 2, height / 2, text="No data yet", font=FONT_LABEL, fill=MUTED)
        return
    x_max = nice_ceiling(max(x for x, _ in points))
    y_max = nice_ceiling(max(y for _, y in points))

    def to_px(x, y):
        # Turn a data point into a pixel: x grows to the right, y grows UPWARDS
        # (but pixel rows grow downwards, hence the "bottom - ...").
        return left + (x / x_max) * (right - left), bottom - (y / y_max) * (bottom - top)

    # Grid lines and tick labels.
    for i in range(5):
        y_value = y_max * i / 4
        _, py = to_px(0, y_value)
        canvas.create_line(left, py, right, py, fill="#e5e7eb")
        canvas.create_text(left - 6, py, text=_short_number(y_value), anchor="e", font=FONT_SMALL, fill=MUTED)
        x_value = x_max * i / 4
        px, _ = to_px(x_value, 0)
        canvas.create_text(px, bottom + 12, text=_short_number(x_value), font=FONT_SMALL, fill=MUTED)
    canvas.create_line(left, top, left, bottom, fill=TEXT)
    canvas.create_line(left, bottom, right, bottom, fill=TEXT)
    canvas.create_text((left + right) / 2, height - 10, text=x_label, font=FONT_SMALL, fill=TEXT)
    canvas.create_text(12, (top + bottom) / 2, text=y_label, angle=90, font=FONT_SMALL, fill=TEXT)

    # The lines, with a dot on every measured point, and a little legend.
    for index, s in enumerate(series):
        pixels = [to_px(x, y) for x, y in sorted(s["points"])]
        if len(pixels) > 1:
            canvas.create_line(*[c for p in pixels for c in p], fill=s["color"], width=2)
        for px, py in pixels:
            canvas.create_oval(px - 3, py - 3, px + 3, py + 3, fill=s["color"], outline=s["color"])
        canvas.create_rectangle(left + 10, top + 6 + index * 16, left + 22, top + 14 + index * 16,
                                fill=s["color"], outline=s["color"])
        canvas.create_text(left + 28, top + 10 + index * 16, text=s["name"], anchor="w",
                           font=FONT_SMALL, fill=TEXT)


# ----- the "Show Working" text (pure, so it can be tested without a window) -----

def _vigenere_block(working):
    """The Stage 1 working as (style, text) pairs: formula and worked example,
    the table (one line per letter), and a note if only some letters are shown.

    "mono" text is fixed-width (tables line up); "note" text wraps to the window.
    """
    rows = working["rows"]
    sign = "-" if working["decrypt"] else "+"
    intro = working["formula"]
    if rows:
        intro += f"\n\nWorked example (row 1):  {explain.describe_row(rows[0])}"
    lines = [f"{'#':>3}  {'letter':^6} {'number':>6}  {'key':^5} {'key no.':>7}  "
             f"{'letter ' + sign + ' key':>12} {'mod 26':>7}  {'result':^6}"]
    for r in rows:
        lines.append(f"{r['pos']:>3}  {r['in_letter']:^6} {r['in_num']:>6}  {r['key_letter']:^5} "
                     f"{r['key_num']:>7}  {r['raw']:>12} {r['result_num']:>7}  {r['out_letter']:^6}")
    segments = [("mono", intro), ("mono", "\n".join(lines))]
    if working["total"] > working["shown"]:
        segments.append(("note", f"(Only the first {working['shown']} of {working['total']} letters are shown; "
                                 "the rest follow the same rule, and the key keeps repeating.)"))
    return segments


def _rail_block(working, what_it_is, source):
    """The Stage 2 working as (style, text) pairs. `what_it_is` names the text
    that was used and `source` is that text (only its first letters are drawn)."""
    rails = working["rails"]
    if working["decrypt"]:
        intro = (f"The first {working['shown']} letters of the {what_it_is} are cut into one piece per "
                 f"rail ({rails} rails), each piece is put back on its rail, and the columns are read "
                 "left to right (zigzag order).  '.' means an empty cell.")
    else:
        intro = (f"The first {working['shown']} letters of the {what_it_is} are written in a zigzag "
                 f"across {rails} rails.  '.' means an empty cell.")
    lines = [f"{what_it_is[0].upper() + what_it_is[1:]}:  {source[:working['shown']]}", ""]
    for r in range(rails):
        cells = " ".join(working["grid"][r])
        verb = "piece" if working["decrypt"] else "reads"
        lines.append(f"rail {r + 1:>2}:  {cells}      {verb}  {working['rail_strings'][r]}")
    lines.append("")
    if working["decrypt"]:
        lines.append(f"Reading the columns left to right gives:  {working['joined']}")
    else:
        lines.append(f"Reading rail 1, then rail 2, ... joins to:  {working['joined']}")
    segments = [("body", intro), ("mono", "\n".join(lines))]
    if working["truncated"]:
        segments.append(("note", f"(Only the first {working['shown']} of {working['total']} letters are drawn, "
                                 "so this is the result for just those letters. The whole message is done "
                                 "the same way.)"))
    return segments


def build_working_document(op):
    """Everything the Show Working window displays, as (style, text) pairs.

    `op` describes the last lock/unlock: mode ('lock' or 'unlock'), clean (the
    cleaned input), middle (the text between the stages), final, key, rails.
    Returns (segments, matches, error). `matches` is True when every row and
    grid agreed with cipher.py; otherwise `error` says what disagreed.
    """
    key, rails = op["key"], op["rails"]
    segments = []
    try:
        # First check the whole chain: the text between the stages and the final
        # result that are on screen must be exactly what cipher.py produces.
        # (Each table/grid below is then checked row by row inside explain.py.)
        if op["mode"] == "lock":
            real = cipher.custom_encrypt(op["clean"], key, rails)
        else:
            real = (cipher.rail_decrypt(op["clean"], rails), cipher.custom_decrypt(op["clean"], key, rails))
        if real != (op["middle"], op["final"]):
            raise explain.ExplainMismatchError(
                "the text between the stages or the final result is not what cipher.py produces.")

        if op["mode"] == "lock":
            # Locking: Stage 1 first, then Stage 2.
            stage1 = explain.vigenere_steps(op["clean"], key, decrypt=False)
            stage2 = explain.rail_grid(op["middle"], rails, decrypt=False)
            segments += [("stage1", "STAGE 1 - VIGENERE (substitution: changes WHAT each letter is)"),
                         *_vigenere_block(stage1),
                         ("stage2", "STAGE 2 - RAIL FENCE (transposition: changes WHERE each letter is)"),
                         *_rail_block(stage2, "Stage 1 result", op["middle"])]
        else:
            # Unlocking goes backwards: undo Stage 2 first, then undo Stage 1.
            stage2 = explain.rail_grid(op["clean"], rails, decrypt=True)
            stage1 = explain.vigenere_steps(op["middle"], key, decrypt=True)
            segments += [("stage2", "UNDO STAGE 2 - RAIL FENCE (put the letters back in their places)"),
                         *_rail_block(stage2, "ciphertext", op["clean"]),
                         ("stage1", "THEN UNDO STAGE 1 - VIGENERE (subtract the key letter)"),
                         *_vigenere_block(stage1)]
    except explain.ExplainMismatchError as error:
        segments.append(("bad", f"All rows match cipher.py: NO  ({error})"))
        return segments, False, str(error)
    segments.append(("ok", "All rows match cipher.py: yes"))
    return segments, True, ""


# ==========================================================================
# ===== THE APP (class App: one window, four tabs) =====
# ==========================================================================

class App:
    """The whole window. Give it a Tk root: App(tk.Tk())."""

    # ----------------------------------------------------------------------
    # ----- window frame: style, top bar, notebook, status bar -----
    # ----------------------------------------------------------------------

    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.minsize(950, 680)                      # never smaller than this; still resizable
        root.geometry("1040x740")
        root.configure(bg=BG)

        # State shared by the handlers.
        self._last_op = None                        # the last lock/unlock (for Show Working)
        self._truth = None                          # hidden answer of the current test message
        self._corpus = None                         # the test text, loaded the first time it is needed
        self._attack_results = None                 # tables currently shown on the experiments page
        self._speed_results = None                  # results currently shown on the speed page
        self._chart_series = None
        # Background jobs: a worker thread does the slow work and puts messages
        # on a queue; the main thread reads the queue (never touch tk from a worker).
        self._busy = {"attack": False, "exp": False, "speed": False}
        self._cancel = {"exp": threading.Event(), "speed": threading.Event()}
        self._queue = queue.Queue()
        # Each tab remembers its own last status message (tab number -> (message, kind)),
        # so the bar shows the right words when you come back to a tab.
        self._status_memory = {tab: (message, "info") for tab, message in READY_MESSAGES.items()}
        # The guided tour: the banner is built the first time START HERE is pressed.
        self._tour_step = None                      # None = no tour running, otherwise 1..TOUR_STEPS
        self._tour_frame = None
        self._tour_grew = 0                         # how many pixels taller the window was made for the banner

        self._build_style()
        self._build_top_bar()
        self._build_status_bar()
        self._build_notebook()
        self._poll_id = root.after(100, self._poll_queue)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._show_status(*self._status_memory[TAB_LOCK])

    def _build_style(self):
        """Use the calm 'clam' theme and our colours/fonts."""
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=TEXT, font=FONT_LABEL)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT, font=FONT_LABEL)
        style.configure("TLabelframe", background=BG)
        style.configure("TLabelframe.Label", background=BG, foreground=TEXT, font=FONT_BOLD)
        style.configure("TButton", font=FONT_LABEL, padding=(10, 4))
        style.configure("TRadiobutton", background=BG, font=FONT_LABEL)
        style.configure("TNotebook", background=BG)
        style.configure("TNotebook.Tab", font=FONT_BOLD, padding=(14, 6))
        style.configure("Treeview", font=FONT_SMALL, rowheight=20, background=PANEL, fieldbackground=PANEL)
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Go.TButton", font=FONT_BOLD, padding=(14, 5))
        # The START HERE button stands out: white bold text on the tour's purple.
        style.configure("Start.TButton", font=FONT_BOLD, padding=(16, 5), background=TOUR_EDGE, foreground="#ffffff")
        style.map("Start.TButton", background=[("active", "#7c3aed"), ("pressed", "#6d28d9")],
                  foreground=[("active", "#ffffff")])
        style.configure("Tour.TButton", font=FONT_LABEL, padding=(10, 1))        # the small buttons in the tour banner

    def _build_top_bar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(side="top", fill="x", padx=12, pady=(8, 2))
        tk.Label(bar, text="Vigenere + Rail Fence", font=FONT_TITLE, bg=BG, fg=TEXT).pack(side="left")
        tk.Label(bar, text="  two-stage classical cipher", font=FONT_LABEL, bg=BG, fg=MUTED).pack(side="left")
        self.selftest_label = tk.Label(bar, text="Self-test: not run yet", font=FONT_BOLD, bg=BG, fg=MUTED)
        self.selftest_label.pack(side="right")
        ttk.Button(bar, text="Run Self-Test", command=self.run_self_test).pack(side="right", padx=10)
        # Packed after the Self-Test button on the right side, so it sits to its LEFT.
        self.start_button = ttk.Button(bar, text="START HERE", style="Start.TButton", command=self.start_tour)
        self.start_button.pack(side="right")

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg="#e5e9ef")
        bar.pack(side="bottom", fill="x")
        self.status_var = tk.StringVar()
        self.status_label = tk.Label(bar, textvariable=self.status_var, anchor="w", font=FONT_LABEL,
                                     bg="#e5e9ef", fg=TEXT, padx=12, pady=4)
        self.status_label.pack(fill="x")

    def _build_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(side="top", fill="both", expand=True, padx=10, pady=(4, 6))
        builders = [self._build_lock_tab, self._build_break_tab, self._build_speed_tab, self._build_help_tab]
        self.tab_titles = self._choose_tab_titles()
        for title, builder in zip(self.tab_titles, builders):
            frame = ttk.Frame(self.notebook, padding=8)
            self.notebook.add(frame, text=title)
            builder(frame)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _choose_tab_titles(self):
        """The long tab names if all four fit the smallest window, otherwise the short ones.

        Each tab is as wide as its text plus its padding (14 pixels on each side
        and a few for the border). The room is the smallest window width (950)
        minus the margins. The text width is measured with the real font, so this
        also works on screens with a larger text scale.
        """
        font = tkfont.Font(root=self.root, font=FONT_BOLD)
        per_tab_extra = 2 * 14 + 8
        room = 950 - 2 * 10 - 24
        for titles in (TAB_TITLES_LONG, TAB_TITLES_SHORT):
            if sum(font.measure(title) + per_tab_extra for title in titles) <= room:
                return titles
        return TAB_TITLES_SHORT

    def _current_tab(self):
        return self.notebook.index(self.notebook.select())

    def _on_tab_changed(self, _event=None):
        tab = self._current_tab()
        # Re-read the results files every time the Design tab is opened.
        if tab == TAB_DESIGN:
            self.refresh_help()
        # The bar shows what this tab last said (or its own "Ready" message).
        self._show_status(*self._status_memory[tab])

    def _show_status(self, message, kind):
        colour = {"info": TEXT, "ok": GREEN, "error": RED}[kind]
        self.status_var.set(message)
        self.status_label.configure(fg=colour)

    def set_status(self, message, kind="info", tab=None):
        """Show a plain-English message in the bottom bar. kind: info, ok or error.

        `tab` is the number of the tab the message belongs to (TAB_LOCK, ...).
        The message is shown now AND remembered for that tab, so it comes back
        when you return to that tab. tab=None shows it without remembering it.
        """
        self._show_status(message, kind)
        if tab is not None:
            self._status_memory[tab] = (message, kind)

    # ---- small widget helpers (used by every tab) ----

    @staticmethod
    def _set_text(widget, value):
        """Replace the contents of a read-only Text box."""
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    @staticmethod
    def _get_text(widget):
        return widget.get("1.0", "end-1c")

    def _make_scrollable(self, parent):
        """A vertically scrollable area. Returns (canvas, scrollbar, inner_frame).

        Put widgets in `inner_frame`; place `canvas` and `scrollbar` in the
        parent yourself. If the content is taller than the window, the
        scrollbar (or the mouse wheel over the area) moves it.
        """
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        # Keep the scrollable height equal to the content height, and make the
        # content as wide as the canvas.
        inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(window, width=e.width))

        def on_wheel(event):
            # One mouse-wheel notch is 120 on Windows; scroll 2 lines per notch.
            canvas.yview_scroll(int(-event.delta / 120) * 2, "units")

        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", on_wheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))
        return canvas, scrollbar, inner

    def _make_box(self, parent, bg, height, font=FONT_MONO, editable=False):
        """A Text box with a scrollbar. Returns (frame, text_widget)."""
        frame = tk.Frame(parent, bg=bg, highlightbackground="#c7ced8", highlightthickness=1)
        text = tk.Text(frame, height=height, width=10, wrap="char" if not editable else "word", font=font,
                       bg=bg, fg=TEXT, relief="flat", borderwidth=4, insertbackground=TEXT)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        if not editable:
            text.configure(state="disabled")
        return frame, text

    # ----------------------------------------------------------------------
    # ----- SELF-TEST (top bar button) -----
    # ----------------------------------------------------------------------

    def run_self_test(self, show_window=True):
        """Run the self-test, update the top bar, and (optionally) show the list."""
        checks, elapsed_ms = run_self_test_checks()
        failed = [c for c in checks if not c[1]]
        if failed:
            self.selftest_label.configure(text=f"Self-test: FAIL ({len(failed)} of {len(checks)} checks)", fg=RED)
            self.set_status(f"Self-test FAILED: {failed[0][0]}", "error")
        else:
            self.selftest_label.configure(
                text=f"Self-test: PASS ({len(checks)} checks, {elapsed_ms:.1f} ms)", fg=GREEN)
            self.set_status(f"Self-test passed: all {len(checks)} checks in {elapsed_ms:.1f} ms.", "ok")
        if show_window:
            self._show_self_test_window(checks, elapsed_ms)
        return checks, elapsed_ms

    def _show_self_test_window(self, checks, elapsed_ms):
        win = tk.Toplevel(self.root)
        win.title("Self-test")
        win.configure(bg=BG)
        win.geometry("700x430")
        tree = ttk.Treeview(win, columns=("result", "check", "detail"), show="headings", height=14)
        for name, text, width in (("result", "Result", 70), ("check", "Check", 400), ("detail", "Detail", 200)):
            tree.heading(name, text=text)
            tree.column(name, width=width, anchor="w")
        tree.tag_configure("pass", foreground=GREEN)
        tree.tag_configure("fail", foreground=RED)
        for name, passed, detail in checks:
            tree.insert("", "end", values=("PASS" if passed else "FAIL", name, detail),
                        tags=("pass" if passed else "fail",))
        tree.pack(fill="both", expand=True, padx=10, pady=10)
        ok = all(c[1] for c in checks)
        tk.Label(win, bg=BG, font=FONT_BOLD, fg=GREEN if ok else RED,
                 text=f"{'All checks passed' if ok else 'Some checks FAILED'} - took {elapsed_ms:.1f} ms"
                 ).pack(pady=(0, 10))

    # ----------------------------------------------------------------------
    # ----- TAB 1: LOCK / UNLOCK -----
    # ----------------------------------------------------------------------

    def _build_lock_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        # --- Row 0: the message ---
        msg = ttk.LabelFrame(tab, text="1. Message (only A-Z is kept; spaces, digits and punctuation are removed for good)",
                             padding=6)
        msg.grid(row=0, column=0, sticky="ew")
        msg.columnconfigure(0, weight=1)
        frame, self.message_text = self._make_box(msg, PANEL, 4, editable=True)
        frame.grid(row=0, column=0, rowspan=2, sticky="ew")
        ttk.Button(msg, text="Load sample", command=self.load_sample).grid(row=0, column=1, padx=(8, 0), sticky="ew")
        ttk.Button(msg, text="Clear", command=self.clear_all).grid(row=1, column=1, padx=(8, 0), pady=(4, 0), sticky="ew")

        # --- Row 1: key and rails (two separate inputs) ---
        keyf = ttk.LabelFrame(tab, text="2. Key and rails (two separate inputs)", padding=6)
        keyf.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        tk.Label(keyf, text="Stage 1 - Vigenere key (letters only):", font=FONT_BOLD, bg=BG,
                 fg=STAGE1_FG).grid(row=0, column=0, sticky="w")
        self.key_var = tk.StringVar()
        # validate="key": the entry itself refuses anything that is not a letter.
        only_letters = (self.root.register(self._key_edit_allowed), "%P")
        self.key_entry = ttk.Entry(keyf, textvariable=self.key_var, width=26, font=FONT_MONO,
                                   validate="key", validatecommand=only_letters)
        self.key_entry.grid(row=0, column=1, padx=8)
        self.key_entry.bind("<Return>", self._on_key_enter)               # Enter = Lock
        self.counter_label = tk.Label(keyf, text="", font=FONT_BOLD, bg=BG)
        self.counter_label.grid(row=0, column=2, sticky="w")
        tk.Label(keyf, text="Stage 2 - Rail Fence rails:", font=FONT_BOLD, bg=BG,
                 fg=STAGE2_FG).grid(row=0, column=3, sticky="e", padx=(24, 6))
        self.rails_var = tk.StringVar(value="4")        # a sensible starting value
        self.rails_spin = ttk.Spinbox(keyf, from_=cipher.MIN_RAILS, to=cipher.MAX_RAILS, width=4,
                                      textvariable=self.rails_var, font=FONT_MONO, wrap=False)
        self.rails_spin.grid(row=0, column=4)
        # Row 1: the weak-key note. It is orange, never blocks anything, and is
        # empty (but keeps its line, so the layout does not jump) for a good key.
        self.weak_var = tk.StringVar()
        self.weak_label = tk.Label(keyf, textvariable=self.weak_var, font=FONT_SMALL, bg=BG, fg=WEAK_FG, anchor="w")
        self.weak_label.grid(row=1, column=0, columnspan=5, sticky="w")
        self.key_var.trace_add("write", self._update_key_counter)
        self._update_key_counter()

        # --- Row 2: buttons ---
        buttons = ttk.Frame(tab)
        buttons.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(buttons, text="Lock (encrypt)", style="Go.TButton", command=self.do_encrypt).pack(side="left")
        ttk.Button(buttons, text="Unlock (decrypt)", style="Go.TButton", command=self.do_decrypt).pack(side="left", padx=8)
        ttk.Button(buttons, text="Move output to input", command=self.move_output_to_input).pack(side="left", padx=(16, 0))
        ttk.Button(buttons, text="Copy output", command=self.copy_output).pack(side="left", padx=8)
        ttk.Button(buttons, text="Show Working", command=self.show_working).pack(side="right")

        # --- Row 3: red inline message (validation errors appear here, never in pop-ups) ---
        self.inline_var = tk.StringVar()
        self.inline_label = tk.Label(tab, textvariable=self.inline_var, anchor="w", font=FONT_BOLD,
                                     bg=BG, fg=RED)
        self.inline_label.grid(row=3, column=0, sticky="ew", pady=(4, 0))

        # --- Row 4: the three output boxes, side by side ---
        outs = ttk.Frame(tab)
        outs.grid(row=4, column=0, sticky="nsew", pady=(2, 0))
        outs.rowconfigure(2, weight=1)
        self._out = []                                  # per column: dict(caption, box frame, text)
        for col in range(3):
            outs.columnconfigure(col, weight=1, uniform="outputs")
            # wraplength: a long caption continues on a second line instead of being cut off.
            caption = tk.Label(outs, text="", anchor="w", justify="left", wraplength=270, font=FONT_BOLD, bg=BG)
            caption.grid(row=0, column=col, sticky="ew", padx=3)
            note = tk.Label(outs, text="", anchor="w", font=FONT_SMALL, bg=BG, fg=MUTED)
            note.grid(row=1, column=col, sticky="ew", padx=3)
            frame, text = self._make_box(outs, NEUTRAL_BG, 6)
            frame.grid(row=2, column=col, sticky="nsew", padx=3)
            self._out.append({"caption": caption, "note": note, "text": text})
        self._set_output_style("lock")

        # --- Row 5: results of the check, and the time taken ---
        info = ttk.Frame(tab)
        info.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        self.check_label = tk.Label(info, text="", font=FONT_BOLD, bg=BG)
        self.check_label.pack(side="left")
        self.time_label = tk.Label(info, text="", font=FONT_LABEL, bg=BG, fg=MUTED)
        self.time_label.pack(side="right")

    # ---- key field behaviour ----

    def _on_key_enter(self, _event=None):
        """Pressing Enter in the key field does the same as the Lock button."""
        self.do_encrypt()

    def _key_edit_allowed(self, proposed):
        """Called by the entry before every edit: only letters may be typed or pasted."""
        allowed = proposed == "" or (proposed.isascii() and proposed.isalpha())
        if not allowed:
            self.inline_var.set("Only the letters A-Z can be used in the key (no digits, spaces or symbols).")
        return allowed

    def _update_key_counter(self, *_args):
        """The live counter next to the key, e.g. '7 / 10 letters' (red until 10, then green)."""
        key = self.key_var.get()
        letters = sum(1 for ch in key if ch.isascii() and ch.isalpha())
        good = letters >= cipher.MIN_KEY_LENGTH and letters == len(key)
        self.counter_label.configure(text=f"{letters} / {cipher.MIN_KEY_LENGTH} letters",
                                     fg=GREEN if good else RED)
        self.weak_var.set(weak_key_note(key))               # "" for a good key

    # ---- output boxes ----

    def _set_output_style(self, mode):
        """Captions and colours of the three boxes for 'lock' or 'unlock'.

        The colour shows which stage did the step: BLUE = Stage 1 (Vigenere),
        ORANGE = Stage 2 (Rail Fence).
        """
        if mode == "lock":
            spec = [("Cleaned text", NEUTRAL_BG, TEXT),
                    ("After Stage 1 - Vigenere", STAGE1_BG, STAGE1_FG),
                    ("Final ciphertext - after Stage 2 Rail Fence", STAGE2_BG, STAGE2_FG)]
        else:
            spec = [("Cleaned ciphertext", NEUTRAL_BG, TEXT),
                    ("After undoing Stage 2 (Rail Fence)", STAGE2_BG, STAGE2_FG),
                    ("Final plaintext - after undoing Stage 1 (Vigenere)", STAGE1_BG, STAGE1_FG)]
        for box, (caption, bg, fg) in zip(self._out, spec):
            box["caption"].configure(text=caption, fg=fg)
            box["text"].configure(bg=bg)
            box["text"].master.configure(bg=bg)
            box["note"].configure(text="")

    def _show_outputs(self, mode, first, middle, last, removed):
        self._set_output_style(mode)
        for box, value in zip(self._out, (first, middle, last)):
            self._set_text(box["text"], value)
        self._out[0]["note"].configure(
            text=f"{removed} character{'s' if removed != 1 else ''} removed" if removed else "nothing removed")

    def _clear_outputs(self):
        for box in self._out:
            self._set_text(box["text"], "")
            box["note"].configure(text="")
        self.check_label.configure(text="")
        self.time_label.configure(text="")

    def get_outputs(self):
        """The three output boxes as a dict (used by the tests)."""
        return {"cleaned": self._get_text(self._out[0]["text"]),
                "middle": self._get_text(self._out[1]["text"]),
                "final": self._get_text(self._out[2]["text"])}

    def inline_text(self):
        return self.inline_var.get()

    # ---- message box ----

    def set_message(self, value):
        self.message_text.delete("1.0", "end")
        self.message_text.insert("1.0", value)

    def get_message(self):
        return self._get_text(self.message_text)

    def load_sample(self):
        """Fill the message box with a sample (and the sample key, if the key box is empty)."""
        self.set_message(SAMPLE_MESSAGE)
        if not self.key_var.get():
            self.key_var.set(SAMPLE_KEY)
            self.rails_var.set(str(SAMPLE_RAILS))
        self.inline_var.set("")
        self.set_status("Loaded a sample message. Press Lock to encrypt it.", "info", TAB_LOCK)

    def clear_all(self):
        """Empty the message and every output."""
        self.set_message("")
        self._clear_outputs()
        self.inline_var.set("")
        self._last_op = None
        self.set_status("Cleared.", "info", TAB_LOCK)

    # ---- reading and checking the inputs ----

    def _read_inputs(self):
        """Return (clean_text, removed, key, rails), or None after showing a red message."""
        self.inline_var.set("")
        raw = self.get_message()
        if raw.strip() == "":
            return self._reject("Type or load a message first.")
        clean, removed = cipher.sanitize(raw)
        if clean == "":
            return self._reject("The message has no letters A-Z, so there is nothing to lock.")
        key = self.key_var.get()
        try:
            rails = int(self.rails_var.get().strip())
        except ValueError:
            return self._reject(f"The number of rails must be a whole number from "
                                f"{cipher.MIN_RAILS} to {cipher.MAX_RAILS}.")
        try:
            cipher.validate_key(key, rails)             # gives the plain-English reason
        except ValueError as error:
            return self._reject(str(error))
        return clean, removed, key, rails

    def _reject(self, message):
        """Show `message` in red, clear old output, and return None."""
        self.inline_var.set(message)
        self._clear_outputs()
        self.set_status("Nothing was done - see the red message.", "error", TAB_LOCK)
        return None

    @staticmethod
    def _removed_note(removed):
        if not removed:
            return ""
        return (f" {removed} character{' was' if removed == 1 else 's were'} removed "
                "because only A-Z is supported.")

    # ---- the two main handlers ----

    def do_encrypt(self):
        """Lock: Stage 1 (Vigenere), then Stage 2 (Rail Fence). Returns the ciphertext."""
        parsed = self._read_inputs()
        if parsed is None:
            return None
        clean, removed, key, rails = parsed

        start = time.perf_counter()
        stage1, final = cipher.custom_encrypt(clean, key, rails)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Self-check: unlocking must give back exactly what we locked.
        back = cipher.custom_decrypt(final, key, rails)
        unlocks = back == clean
        self._show_outputs("lock", clean, stage1, final, removed)
        self.check_label.configure(
            text="Unlocks back to the original: yes" if unlocks else "Unlocks back to the original: NO",
            fg=GREEN if unlocks else RED)
        self.time_label.configure(text=f"Done in {elapsed_ms:.2f} ms")
        self._last_op = {"mode": "lock", "clean": clean, "middle": stage1, "final": final,
                         "key": key, "rails": rails}
        self.set_status(f"Done in {elapsed_ms:.2f} ms.{self._removed_note(removed)}",
                        "ok" if unlocks else "error", TAB_LOCK)
        return final

    def do_decrypt(self):
        """Unlock: undo Stage 2 (Rail Fence) first, then undo Stage 1 (Vigenere). Returns the plaintext."""
        parsed = self._read_inputs()
        if parsed is None:
            return None
        clean, removed, key, rails = parsed

        start = time.perf_counter()
        plain = cipher.custom_decrypt(clean, key, rails)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Show the middle step too: the text after undoing only Stage 2.
        middle = cipher.rail_decrypt(clean, rails)
        # Self-check: locking the answer again must give the ciphertext we started with.
        relocks = cipher.custom_encrypt(plain, key, rails)[1] == clean
        self._show_outputs("unlock", clean, middle, plain, removed)
        self.check_label.configure(
            text="Locks back to the same ciphertext: yes" if relocks else "Locks back to the same ciphertext: NO",
            fg=GREEN if relocks else RED)
        self.time_label.configure(text=f"Done in {elapsed_ms:.2f} ms")
        self._last_op = {"mode": "unlock", "clean": clean, "middle": middle, "final": plain,
                         "key": key, "rails": rails}
        self.set_status(f"Done in {elapsed_ms:.2f} ms.{self._removed_note(removed)}",
                        "ok" if relocks else "error", TAB_LOCK)
        return plain

    def move_output_to_input(self):
        """Copy the final output into the message box (handy: lock, then move, then unlock)."""
        final = self.get_outputs()["final"]
        if not final:
            self.inline_var.set("There is no output to move yet. Press Lock or Unlock first.")
            return False
        self.set_message(final)
        self._clear_outputs()
        self.inline_var.set("")
        self._last_op = None
        self.set_status("Moved the output into the message box.", "info", TAB_LOCK)
        return True

    def copy_output(self):
        """Copy the final output to the clipboard."""
        final = self.get_outputs()["final"]
        if not final:
            self.inline_var.set("There is no output to copy yet. Press Lock or Unlock first.")
            return False
        self.root.clipboard_clear()
        self.root.clipboard_append(final)
        self.inline_var.set("")
        self.set_status(f"Copied {len(final)} letters to the clipboard.", "ok", TAB_LOCK)
        return True

    # ---- Show Working window ----

    def show_working(self):
        """Open a window with the letter-by-letter working of the last lock/unlock."""
        if self._last_op is None:
            self.inline_var.set("Press Lock or Unlock first, then Show Working.")
            return None
        segments, matches, _error = build_working_document(self._last_op)
        win = tk.Toplevel(self.root)
        win.title("Show working")
        win.configure(bg=BG)
        win.geometry("940x640")
        title = "locks" if self._last_op["mode"] == "lock" else "unlocks"
        tk.Label(win, bg=BG, font=FONT_BOLD, fg=TEXT, anchor="w",
                 text=f"How the cipher {title} this message (key and rails as entered)").pack(fill="x", padx=10, pady=(8, 2))
        box = tk.Text(win, wrap="none", font=FONT_MONO, bg=PANEL, fg=TEXT, relief="flat", borderwidth=6)
        yscroll = ttk.Scrollbar(win, orient="vertical", command=box.yview)
        xscroll = ttk.Scrollbar(win, orient="horizontal", command=box.xview)
        box.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        xscroll.pack(side="bottom", fill="x")
        yscroll.pack(side="right", fill="y")
        box.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=(0, 6))
        self._apply_styles(box, segments)
        return win

    def _apply_styles(self, box, segments):
        """Write (style, text) pairs into a Text widget with colours (read-only afterwards)."""
        box.tag_configure("title", font=FONT_TITLE, foreground=TEXT, spacing3=6)
        box.tag_configure("heading", font=FONT_BOLD, foreground=TEXT, spacing1=12, spacing3=4)
        box.tag_configure("stage1", font=FONT_BOLD, foreground=STAGE1_FG, background=STAGE1_BG,
                          spacing1=12, spacing3=4)
        box.tag_configure("stage2", font=FONT_BOLD, foreground=STAGE2_FG, background=STAGE2_BG,
                          spacing1=12, spacing3=4)
        box.tag_configure("body", font=FONT_LABEL, foreground=TEXT, spacing3=4, wrap="word")
        box.tag_configure("mono", font=FONT_MONO, foreground=TEXT, spacing3=4)
        box.tag_configure("note", font=FONT_SMALL, foreground=MUTED, spacing1=6, wrap="word")
        box.tag_configure("ok", font=FONT_BOLD, foreground=GREEN, spacing1=10)
        box.tag_configure("bad", font=FONT_BOLD, foreground=RED, spacing1=10)
        box.configure(state="normal")
        box.delete("1.0", "end")
        for style, text in segments:
            box.insert("end", text + "\n", style)
        box.configure(state="disabled")

    # ----------------------------------------------------------------------
    # ----- TAB 2: BREAK IT (attacks and experiments) -----
    # ----------------------------------------------------------------------

    def _build_break_tab(self, tab):
        # Two sub-pages keep each one small enough to see without scrolling.
        sub = ttk.Notebook(tab)
        sub.pack(fill="both", expand=True)
        self.attack_sub = sub                       # the guided tour switches between its two pages
        one = ttk.Frame(sub, padding=8)
        many = ttk.Frame(sub, padding=8)
        sub.add(one, text="  Try one attack  ")
        sub.add(many, text="  Run the experiments  ")
        self._build_one_attack(one)
        self._build_experiments(many)

    # ---- one attack ----

    def _build_one_attack(self, page):
        page.columnconfigure(0, weight=1, uniform="a")
        page.columnconfigure(1, weight=1, uniform="a")
        page.rowconfigure(0, weight=1)

        # --- Left side: choices ---
        left = ttk.Frame(page)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        left.columnconfigure(0, weight=1)

        src = ttk.LabelFrame(left, text="1. Where does the ciphertext come from?", padding=8)
        src.grid(row=0, column=0, sticky="ew")
        src.columnconfigure(1, weight=1)
        self.source_var = tk.StringVar(value="test")
        ttk.Radiobutton(src, text="Make a test message for me", variable=self.source_var,
                        value="test").grid(row=0, column=0, columnspan=2, sticky="w")
        tk.Label(src, text="    Message length (letters):", bg=BG, font=FONT_LABEL).grid(row=1, column=0, sticky="w")
        self.n_var = tk.StringVar(value=str(DEFAULT_TEST_LENGTH))
        self.n_combo = ttk.Combobox(src, textvariable=self.n_var, values=[str(n) for n in attack.TEXT_LENGTHS],
                                    state="readonly", width=8)
        self.n_combo.grid(row=1, column=1, sticky="w")
        tk.Label(src, text="    Random text, key and rails; the answer stays hidden.",
                 bg=BG, fg=MUTED, font=FONT_SMALL, justify="left").grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(src, text="Paste my own ciphertext", variable=self.source_var,
                        value="paste").grid(row=3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        frame, self.paste_text = self._make_box(src, PANEL, 3, editable=True)
        frame.grid(row=4, column=0, columnspan=2, sticky="ew")
        tk.Label(src, text="    Crib (first letters of the message):", bg=BG, font=FONT_LABEL
                 ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(4, 0))
        self.crib_entry_var = tk.StringVar()
        ttk.Entry(src, textvariable=self.crib_entry_var, font=FONT_MONO).grid(row=6, column=0, columnspan=2, sticky="ew")

        atk = ttk.LabelFrame(left, text="2. Which attack?", padding=8)
        atk.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        atk.columnconfigure(1, weight=1)
        self.attack_var = tk.StringVar(value="freq")
        ttk.Radiobutton(atk, text="Frequency attack (ciphertext only)", variable=self.attack_var,
                        value="freq").grid(row=0, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(atk, text="Known-plaintext attack (needs a crib)", variable=self.attack_var,
                        value="kpa").grid(row=1, column=0, columnspan=2, sticky="w")
        tk.Label(atk, text="    Crib size for test messages:", bg=BG, font=FONT_LABEL).grid(row=2, column=0, sticky="w")
        self.crib_size_var = tk.StringVar(value="30")
        ttk.Spinbox(atk, from_=10, to=40, width=5, textvariable=self.crib_size_var,
                    wrap=False).grid(row=2, column=1, sticky="w")

        run = ttk.Frame(left)
        run.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.attack_button = ttk.Button(run, text="Run attack", style="Go.TButton", command=self.run_attack)
        self.attack_button.pack(side="left")
        self.attack_bar = ttk.Progressbar(run, mode="indeterminate", length=160)
        self.attack_bar.pack(side="left", padx=10)
        self.attack_inline_var = tk.StringVar()
        tk.Label(left, textvariable=self.attack_inline_var, bg=BG, fg=RED, font=FONT_BOLD, anchor="w",
                 wraplength=420, justify="left").grid(row=3, column=0, sticky="ew", pady=(4, 0))

        # --- Right side: the result ---
        right = ttk.LabelFrame(page, text="Result", padding=8)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        right.columnconfigure(1, weight=1)
        right.rowconfigure(6, weight=1)
        self.result_vars = {}
        for row, (key, label) in enumerate([("rails", "Rails found:"), ("key", "Key found:"),
                                            ("length", "Key length:"), ("guesses", "Guesses:"),
                                            ("time", "Time:")]):
            tk.Label(right, text=label, bg=BG, font=FONT_BOLD, anchor="w").grid(row=row, column=0, sticky="w")
            self.result_vars[key] = tk.StringVar(value="-")
            tk.Label(right, textvariable=self.result_vars[key], bg=BG, font=FONT_MONO, anchor="w"
                     ).grid(row=row, column=1, sticky="w", padx=8)
        tk.Label(right, text="Recovered plaintext (first 300 letters):", bg=BG, font=FONT_BOLD,
                 anchor="w").grid(row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        frame, self.recovered_text = self._make_box(right, NEUTRAL_BG, 7)
        frame.grid(row=6, column=0, columnspan=2, sticky="nsew")
        self.correct_var = tk.StringVar()
        self.correct_label = tk.Label(right, textvariable=self.correct_var, bg=BG, font=FONT_BOLD, anchor="w")
        self.correct_label.grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))
        reveal = ttk.Frame(right)
        reveal.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        self.reveal_button = ttk.Button(reveal, text="Reveal truth", command=self.reveal_truth, state="disabled")
        self.reveal_button.pack(side="left")
        self.truth_var = tk.StringVar()
        tk.Label(right, textvariable=self.truth_var, bg=BG, fg=TEXT, font=FONT_SMALL, anchor="w",
                 justify="left", wraplength=420).grid(row=9, column=0, columnspan=2, sticky="w")

    def _get_corpus(self):
        """The test text, loaded the first time it is needed. None if the file is missing."""
        if self._corpus is None:
            try:
                self._corpus = attack.load_corpus()
            except SystemExit:                      # attack.load_corpus exits if the file is missing
                return None
        return self._corpus

    def _clear_attack_result(self):
        for var in self.result_vars.values():
            var.set("-")
        self._set_text(self.recovered_text, "")
        self.correct_var.set("")
        self.truth_var.set("")
        self.reveal_button.configure(state="disabled")
        self._truth = None

    def run_attack(self):
        """Start the chosen attack in a background thread (the window stays responsive)."""
        if self._busy["attack"]:
            return False
        self.attack_inline_var.set("")
        self._clear_attack_result()
        which = self.attack_var.get()
        truth, crib, note = None, "", ""

        if self.source_var.get() == "test":
            try:
                crib_size = int(self.crib_size_var.get().strip())
                n = int(self.n_var.get())
            except ValueError:
                self.attack_inline_var.set("The message length and the crib size must be whole numbers.")
                return False
            if not 10 <= crib_size <= 40:
                self.attack_inline_var.set("The crib size must be between 10 and 40.")
                return False
            corpus = self._get_corpus()
            if corpus is None:
                self.attack_inline_var.set("The test text (data/corpus.txt) was not found, so a test message "
                                           "cannot be made. You can still paste your own ciphertext.")
                return False
            plaintext, key, rails, ciphertext = attack._make_trial(random.Random(), corpus, n)
            truth = {"plaintext": plaintext, "key": key, "rails": rails}
            crib = plaintext[:crib_size]
            note = f"Test message of {n} letters"
        else:
            ciphertext, removed = cipher.sanitize(self._get_text(self.paste_text))
            if not ciphertext:
                self.attack_inline_var.set("Paste a ciphertext first (it needs letters A-Z).")
                return False
            crib, _ = cipher.sanitize(self.crib_entry_var.get())
            if which == "kpa" and not crib:
                self.attack_inline_var.set("The known-plaintext attack needs a crib: type the first letters "
                                           "of the original message.")
                return False
            note = f"Pasted ciphertext of {len(ciphertext)} letters" + (
                f" ({removed} characters removed)" if removed else "")

        self._truth = truth
        self._attack_note = note
        self.attack_button.configure(state="disabled")
        self.attack_bar.start(12)
        self.set_status(f"{note}: attack running ...", "info", TAB_ATTACK)
        return self._start_job("attack", lambda: self._attack_job(which, ciphertext, crib))

    @staticmethod
    def _attack_job(which, ciphertext, crib):
        """Runs in the worker thread: do the attack and time it."""
        start = time.perf_counter()
        if which == "freq":
            found = attack.frequency_attack(ciphertext)
        else:
            found = attack.known_plaintext_attack(ciphertext, crib)
        return {"found": found, "ms": (time.perf_counter() - start) * 1000, "which": which}

    def _on_attack_done(self, payload):
        """Back on the main thread: show what the attack found."""
        self.attack_bar.stop()
        self.attack_button.configure(state="normal")
        found, ms = payload["found"], payload["ms"]
        if not found["ok"]:
            self.attack_inline_var.set(found["error"][0].upper() + found["error"][1:] + ".")
            self.set_status("The attack could not run - see the red message.", "error", TAB_ATTACK)
            return
        self.result_vars["rails"].set(str(found["rails"]))
        self.result_vars["key"].set(found["key"])
        self.result_vars["length"].set(str(found["key_length"]))
        self.result_vars["guesses"].set(str(found["guesses"]))
        self.result_vars["time"].set(f"{ms:.2f} ms")
        self._set_text(self.recovered_text, found["plaintext"][:300])
        message = f"{self._attack_note}: attack finished in {ms:.2f} ms."
        if self._truth is not None:
            accuracy = letter_accuracy(self._truth["plaintext"], found["plaintext"])
            correct = found["plaintext"] == self._truth["plaintext"]
            self.correct_var.set(f"Correct: {'yes' if correct else 'no'}   "
                                 f"(letters right: {accuracy * 100:.1f} %)")
            self.correct_label.configure(fg=GREEN if correct else RED)
            self.reveal_button.configure(state="normal")
            message += " Press Reveal truth to compare."
        self.set_status(message, "ok", TAB_ATTACK)

    def reveal_truth(self):
        """Show the hidden key, rails and the start of the real message."""
        if self._truth is None:
            return False
        t = self._truth
        self.truth_var.set(f"True rails: {t['rails']}    True key: {t['key']} ({len(t['key'])} letters)\n"
                           f"True message starts: {t['plaintext'][:60]}")
        return True

    # ---- experiments ----

    EXP_TIP = "Tip: 'Load saved full results' shows the saved run instantly."

    def _build_experiments(self, page):
        page.columnconfigure(0, weight=1)
        page.rowconfigure(2, weight=1)

        # Row 0: choose how big a run, then Run / Cancel and a progress bar.
        controls = ttk.Frame(page)
        controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.exp_mode_var = tk.StringVar(value="quick")
        ttk.Radiobutton(controls, text="Quick (10 trials)", variable=self.exp_mode_var,
                        value="quick").pack(side="left")
        ttk.Radiobutton(controls, text="Full (100 trials, slow)", variable=self.exp_mode_var,
                        value="full").pack(side="left", padx=8)
        self.exp_run = ttk.Button(controls, text="Run", style="Go.TButton", command=self.run_experiments)
        self.exp_run.pack(side="left", padx=8)
        self.exp_cancel = ttk.Button(controls, text="Cancel", command=self.cancel_experiments, state="disabled")
        self.exp_cancel.pack(side="left")
        # One step per table row: Table 1 and Table 2 have one row per message length, Table 3 one per crib size.
        rows_in_all_tables = 2 * len(attack.TEXT_LENGTHS) + len(attack.CRIB_SIZES)
        self.exp_bar = ttk.Progressbar(controls, mode="determinate", length=160, maximum=rows_in_all_tables)
        self.exp_bar.pack(side="left", padx=10)

        # Row 1: the file buttons, and ONE note line that shows the progress text,
        # a tip, or (in red) a plain-English error. One line = never cut off.
        files = ttk.Frame(page)
        files.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 4))
        ttk.Button(files, text="Load saved full results", command=self.load_saved_attack_results).pack(side="left")
        ttk.Button(files, text="Save as CSV...", command=self.save_attack_csv).pack(side="left", padx=8)
        self.exp_note_var = tk.StringVar(value=self.EXP_TIP)
        self.exp_note_label = tk.Label(files, textvariable=self.exp_note_var, bg=BG, font=FONT_SMALL, fg=MUTED,
                                       anchor="w", justify="left", wraplength=520)
        self.exp_note_label.pack(side="left", padx=8, fill="x", expand=True)

        # Row 2: the three tables, exactly as attack.py prints them. They sit in a
        # scrollable area so that nothing is cut off even at the smallest window size.
        canvas, scrollbar, inner = self._make_scrollable(page)
        canvas.grid(row=2, column=0, sticky="nsew")
        scrollbar.grid(row=2, column=1, sticky="ns")
        inner.columnconfigure(0, weight=1)
        self.attack_trees = {}
        by_length = len(attack.TEXT_LENGTHS)              # tables 1 and 2 have one row per message length
        specs = [("table1", "Table 1: frequency attack (ciphertext only)", "N", by_length),
                 ("table2", f"Table 2: known-plaintext attack, crib M = {attack.DEFAULT_CRIB}", "N", by_length),
                 ("table3", f"Table 3: known-plaintext attack vs crib size, N = {attack.TABLE3_LENGTH}", "crib M", 5)]
        row = 0
        for name, title, first, height in specs:
            tk.Label(inner, text=title, bg=BG, font=FONT_BOLD, anchor="w").grid(row=row, column=0, sticky="ew", pady=(4, 0))
            tree = ttk.Treeview(inner, show="headings", height=height,
                                columns=("a", "exact", "text", "key", "rails", "ms", "guesses"))
            for col, text, width in (("a", first, 70), ("exact", "exact %", 90), ("text", "text acc %", 100),
                                     ("key", "key acc %", 100), ("rails", "rails %", 90),
                                     ("ms", "median ms", 100), ("guesses", "median guesses", 130)):
                tree.heading(col, text=text)
                tree.column(col, width=width, anchor="e")
            tree.grid(row=row + 1, column=0, sticky="ew")
            self.attack_trees[name] = tree
            row += 2

    def _exp_say(self, text, error=False):
        """Show one line on the experiments page: grey normally, red for an error."""
        self.exp_note_var.set(text)
        self.exp_note_label.configure(fg=RED if error else MUTED)

    def _fill_attack_trees(self, results):
        """Show the three tables (same columns and decimals as attack.py prints)."""
        for name, tree in self.attack_trees.items():
            tree.delete(*tree.get_children())
            vary = "crib" if name == "table3" else "text_length"
            for r in results[name]:
                tree.insert("", "end", values=format_attack_row(r, vary))

    def run_experiments(self):
        """Run the three experiment tables in a background thread, with progress and Cancel."""
        if self._busy["exp"]:
            return False
        trials = 10 if self.exp_mode_var.get() == "quick" else 100
        self._cancel["exp"].clear()
        self.exp_run.configure(state="disabled")
        self.exp_cancel.configure(state="normal")
        self.exp_bar.configure(value=0)
        self._exp_say(f"working ({trials} trials per row) ...")
        self.set_status(f"Running the experiments with {trials} trials per row. "
                        "You can keep using the other tabs.", "info", TAB_ATTACK)

        def progress(done, total):
            # Runs in the worker thread: report, then stop if the user pressed Cancel.
            self._queue.put(("exp", "progress", (done, total)))
            if self._cancel["exp"].is_set():
                raise attack.CancelledError()

        return self._start_job("exp", lambda: attack.run_experiments(trials=trials, progress=progress))

    def cancel_experiments(self):
        """Ask the running experiments to stop (they stop after the table row in progress)."""
        if self._busy["exp"]:
            self._cancel["exp"].set()
            self.exp_cancel.configure(state="disabled")
            self._exp_say("cancelling - finishing the current row ...")
            self.set_status("Cancelling: the run stops when the current table row is finished.", "info", TAB_ATTACK)
            return True
        return False

    def _on_exp_progress(self, payload):
        done, total = payload
        self.exp_bar.configure(maximum=total, value=done)
        self._exp_say(f"row {done} of {total} done")

    def _on_exp_done(self, results):
        self._attack_results = results
        self._fill_attack_trees(results)
        trials = results["table1"][0]["trials"]
        self._exp_finished(f"done ({trials} trials per row)")
        self.set_status(f"Experiments finished ({trials} trials per row). Use 'Save as CSV...' to keep them.",
                        "ok", TAB_ATTACK)

    def _exp_finished(self, label, error=False):
        self.exp_run.configure(state="normal")
        self.exp_cancel.configure(state="disabled")
        self._exp_say(label, error)

    def load_saved_attack_results(self, path=None):
        """Show results/attack_results.csv (the saved full run) instantly."""
        path = path or ATTACK_CSV
        try:
            results = read_attack_csv(path)
        except FileNotFoundError:
            self._exp_say(f"{os.path.basename(path)} was not found. Run  python attack.py  to create it.", True)
            return None
        except ValueError as error:
            self._exp_say(str(error), True)
            return None
        self._attack_results = results
        self._fill_attack_trees(results)
        trials = results["table1"][0]["trials"]
        self._exp_say(f"showing saved results ({trials} trials per row)")
        self.set_status(f"Loaded {os.path.basename(path)}: {trials} trials per row.", "ok", TAB_ATTACK)
        return results

    def save_attack_csv(self, path=None):
        """Save the tables on screen as a CSV file chosen in a Save dialog.

        Never overwrites the protected result files. Returns the path written, or None.
        """
        if self._attack_results is None:
            self._exp_say("There are no results to save yet. Run the experiments or load saved results first.", True)
            return None
        if path is None:
            folder = os.path.dirname(ATTACK_CSV)
            path = filedialog.asksaveasfilename(
                parent=self.root, title="Save experiment tables as CSV", defaultextension=".csv",
                initialdir=folder if os.path.isdir(folder) else os.path.expanduser("~"),
                initialfile="attack_results_gui.csv", filetypes=[("CSV file", "*.csv")])
            if not path:                                # the user pressed Cancel in the dialog
                return None
        if is_protected(path):
            self._exp_say("That file is protected (it holds the saved results of the command-line "
                          "programs). Please choose a different name, for example attack_results_gui.csv.", True)
            return None
        try:
            attack.write_csv(self._attack_results, path)
        except OSError as error:
            self._exp_say(f"Could not save the file: {error}", True)
            return None
        self._exp_say(f"saved {os.path.basename(path)}")
        self.set_status(f"Saved {path}", "ok", TAB_ATTACK)
        return path

    # ----------------------------------------------------------------------
    # ----- TAB 3: SPEED TEST -----
    # ----------------------------------------------------------------------

    def _build_speed_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        controls = ttk.Frame(tab)
        controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.speed_mode_var = tk.StringVar(value="quick")
        ttk.Radiobutton(controls, text="Quick (up to 10,000)", variable=self.speed_mode_var,
                        value="quick").pack(side="left")
        ttk.Radiobutton(controls, text="Full (up to 100,000)", variable=self.speed_mode_var,
                        value="full").pack(side="left", padx=8)
        self.speed_run = ttk.Button(controls, text="Run", style="Go.TButton", command=self.run_speed_test)
        self.speed_run.pack(side="left", padx=8)
        self.speed_cancel = ttk.Button(controls, text="Cancel", command=self.cancel_speed_test, state="disabled")
        self.speed_cancel.pack(side="left")
        self.speed_bar = ttk.Progressbar(controls, mode="determinate", length=90, maximum=39)
        self.speed_bar.pack(side="left", padx=10)
        ttk.Button(controls, text="Load saved results", command=self.load_saved_speed_results).pack(side="right")

        # ONE note line under the buttons: progress text, or (in red) a plain-English error.
        self.speed_note_var = tk.StringVar(value="Median time per message length. A flat 'custom us/char' "
                                                 "column means O(N).")
        self.speed_note_label = tk.Label(tab, textvariable=self.speed_note_var, bg=BG, font=FONT_SMALL, fg=MUTED,
                                         anchor="w", justify="left", wraplength=880)
        self.speed_note_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 2))

        self.speed_tree = ttk.Treeview(tab, show="headings", height=6,
                                       columns=("n", "shift", "enc", "dec", "ratio", "us"))
        for col, text, width in (("n", "N", 80), ("shift", "Shift enc ms", 130), ("enc", "Custom enc ms", 140),
                                 ("dec", "Custom dec ms", 140), ("ratio", "ratio c/s", 100),
                                 ("us", "custom us/char", 140)):
            self.speed_tree.heading(col, text=text)
            self.speed_tree.column(col, width=width, anchor="e")
        self.speed_tree.grid(row=2, column=0, columnspan=2, sticky="ew")

        self.chart_time = tk.Canvas(tab, bg=PANEL, height=200, highlightthickness=1, highlightbackground="#c7ced8")
        self.chart_time.grid(row=3, column=0, sticky="nsew", padx=(0, 4), pady=(6, 0))
        self.chart_per_char = tk.Canvas(tab, bg=PANEL, height=200, highlightthickness=1, highlightbackground="#c7ced8")
        self.chart_per_char.grid(row=3, column=1, sticky="nsew", padx=(4, 0), pady=(6, 0))
        tab.rowconfigure(3, weight=1)
        self.chart_time.bind("<Configure>", lambda _e: self._redraw_charts())
        self.chart_per_char.bind("<Configure>", lambda _e: self._redraw_charts())

        self.verdict_box = tk.Text(tab, height=7, wrap="word", font=FONT_SMALL, bg=NEUTRAL_BG, fg=TEXT,
                                   relief="flat", borderwidth=4, state="disabled")
        self.verdict_box.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        tk.Label(tab, text="Timings depend on this machine; python benchmark.py gives the cleanest numbers.",
                 bg=BG, font=FONT_SMALL, fg=MUTED, anchor="w").grid(row=5, column=0, columnspan=2, sticky="ew")
        self._redraw_charts()

    def _speed_say(self, text, error=False):
        """Show one line on the speed page: grey normally, red for an error."""
        self.speed_note_var.set(text)
        self.speed_note_label.configure(fg=RED if error else MUTED)

    def run_speed_test(self):
        """Run the benchmarks in a background thread, with progress and Cancel."""
        if self._busy["speed"]:
            return False
        settings = benchmark.QUICK_SETTINGS if self.speed_mode_var.get() == "quick" else benchmark.FULL_SETTINGS
        self._cancel["speed"].clear()
        self.speed_run.configure(state="disabled")
        self.speed_cancel.configure(state="normal")
        self.speed_bar.configure(value=0, maximum=benchmark.count_cells(settings))
        self._speed_say("working ...")
        self.set_status("Running the speed test. Please leave the computer alone for the best numbers.", "info",
                        TAB_EFFICIENCY)

        def progress(done, total):
            self._queue.put(("speed", "progress", (done, total)))
            if self._cancel["speed"].is_set():
                raise benchmark.CancelledError()

        return self._start_job("speed", lambda: benchmark.run_benchmarks(settings, progress=progress))

    def cancel_speed_test(self):
        if self._busy["speed"]:
            self._cancel["speed"].set()
            self.speed_cancel.configure(state="disabled")
            self._speed_say("cancelling ...")
            return True
        return False

    def _on_speed_progress(self, payload):
        done, total = payload
        self.speed_bar.configure(maximum=total, value=done)
        self._speed_say(f"{done} of {total} measurements done")

    def _on_speed_done(self, results):
        self._show_speed_results({"table_a": results["table_a"], "fits": results["fits"],
                                  "memory": results["memory"]})
        self._speed_finished("done")
        self.set_status("Speed test finished.", "ok", TAB_EFFICIENCY)

    def _speed_finished(self, label, error=False):
        self.speed_run.configure(state="normal")
        self.speed_cancel.configure(state="disabled")
        self._speed_say(label, error)

    def load_saved_speed_results(self, path=None):
        """Show results/benchmark_results.csv (the saved full run)."""
        path = path or BENCH_CSV
        try:
            data = read_benchmark_csv(path)
        except FileNotFoundError:
            self._speed_say(f"{os.path.basename(path)} was not found. Run  python benchmark.py  to create it.", True)
            return None
        except ValueError as error:
            self._speed_say(str(error), True)
            return None
        self._show_speed_results(data)
        self._speed_say("showing saved results")
        self.set_status(f"Loaded {os.path.basename(path)}.", "ok", TAB_EFFICIENCY)
        return data

    def _show_speed_results(self, data):
        """Fill the table, the two charts and the verdict lines."""
        self._speed_results = data
        self.speed_tree.delete(*self.speed_tree.get_children())
        for row in data["table_a"]:
            self.speed_tree.insert("", "end", values=format_speed_row(row))
        rows = data["table_a"]
        self._chart_series = {
            "time": [{"name": "Shift cipher", "color": "#6b7280",
                      "points": [(r["n"], r["shift_enc_ms"]) for r in rows]},
                     {"name": "Two-stage cipher (lock)", "color": STAGE1_FG,
                      "points": [(r["n"], r["custom_enc_ms"]) for r in rows]}],
            "per_char": [{"name": "Two-stage cipher (lock)", "color": STAGE2_FG,
                          "points": [(r["n"], r["us_per_char"]) for r in rows]}],
        }
        self._redraw_charts()
        lines = ["Does the time grow in step with N?  (slope 1.0 = linear)"]
        for fit in data["fits"]:
            lines.append(f"  {fit['name']}: log-log slope {fit['loglog_slope']:.3f}, R^2 {fit['r_squared']:.5f}"
                         f"  ->  {fit['verdict']}")
        # One line per cipher, with every message size measured, e.g.
        #   Custom enc: N=10000 487.5 KB (49.9 bytes/char);  N=100000 4873.8 KB (49.9 bytes/char)
        lines.append("Peak memory while locking:")
        by_name = {}
        for m in data["memory"]:
            by_name.setdefault(m["name"], []).append(
                f"N={m['n']} {m['peak_kb']:.1f} KB ({m['bytes_per_char']:.1f} bytes/char)")
        for name, parts in by_name.items():
            lines.append(f"  {name}: " + ";  ".join(parts))
        self._set_text(self.verdict_box, "\n".join(lines))

    def _redraw_charts(self):
        series = self._chart_series or {"time": [], "per_char": []}
        draw_line_chart(self.chart_time, "Time to lock a message", "message length N (letters)",
                        "time (ms)", series["time"])
        draw_line_chart(self.chart_per_char, "Microseconds per character", "message length N (letters)",
                        "us per character", series["per_char"])

    # ----------------------------------------------------------------------
    # ----- TAB 4: HOW IT WORKS -----
    # ----------------------------------------------------------------------

    def _build_help_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        self.help_text = tk.Text(tab, wrap="word", font=FONT_LABEL, bg=PANEL, fg=TEXT, relief="flat",
                                 borderwidth=8, state="disabled")
        scroll = ttk.Scrollbar(tab, orient="vertical", command=self.help_text.yview)
        self.help_text.configure(yscrollcommand=scroll.set)
        self.help_text.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.refresh_help()

    def refresh_help(self):
        """(Re)build the page. Result numbers are read from the CSV files each time."""
        try:
            attack_data = read_attack_csv()
        except (OSError, ValueError):
            attack_data = None                      # missing/unreadable: the page says so
        try:
            speed_data = read_benchmark_csv()
        except (OSError, ValueError):
            speed_data = None
        self._apply_styles(self.help_text, help_text.build_help_document(attack_data, speed_data))

    def help_content(self):
        return self._get_text(self.help_text)

    # ----------------------------------------------------------------------
    # ----- GUIDED TOUR (the START HERE button) -----
    # ----------------------------------------------------------------------
    # The tour is a purple banner under the header with "Step N of 5", a short
    # explanation, and Back / Next / Exit tour buttons. Each step switches to
    # the right tab and then presses the SAME handlers the normal buttons use
    # (do_encrypt, do_decrypt, run_attack, load_saved_attack_results, ...), so
    # what you see is real output, never a fake. The tour never writes a file:
    # the only file actions in these steps are READING the saved result CSVs.
    # Any number in a banner is read from those CSVs at runtime.

    def _build_tour_banner(self):
        frame = tk.Frame(self.root, bg=TOUR_BG, highlightbackground=TOUR_EDGE, highlightthickness=2)
        frame.columnconfigure(0, weight=1)
        self.tour_title = tk.Label(frame, text="", font=FONT_BOLD, bg=TOUR_BG, fg=TOUR_FG, anchor="w")
        self.tour_title.grid(row=0, column=0, sticky="w", padx=10, pady=(4, 0))
        buttons = tk.Frame(frame, bg=TOUR_BG)
        buttons.grid(row=0, column=1, sticky="e", padx=10, pady=(4, 0))
        # Small buttons keep the banner low, so it takes as little room as possible.
        self.tour_back_button = ttk.Button(buttons, text="Back", style="Tour.TButton", command=self.tour_back)
        self.tour_back_button.pack(side="left")
        self.tour_next_button = ttk.Button(buttons, text="Next", style="Tour.TButton", command=self.tour_next)
        self.tour_next_button.pack(side="left", padx=6)
        ttk.Button(buttons, text="Exit tour", style="Tour.TButton", command=self.tour_exit).pack(side="left")
        # height=2: always reserve two lines, so the banner keeps the same height from step to step.
        self.tour_text = tk.Label(frame, text="", font=FONT_LABEL, bg=TOUR_BG, fg=TEXT, anchor="nw",
                                  justify="left", wraplength=880, height=2)
        self.tour_text.grid(row=1, column=0, columnspan=2, sticky="ew", padx=10, pady=(0, 4))
        # Wrap the text to the banner's width, so it never runs off the right edge.
        frame.bind("<Configure>", lambda e: self.tour_text.configure(wraplength=max(200, e.width - 30)))
        self._tour_frame = frame

    def start_tour(self):
        """START HERE: show the banner (under the header) and go to step 1. Starting again restarts."""
        if self._tour_frame is None:
            self._build_tour_banner()
        if self._tour_frame.winfo_manager() != "pack":      # not already showing (a restart keeps it)
            self._tour_frame.pack(side="top", fill="x", padx=10, pady=(2, 2), before=self.notebook)
            self._grow_window_for_banner()
        return self.tour_goto(1)

    def _grow_window_for_banner(self):
        """Make the window taller by the banner's height, so the tabs keep the room they had.

        Without this the banner would squeeze the tab below it (at the smallest
        window size the output boxes would shrink to a sliver). The window is
        only grown if it is a normal window and the screen has room; otherwise
        the tab simply gets a little less space. tour_exit shrinks it back.
        """
        self._tour_grew = 0
        self.root.update_idletasks()
        if self.root.state() != "normal" or not self.root.winfo_ismapped():
            return                                          # maximised, hidden or not shown yet
        extra = self._tour_frame.winfo_reqheight() + 4      # 4 = the banner's outer padding
        width, height = self.root.winfo_width(), self.root.winfo_height()
        room_below = self.root.winfo_screenheight() - self.root.winfo_y() - 60     # 60 = taskbar etc.
        grown = min(height + extra, room_below)
        if grown > height:
            self.root.geometry(f"{width}x{grown}")
            self._tour_grew = grown - height

    def tour_goto(self, step):
        """Run tour step `step` (1 to 5): switch tab, press the real buttons, show the banner text."""
        step = max(1, min(TOUR_STEPS, step))
        runner = {1: self._tour_step_lock, 2: self._tour_step_unlock, 3: self._tour_step_attack,
                  4: self._tour_step_experiments, 5: self._tour_step_efficiency}[step]
        text = runner()
        self._tour_step = step
        self.tour_title.configure(text=f"Step {step} of {TOUR_STEPS}")
        self.tour_text.configure(text=text)
        self.tour_back_button.configure(state="normal" if step > 1 else "disabled")
        self.tour_next_button.configure(state="normal" if step < TOUR_STEPS else "disabled")
        return text

    def tour_next(self):
        """Go to the next step. Does nothing (returns None) when no tour runs or at the last step."""
        if self._tour_step is None or self._tour_step >= TOUR_STEPS:
            return None
        return self.tour_goto(self._tour_step + 1)

    def tour_back(self):
        """Go to the previous step. Does nothing (returns None) when no tour runs or at step 1."""
        if self._tour_step is None or self._tour_step <= 1:
            return None
        return self.tour_goto(self._tour_step - 1)

    def tour_exit(self):
        """Remove the banner. Nothing else changes: the window stays exactly as the tour left it."""
        if self._tour_frame is not None and self._tour_frame.winfo_manager() == "pack":
            self._tour_frame.pack_forget()
            if self._tour_grew and self.root.state() != "zoomed":      # give back the room the banner added
                smallest = self.root.minsize()[1]
                self.root.geometry(f"{self.root.winfo_width()}x{max(smallest, self.root.winfo_height() - self._tour_grew)}")
        self._tour_grew = 0
        self._tour_step = None

    def tour_running(self):
        return self._tour_step is not None

    # ---- the five steps (each returns the banner text) ----

    def _tour_lock_sample(self):
        """Fill the sample message, key and rails and press Lock. Returns the ciphertext (or None)."""
        self.notebook.select(TAB_LOCK)
        self.set_message(SAMPLE_MESSAGE)
        self.key_var.set(SAMPLE_KEY)
        self.rails_var.set(str(SAMPLE_RAILS))
        return self.do_encrypt()

    def _tour_step_lock(self):
        if self._tour_lock_sample() is None:
            return "The sample could not be locked: " + (self.inline_text() or "see the status bar.")
        return ("Lock: the blue box is the message after Stage 1 (Vigenere); the orange box is the final "
                "ciphertext after Stage 2 (Rail Fence). Click Show Working to see the hand calculation.")

    def _tour_step_unlock(self):
        self._tour_lock_sample()                    # the same state as step 1, so Back / Next always work
        self.move_output_to_input()                 # the ciphertext becomes the new message
        plain = self.do_decrypt()
        original, _ = cipher.sanitize(SAMPLE_MESSAGE)
        if plain != original:
            return "Unlock did not give the original message back: " + (self.inline_text() or "see the status bar.")
        return ("Unlock: the original message is back in the last box, and the green check says it matched "
                f"(\"{self.check_label.cget('text')}\").")

    def _tour_step_attack(self):
        self.notebook.select(TAB_ATTACK)
        self.attack_sub.select(0)
        self.source_var.set("test")
        self.attack_var.set("freq")
        self.n_var.set(str(DEFAULT_TEST_LENGTH))
        self.run_attack()                           # runs in the background; the result appears in a moment
        if self.attack_inline_var.get():
            return "The attack could not start: " + self.attack_inline_var.get()
        return ("Attack: the attacker saw only the ciphertext, never the key. When the result appears, "
                "click Reveal truth to compare it with the real answer.")

    def _tour_step_experiments(self):
        self.notebook.select(TAB_ATTACK)
        self.attack_sub.select(1)
        results = self.load_saved_attack_results()
        text = experiments_banner(results)
        if text is None:                            # the file is missing or unreadable: say so, show no numbers
            return "No saved experiment results could be shown. " + self.exp_note_var.get()
        return text

    def _tour_step_efficiency(self):
        self.notebook.select(TAB_EFFICIENCY)
        data = self.load_saved_speed_results()
        text = efficiency_banner(data)
        if text is None:
            return "No saved speed results could be shown. " + self.speed_note_var.get()
        return text

    # ----------------------------------------------------------------------
    # ----- background jobs (worker thread + queue) -----
    # ----------------------------------------------------------------------
    # A slow job runs in a worker thread so the window never freezes. The
    # worker must NOT touch any widget; it only puts messages on a queue, and
    # the main thread reads them every 100 ms (_poll_queue) and updates the screen.

    def _start_job(self, job, work):
        """Run work() in a new thread; its result arrives later as a queue message."""
        if self._busy[job]:
            return False
        self._busy[job] = True
        threading.Thread(target=self._worker, args=(job, work), daemon=True).start()
        return True

    def _worker(self, job, work):
        """Body of the worker thread. Always ends by putting a message on the queue."""
        try:
            self._queue.put((job, "done", work()))
        except (attack.CancelledError, benchmark.CancelledError):
            self._queue.put((job, "cancelled", None))
        except SystemExit as error:                 # e.g. attack.load_corpus when the file is missing
            self._queue.put((job, "error", str(error) or "The program stopped."))
        except Exception as error:                  # never let a crash kill the thread silently
            self._queue.put((job, "error", f"{type(error).__name__}: {error}"))

    def _poll_queue(self):
        """Main thread: handle every waiting message, then check again in 100 ms."""
        try:
            while True:
                job, kind, payload = self._queue.get_nowait()
                if kind != "progress":
                    self._busy[job] = False
                self._dispatch(job, kind, payload)
        except queue.Empty:
            pass
        self._poll_id = self.root.after(100, self._poll_queue)

    def _dispatch(self, job, kind, payload):
        if kind == "progress":
            {"exp": self._on_exp_progress, "speed": self._on_speed_progress}[job](payload)
        elif kind == "done":
            {"attack": self._on_attack_done, "exp": self._on_exp_done, "speed": self._on_speed_done}[job](payload)
        elif kind == "cancelled":
            if job == "exp":
                self._exp_finished("cancelled")
            else:
                self._speed_finished("cancelled")
            self.set_status("Cancelled. Nothing was changed.", "info", TAB_EFFICIENCY if job == "speed" else TAB_ATTACK)
        elif kind == "error":
            if job == "attack":
                self.attack_bar.stop()
                self.attack_button.configure(state="normal")
                self.attack_inline_var.set(payload)
            elif job == "exp":
                self._exp_finished(f"Stopped by an error: {payload}", error=True)
            else:
                self._speed_finished(f"Stopped by an error: {payload}", error=True)
            self.set_status("Something went wrong - see the red message.", "error",
                            TAB_EFFICIENCY if job == "speed" else TAB_ATTACK)

    def is_busy(self):
        return any(self._busy.values())

    def wait_until_idle(self, timeout=120.0):
        """Keep the window alive until every background job has finished (used by tests and scripts)."""
        deadline = time.monotonic() + timeout
        while self.is_busy() or not self._queue.empty():
            if time.monotonic() > deadline:
                return False
            self.root.update()
            time.sleep(0.01)
        self.root.update()
        return True

    # ----------------------------------------------------------------------
    # ----- closing -----
    # ----------------------------------------------------------------------

    def close(self):
        """Stop any running job and close the window."""
        for event in self._cancel.values():
            event.set()                              # ask the workers to stop at their next checkpoint
        try:
            self.root.after_cancel(self._poll_id)
        except (tk.TclError, AttributeError):
            pass
        self.root.destroy()


# ==========================================================================
# ===== START-UP =====
# ==========================================================================

def main():
    """Open the window. Exits with one plain line (no traceback) if tkinter or a display is missing."""
    if tk is None:
        raise SystemExit("This program needs tkinter, which is not installed with this Python "
                         f"({TKINTER_ERROR}). Install it (on Linux: the python3-tk package) and try again.")
    try:
        import ctypes                                # sharper text on Windows high-DPI screens
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:                                # not Windows, or not available: no problem
        pass
    try:
        root = tk.Tk()
    except tk.TclError as error:
        raise SystemExit(f"Cannot open a window here ({error}). The GUI needs a desktop display.")
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
