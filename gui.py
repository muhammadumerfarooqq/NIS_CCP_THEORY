"""Desktop window for the Vigenere + Rail Fence cipher.   Start it with:

    python gui.py

A demo tool for the viva: four tabs, and each one shows one line of the course project (CCP).

    Req 2 - Encrypt & Decrypt        lock and unlock a message; Show Working = the hand calculation
    Req 3 / Deliverable 2 - Attack   try one attack on a random test message, and see the saved results table
    Req 4 - Efficiency               saved timing table and charts; Run = a quick measurement on this computer
    Req 1 / Deliverable 1 - Design   one screen that explains the design (its examples are checked against cipher.py)

SAFETY RULES this program follows:
    * No network, no local server, no eval/exec.
    * The key is never saved anywhere. It lives only in the window while you use it.
    * The only files it touches are the two saved result files, and only to READ them.
      It never writes a file.
    * Standard library only (tkinter + ttk).

How to read this file (top to bottom):
    1. SETTINGS     colours, fonts, paths, tab names
    2. HELPERS      pure functions: CSV readers, table shaping, chart drawing, the Show Working text
    3. THE APP      class App, in sections:
         window frame, TAB 1 (Encrypt & Decrypt), TAB 2 (Attack), TAB 3 (Efficiency),
         TAB 4 (Design), background jobs, closing
    4. START-UP     main()

The handlers (do_encrypt, do_decrypt, run_attack, ...) do not need a mouse:
the buttons just call them, and the tests call them directly.
"""

import csv
import math
import os
import queue
import random
import threading
import time

# tkinter ships with most Python installs, but not all (some Linux systems
# need a separate "python3-tk" package). If it is missing we do NOT crash
# with a traceback: main() prints one friendly line instead, and the
# window-free helpers in this file can still be imported.
try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import ttk
    TKINTER_ERROR = None
except ImportError as _error:
    tk = ttk = tkfont = None
    TKINTER_ERROR = str(_error)

import attack
import benchmark
import cipher
import explain
import help_text


# ==========================================================================
# ===== SETTINGS (colours, fonts, paths, tab names) =====
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

# The saved results this window READS (the same files attack.py and benchmark.py write).
ATTACK_CSV = attack.RESULTS_PATH
BENCH_CSV = benchmark.RESULTS_PATH
ATTACK_CSV_HELP = "Run python attack.py to create results/attack_results.csv"
SPEED_CSV_HELP = "Run python benchmark.py to create results/benchmark_results.csv"

SAMPLE_MESSAGE = "Defend the east wall of the castle. Meet at dawn, by the old bridge!"
SAMPLE_KEY = "CRYPTOGRAPHY"
SAMPLE_RAILS = 5
DEFAULT_TEST_LENGTH = 500          # the message length the Attack tab starts with
SPEED_HINT = "Median time per message length. Flat custom us/char = O(N)."

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
    TAB_ATTACK: "Ready. Pick a message length and an attack, then press Run attack.",
    TAB_EFFICIENCY: "Ready. Saved results are shown; press Run to measure this computer.",
    TAB_DESIGN: "Ready. This page explains the design.",
}


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


def format_speed_row(row):
    """One Table A row as strings; same decimals as benchmark prints."""
    return [str(row["n"]), f"{row['shift_enc_ms']:.4f}", f"{row['custom_enc_ms']:.4f}",
            f"{row['custom_dec_ms']:.4f}", f"{row['ratio']:.2f}", f"{row['us_per_char']:.4f}"]


def attack_summary(data):
    """Shape the saved attack results into the ONE table the Attack tab shows.

    `data` is what read_attack_csv returns. Table 1 (frequency attack) and
    Table 2 (known-plaintext attack with a fixed crib) have the same message
    lengths, so they are joined on that length. Returns
    {"trials": ..., "crib": ..., "rows": [[N, freq success %, freq ms, KPA success %, KPA ms], ...]}.

    Worked example: Table 1 row N=500 with exact_pct 89.0 and median_ms 22.97, and
    Table 2 row N=500 with 100.0 and 18.08, give  ["500", "89.0", "22.97", "100.0", "18.08"].
    "success %" is the share of trials in which the WHOLE plaintext came back exactly.
    A length missing from Table 2 shows "-".
    """
    known_plaintext = {row["text_length"]: row for row in data["table2"]}
    rows = []
    for freq in data["table1"]:
        kpa = known_plaintext.get(freq["text_length"])
        rows.append([str(freq["text_length"]), f"{freq['exact_pct']:.1f}", f"{freq['median_ms']:.2f}",
                     f"{kpa['exact_pct']:.1f}" if kpa else "-", f"{kpa['median_ms']:.2f}" if kpa else "-"])
    return {"trials": data["table1"][0]["trials"], "crib": data["table2"][0]["crib"], "rows": rows}


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
    # ----- window frame: style, title bar, notebook, status bar -----
    # ----------------------------------------------------------------------

    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.minsize(950, 680)                      # never smaller than this; still resizable
        # Start as big as is comfortable, but never bigger than the screen (a small
        # laptop screen, 1366 x 768, has less room than the 1040 x 740 we would like).
        width = max(950, min(1040, root.winfo_screenwidth() - 40))
        height = max(680, min(740, root.winfo_screenheight() - 80))
        root.geometry(f"{width}x{height}")
        root.configure(bg=BG)

        # State shared by the handlers.
        self._last_op = None                        # the last lock/unlock (for Show Working)
        self._truth = None                          # hidden answer of the current test message
        self._corpus = None                         # the test text, loaded the first time it is needed
        self._speed_results = None                  # results currently shown on the Efficiency tab
        self._chart_series = None
        # Background jobs: a worker thread does the slow work and puts messages
        # on a queue; the main thread reads the queue (never touch tk from a worker).
        self._busy = {"attack": False, "speed": False}
        self._cancel_speed = threading.Event()
        self._queue = queue.Queue()
        # Each tab remembers its own last status message (tab number -> (message, kind)),
        # so the bar shows the right words when you come back to a tab.
        self._status_memory = {tab: (message, "info") for tab, message in READY_MESSAGES.items()}

        self._build_style()
        self._build_title_bar()
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

    def _build_title_bar(self):
        bar = tk.Frame(self.root, bg=BG)
        bar.pack(side="top", fill="x", padx=12, pady=(8, 2))
        tk.Label(bar, text="Vigenere + Rail Fence", font=FONT_TITLE, bg=BG, fg=TEXT).pack(side="left")
        tk.Label(bar, text="  two-stage classical cipher", font=FONT_LABEL, bg=BG, fg=MUTED).pack(side="left")

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
        builders = [self._build_lock_tab, self._build_attack_tab, self._build_speed_tab, self._build_design_tab]
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
        """Called whenever another tab is opened: refresh what that tab shows from the saved files."""
        tab = self._current_tab()
        if tab == TAB_ATTACK:
            self.load_saved_attack_results()                # re-read, so a fresh python attack.py shows up
        elif tab == TAB_EFFICIENCY and self._speed_results is None:
            self.load_saved_speed_results()                 # first visit; a quick run is not wiped by later visits
        elif tab == TAB_DESIGN:
            self.refresh_design()
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
    # ----- TAB 1: REQ 2 - ENCRYPT & DECRYPT -----
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
        self.key_var.trace_add("write", self._update_key_counter)
        self._update_key_counter()

        # --- Row 2: buttons ---
        buttons = ttk.Frame(tab)
        buttons.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        ttk.Button(buttons, text="Lock (encrypt)", style="Go.TButton", command=self.do_encrypt).pack(side="left")
        ttk.Button(buttons, text="Unlock (decrypt)", style="Go.TButton", command=self.do_decrypt).pack(side="left", padx=8)
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
    # ----- TAB 2: REQ 3 / DELIVERABLE 2 - ATTACK -----
    # ----------------------------------------------------------------------
    # One page, two parts: "Try an attack" on a fresh random test message,
    # and a table of the SAVED experiment results (read from results/attack_results.csv).

    def _build_attack_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(1, weight=1)
        self._build_try_an_attack(tab)
        self._build_saved_attack_table(tab)

    def _build_try_an_attack(self, tab):
        top = ttk.LabelFrame(tab, text="Try an attack", padding=8)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(0, weight=1, uniform="a")
        top.columnconfigure(1, weight=1, uniform="a")

        # --- Left side: choices ---
        left = ttk.Frame(top)
        left.grid(row=0, column=0, sticky="nw", padx=(0, 10))
        tk.Label(left, text="Message length (letters):", bg=BG, font=FONT_LABEL).grid(row=0, column=0, sticky="w")
        self.n_var = tk.StringVar(value=str(DEFAULT_TEST_LENGTH))
        self.n_combo = ttk.Combobox(left, textvariable=self.n_var, values=[str(n) for n in attack.TEXT_LENGTHS],
                                    state="readonly", width=8)
        self.n_combo.grid(row=0, column=1, sticky="w", padx=6)
        tk.Label(left, text="Random text, key and rails; the answer stays hidden.", bg=BG, fg=MUTED,
                 font=FONT_SMALL).grid(row=1, column=0, columnspan=2, sticky="w")
        self.attack_var = tk.StringVar(value="freq")
        ttk.Radiobutton(left, text="Frequency attack (ciphertext only)", variable=self.attack_var,
                        value="freq").grid(row=2, column=0, columnspan=2, sticky="w", pady=(6, 0))
        ttk.Radiobutton(left, text="Known-plaintext attack (needs a crib)", variable=self.attack_var,
                        value="kpa").grid(row=3, column=0, columnspan=2, sticky="w")
        # The crib size only matters for the known-plaintext attack, so it is greyed out otherwise.
        self.crib_label = tk.Label(left, text="    Crib size (known first letters):", bg=BG, font=FONT_LABEL)
        self.crib_label.grid(row=4, column=0, sticky="w")
        self.crib_size_var = tk.StringVar(value=str(attack.DEFAULT_CRIB))
        self.crib_spin = ttk.Spinbox(left, from_=10, to=40, width=5, textvariable=self.crib_size_var, wrap=False)
        self.crib_spin.grid(row=4, column=1, sticky="w", padx=6)
        self.attack_var.trace_add("write", self._update_crib_state)
        self._update_crib_state()

        run = ttk.Frame(left)
        run.grid(row=5, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self.attack_button = ttk.Button(run, text="Run attack", style="Go.TButton", command=self.run_attack)
        self.attack_button.pack(side="left")
        self.attack_bar = ttk.Progressbar(run, mode="indeterminate", length=140)
        self.attack_bar.pack(side="left", padx=10)
        self.attack_inline_var = tk.StringVar()
        tk.Label(left, textvariable=self.attack_inline_var, bg=BG, fg=RED, font=FONT_BOLD, anchor="w",
                 wraplength=400, justify="left").grid(row=6, column=0, columnspan=2, sticky="w")

        # --- Right side: the result ---
        right = ttk.Frame(top)
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(1, weight=1)
        self.result_vars = {}
        # Four small facts in a 2 x 2 block (short enough to fit the smallest window), then the key on its own row.
        facts = ttk.Frame(right)
        facts.grid(row=0, column=0, columnspan=2, sticky="w")
        for index, (key, label) in enumerate([("rails", "Rails found:"), ("length", "Key length:"),
                                              ("guesses", "Guesses:"), ("time", "Time:")]):
            row, column = divmod(index, 2)
            tk.Label(facts, text=label, bg=BG, font=FONT_BOLD).grid(row=row, column=2 * column, sticky="w",
                                                                    padx=(0 if column == 0 else 24, 3))
            self.result_vars[key] = tk.StringVar(value="-")
            tk.Label(facts, textvariable=self.result_vars[key], bg=BG, font=FONT_MONO
                     ).grid(row=row, column=2 * column + 1, sticky="w")
        tk.Label(right, text="Key found:", bg=BG, font=FONT_BOLD).grid(row=1, column=0, sticky="w")
        self.result_vars["key"] = tk.StringVar(value="-")
        tk.Label(right, textvariable=self.result_vars["key"], bg=BG, font=FONT_MONO, anchor="w"
                 ).grid(row=1, column=1, sticky="w", padx=8)
        tk.Label(right, text="Recovered plaintext (first 300 letters):", bg=BG, font=FONT_BOLD,
                 anchor="w").grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        frame, self.recovered_text = self._make_box(right, NEUTRAL_BG, 3)
        frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        verdict = ttk.Frame(right)
        verdict.grid(row=4, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self.correct_var = tk.StringVar()
        self.correct_label = tk.Label(verdict, textvariable=self.correct_var, bg=BG, font=FONT_BOLD, anchor="w")
        self.correct_label.pack(side="left")
        self.reveal_button = ttk.Button(verdict, text="Reveal truth", command=self.reveal_truth, state="disabled")
        self.reveal_button.pack(side="right")
        self.truth_var = tk.StringVar()
        tk.Label(right, textvariable=self.truth_var, bg=BG, fg=TEXT, font=FONT_SMALL, anchor="w",
                 justify="left", wraplength=430).grid(row=5, column=0, columnspan=2, sticky="w")

    def _update_crib_state(self, *_args):
        """Grey out the crib size unless the known-plaintext attack is chosen."""
        needed = self.attack_var.get() == "kpa"
        self.crib_spin.configure(state="normal" if needed else "disabled")
        self.crib_label.configure(fg=TEXT if needed else MUTED)

    def _build_saved_attack_table(self, tab):
        self.attack_table_frame = ttk.LabelFrame(tab, text="Saved experiment results", padding=8)
        self.attack_table_frame.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.attack_table_frame.columnconfigure(0, weight=1)
        # ONE line of text above the table: grey normally, red with the friendly message if the file is missing.
        self.attack_note_var = tk.StringVar()
        self.attack_note_label = tk.Label(self.attack_table_frame, textvariable=self.attack_note_var, bg=BG,
                                          fg=MUTED, font=FONT_SMALL, anchor="w")
        self.attack_note_label.grid(row=0, column=0, sticky="ew")
        self.attack_table = ttk.Treeview(self.attack_table_frame, show="headings", height=len(attack.TEXT_LENGTHS),
                                         columns=("n", "freq", "freq_ms", "kpa", "kpa_ms"))
        for column, width in (("n", 80), ("freq", 190), ("freq_ms", 170), ("kpa", 260), ("kpa_ms", 190)):
            self.attack_table.column(column, width=width, anchor="e")
        self._set_attack_headings(attack.DEFAULT_CRIB)
        self.attack_table.grid(row=1, column=0, sticky="ew")

    def _set_attack_headings(self, crib):
        for column, text in (("n", "Length N"), ("freq", "Frequency: success %"), ("freq_ms", "Frequency: time (ms)"),
                             ("kpa", f"Known-plaintext (crib {crib}): success %"), ("kpa_ms", "Known-plaintext: time (ms)")):
            self.attack_table.heading(column, text=text)

    def _attack_table_say(self, text, error=False):
        self.attack_note_var.set(text)
        self.attack_note_label.configure(fg=RED if error else MUTED)

    def load_saved_attack_results(self, path=None):
        """Fill the table from results/attack_results.csv. Returns the table data, or None if it cannot be read.

        A missing or damaged file gives a friendly red line and an empty table, never a crash.
        """
        path = path or ATTACK_CSV
        self.attack_table.delete(*self.attack_table.get_children())
        try:
            data = read_attack_csv(path)
        except FileNotFoundError:
            self.attack_table_frame.configure(text="Saved experiment results")
            self._attack_table_say(ATTACK_CSV_HELP, error=True)
            return None
        except ValueError as error:
            self.attack_table_frame.configure(text="Saved experiment results")
            self._attack_table_say(str(error), error=True)
            return None
        summary = attack_summary(data)
        self.attack_table_frame.configure(
            text=f"Saved experiment results ({summary['trials']} trials per row, median time)")
        self._attack_table_say("Success % = the whole plaintext was recovered exactly. Read from results/attack_results.csv.")
        self._set_attack_headings(summary["crib"])
        for row in summary["rows"]:
            self.attack_table.insert("", "end", values=row)
        return data

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
        """Start the chosen attack on a fresh random test message, in a background thread (the window stays responsive)."""
        if self._busy["attack"]:
            return False
        self.attack_inline_var.set("")
        self._clear_attack_result()
        which = self.attack_var.get()
        try:
            n = int(self.n_var.get())
            crib_size = int(self.crib_size_var.get().strip()) if which == "kpa" else 0
        except ValueError:
            self.attack_inline_var.set("The message length and the crib size must be whole numbers.")
            return False
        if which == "kpa" and not 10 <= crib_size <= 40:
            self.attack_inline_var.set("The crib size must be between 10 and 40.")
            return False
        corpus = self._get_corpus()
        if corpus is None:
            self.attack_inline_var.set("The test text (data/corpus.txt) was not found, so a test message "
                                       "cannot be made.")
            return False
        plaintext, key, rails, ciphertext = attack._make_trial(random.Random(), corpus, n)
        self._truth = {"plaintext": plaintext, "key": key, "rails": rails}
        crib = plaintext[:crib_size]                # only the known-plaintext attack looks at it
        self._attack_label = f"Test message of {n} letters"
        self.attack_button.configure(state="disabled")
        self.attack_bar.start(12)
        self.set_status(f"{self._attack_label}: attack running ...", "info", TAB_ATTACK)
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
        accuracy = letter_accuracy(self._truth["plaintext"], found["plaintext"])
        correct = found["plaintext"] == self._truth["plaintext"]
        self.correct_var.set(f"Correct: {'yes' if correct else 'no'}   (letters right: {accuracy * 100:.1f} %)")
        self.correct_label.configure(fg=GREEN if correct else RED)
        self.reveal_button.configure(state="normal")
        self.set_status(f"{self._attack_label}: attack finished in {ms:.2f} ms. Press Reveal truth to compare.",
                        "ok", TAB_ATTACK)

    def reveal_truth(self):
        """Show the hidden key, rails and the start of the real message (one line)."""
        if self._truth is None:
            return False
        t = self._truth
        self.truth_var.set(f"True rails: {t['rails']}   True key: {t['key']} ({len(t['key'])} letters)\n"
                           f"Message starts: {t['plaintext'][:40]}")
        return True

    # ----------------------------------------------------------------------
    # ----- TAB 3: REQ 4 - EFFICIENCY -----
    # ----------------------------------------------------------------------
    # The saved timing table and charts appear when the tab is opened. Run measures THIS computer
    # (quick settings only: messages up to 10,000 letters), with a progress bar and Cancel.

    def _build_speed_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        tab.columnconfigure(1, weight=1)
        controls = ttk.Frame(tab)
        controls.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.speed_run = ttk.Button(controls, text="Run", style="Go.TButton", command=self.run_speed_test)
        self.speed_run.pack(side="left")
        self.speed_cancel = ttk.Button(controls, text="Cancel", command=self.cancel_speed_test, state="disabled")
        self.speed_cancel.pack(side="left", padx=8)
        self.speed_bar = ttk.Progressbar(controls, mode="determinate", length=160,
                                         maximum=benchmark.count_cells(benchmark.QUICK_SETTINGS))
        self.speed_bar.pack(side="left", padx=10)
        # Where the table below comes from: the saved file, or a quick run just made on this computer.
        self.speed_source_var = tk.StringVar()
        tk.Label(controls, textvariable=self.speed_source_var, bg=BG, fg=MUTED, font=FONT_SMALL
                 ).pack(side="right")

        # ONE hint line under the buttons; it turns into a red message when something is wrong.
        self.speed_note_var = tk.StringVar(value=SPEED_HINT)
        self.speed_note_label = tk.Label(tab, textvariable=self.speed_note_var, bg=BG, font=FONT_SMALL, fg=MUTED,
                                         anchor="w")
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
        self._redraw_charts()

    def _speed_say(self, text, error=False):
        """Show one line on the Efficiency tab: grey normally, red for an error."""
        self.speed_note_var.set(text)
        self.speed_note_label.configure(fg=RED if error else MUTED)

    def run_speed_test(self):
        """Run the QUICK benchmark in a background thread, with progress and Cancel."""
        if self._busy["speed"]:
            return False
        self._cancel_speed.clear()
        self.speed_run.configure(state="disabled")
        self.speed_cancel.configure(state="normal")
        self.speed_bar.configure(value=0)
        self._speed_say("working ...")
        self.set_status("Running the quick speed test. Please leave the computer alone for the best numbers.",
                        "info", TAB_EFFICIENCY)

        def progress(done, total):
            # Runs in the worker thread: report, then stop if the user pressed Cancel.
            self._queue.put(("speed", "progress", (done, total)))
            if self._cancel_speed.is_set():
                raise benchmark.CancelledError()

        return self._start_job("speed", lambda: benchmark.run_benchmarks(benchmark.QUICK_SETTINGS, progress=progress))

    def cancel_speed_test(self):
        if self._busy["speed"]:
            self._cancel_speed.set()
            self.speed_cancel.configure(state="disabled")
            self._speed_say("cancelling ...")
            return True
        return False

    def _on_speed_progress(self, payload):
        done, total = payload
        self.speed_bar.configure(maximum=total, value=done)
        self._speed_say(f"{done} of {total} measurements done")

    def _on_speed_done(self, results):
        self._show_speed_results(results, "Quick run on this computer (not saved)")
        self._speed_finished()
        self.set_status("Quick speed test finished (shown above, not saved).", "ok", TAB_EFFICIENCY)

    def _speed_finished(self, error=None):
        """Buttons back to normal; the hint line returns (or shows `error` in red)."""
        self.speed_run.configure(state="normal")
        self.speed_cancel.configure(state="disabled")
        if error:
            self._speed_say(error, error=True)
        else:
            self._speed_say(SPEED_HINT)

    def load_saved_speed_results(self, path=None):
        """Show results/benchmark_results.csv. Returns the data, or None (with a friendly red line) if it cannot be read."""
        path = path or BENCH_CSV
        try:
            data = read_benchmark_csv(path)
        except FileNotFoundError:
            self._speed_say(SPEED_CSV_HELP, True)
            return None
        except ValueError as error:
            self._speed_say(str(error), True)
            return None
        self._show_speed_results(data, "Saved results: results/benchmark_results.csv")
        self._speed_say(SPEED_HINT)
        return data

    def _show_speed_results(self, data, source):
        """Fill the table and the two charts from `data` (it needs a "table_a" list)."""
        self._speed_results = data
        self.speed_source_var.set(source)
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

    def _redraw_charts(self):
        series = self._chart_series or {"time": [], "per_char": []}
        draw_line_chart(self.chart_time, "Time to lock a message", "message length N (letters)",
                        "time (ms)", series["time"])
        draw_line_chart(self.chart_per_char, "Microseconds per character", "message length N (letters)",
                        "us per character", series["per_char"])

    # ----------------------------------------------------------------------
    # ----- TAB 4: REQ 1 / DELIVERABLE 1 - DESIGN -----
    # ----------------------------------------------------------------------
    # One screen, no scrolling. The words come from help_text.design_lines: the two worked
    # examples are run through cipher.py every time (a red warning replaces one that disagrees),
    # and the speed and attack numbers are read from the saved result files.

    DESIGN_LOOK = {          # style name -> (font, text colour, background)
        "title": (FONT_TITLE, TEXT, BG),
        "stage1": (FONT_BOLD, STAGE1_FG, STAGE1_BG),
        "stage2": (FONT_BOLD, STAGE2_FG, STAGE2_BG),
        "example": (FONT_MONO, TEXT, PANEL),
        "body": (FONT_LABEL, TEXT, BG),
        "warning": (FONT_BOLD, RED, BG),
    }

    def _build_design_tab(self, tab):
        tab.columnconfigure(0, weight=1)
        self.design_frame = tk.Frame(tab, bg=BG)
        self.design_frame.grid(row=0, column=0, sticky="nsew")
        self.design_frame.columnconfigure(0, weight=1)
        # Wrap every line to the width of the window.
        self.design_frame.bind("<Configure>", self._wrap_design_lines)
        self.refresh_design()

    def _wrap_design_lines(self, _event=None):
        width = max(300, self.design_frame.winfo_width() - 24)
        for label in self.design_frame.winfo_children():
            label.configure(wraplength=width)

    def refresh_design(self):
        """(Re)build the page. Numbers are read from the CSV files each time; examples are re-checked."""
        try:
            attack_data = read_attack_csv()
        except (OSError, ValueError):
            attack_data = None                      # missing/unreadable: the page says so
        try:
            speed_data = read_benchmark_csv()
        except (OSError, ValueError):
            speed_data = None
        for old in self.design_frame.winfo_children():
            old.destroy()
        for row, (style, text) in enumerate(help_text.design_lines(attack_data, speed_data)):
            font, colour, background = self.DESIGN_LOOK[style]
            tk.Label(self.design_frame, text=text, font=font, fg=colour, bg=background, anchor="w", justify="left",
                     padx=8, pady=3 if style != "title" else 0).grid(row=row, column=0, sticky="ew", pady=(2, 0))
        self._wrap_design_lines()

    def design_content(self):
        """All the text on the Design page, one line per row (used by the tests)."""
        return "\n".join(label.cget("text") for label in self.design_frame.winfo_children())

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
        except benchmark.CancelledError:
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
        """Show a worker's message. job is "attack" or "speed"; kind is progress, done, cancelled or error."""
        if kind == "progress":
            self._on_speed_progress(payload)                # only the speed test reports progress
        elif kind == "done":
            {"attack": self._on_attack_done, "speed": self._on_speed_done}[job](payload)
        elif kind == "cancelled":                           # only the speed test can be cancelled
            self._speed_finished()
            self.set_status("Cancelled. Nothing was changed.", "info", TAB_EFFICIENCY)
        elif kind == "error":
            if job == "attack":
                self.attack_bar.stop()
                self.attack_button.configure(state="normal")
                self.attack_inline_var.set(payload)
            else:
                self._speed_finished(f"Stopped by an error: {payload}")
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
        self._cancel_speed.set()                     # ask a running speed test to stop at its next checkpoint
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
