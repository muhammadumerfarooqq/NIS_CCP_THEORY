"""Benchmarks and complexity evidence for the two-stage cipher.

This file measures how long the cipher takes and how much memory it uses, for
messages of many different lengths, and then checks whether the growth looks
like O(N) ("linear": double the message, double the time).

What is measured
----------------
Table A   main table: Shift cipher vs the two-stage (custom) cipher, N from 100
          to 100,000 letters. A flat "microseconds per character" column is
          the evidence for O(N).
Table B   where the time goes at N = 10,000: Shift, Vigenere alone, Rail Fence
          alone, and the custom cipher in total.
Table C   parameters do not change the big-O: rails 2..10, and key length
          10..100.
Fits      for the Table A timings: a straight line time = a*N + b with its
          R-squared, and the log-log slope. A slope near 1.0 means linear.
Memory    peak memory (tracemalloc) for Shift and custom encryption.

How the timing is done (so the numbers can be trusted)
------------------------------------------------------
* time.perf_counter, the most precise clock Python offers.
* Garbage collection is switched off while timing, so a random clean-up does
  not land in the middle of a measurement.
* One warm-up call first (the very first call is often slower), then R
  repeats. We report the MEDIAN and the interquartile range (IQR).
* Before timing each size we check that decrypt(encrypt(x)) == x. If not, the
  program aborts loudly: a fast but wrong cipher is worthless.

Timings depend on this machine (CPU, Python version, what else is running).
Only the shape of the growth and the relative sizes are meaningful.

Usage
-----
    python benchmark.py            everything; writes results/benchmark_results.csv
    python benchmark.py --quick    far fewer repeats, sizes up to 10,000;
                                   writes results/benchmark_results_quick.csv
                                   (ignored by git)

Standard library only.

How to read this file (top to bottom):
    1. SETTINGS              sizes, repeat budgets, constants
    2. MATHS HELPERS         straight-line fit, log-log slope, the verdict
    3. TIMING AND MEMORY     how one measurement is made
    4. INPUTS AND SAFETY     test data and the round-trip check
    5. THE BENCHMARKS        Tables A, B, C, the fits, the memory test
    6. OUTPUT                tables, CSV file and the command line
"""

import argparse
import csv
import gc
import math
import os
import platform
import random
import statistics
import string
import time
import tracemalloc
from functools import partial

import cipher


# ==========================================================================
# ===== SETTINGS (sizes, repeat budgets, constants) =====
# ==========================================================================

SEED = 486                  # same seed as the rest of the project
DEFAULT_KEY_LENGTH = 12     # key used unless a table varies it
DEFAULT_RAILS = 4           # rails used unless a table varies it
SHIFT_AMOUNT = 7            # the Shift cipher's single number, e.g. 7: A -> H

# A log-log slope in this range is called "linear". Fixed up front.
LINEAR_SLOPE_LOW = 0.85
LINEAR_SLOPE_HIGH = 1.15

# Each setting block says how big to go and how long to spend per measurement.
#   budget_s     : aim to spend about this many seconds on each measurement
#   min/max_repeats : never fewer / more repeats than this
# The number of repeats R is chosen from the warm-up call: if one call takes
# 2 ms and the budget is 1 s, we do about 500 repeats. Small N -> many repeats,
# big N -> few, so every measurement costs about the same wall-clock time.
FULL_SETTINGS = {
    "name": "full",
    "sizes": [100, 1000, 5000, 10000, 50000, 100000],   # Table A
    "table_b_n": 10000,                                 # Table B
    "table_c_n": 10000,                                 # Table C
    "key_lengths": [10, 20, 50, 100],                   # Table C (key part)
    "memory_sizes": [10000, 100000],                    # memory test
    "budget_s": 1.0,
    "min_repeats": 5,
    "max_repeats": 2000,
}
QUICK_SETTINGS = {
    "name": "quick",
    "sizes": [100, 1000, 5000, 10000],
    "table_b_n": 10000,
    "table_c_n": 10000,
    "key_lengths": [10, 20, 50, 100],
    "memory_sizes": [1000, 10000],
    "budget_s": 0.05,
    "min_repeats": 3,
    "max_repeats": 50,
}

_ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS_PATH = os.path.join(_ROOT, "results", "benchmark_results.csv")
# --quick writes here; this file is git-ignored.
RESULTS_PATH_QUICK = os.path.join(_ROOT, "results", "benchmark_results_quick.csv")


class RoundTripError(RuntimeError):
    """Raised when decrypt(encrypt(x)) != x, so the benchmark must stop."""


class CancelledError(Exception):
    """Raised by a progress callback to stop run_benchmarks early.

    The GUI's Cancel button works like this: the callback notices the user
    pressed Cancel and raises CancelledError; nothing in this file catches it,
    so it travels up to whoever started the run.
    """


# ==========================================================================
# ===== MATHS HELPERS (straight-line fit, log-log slope, the verdict) =====
# ==========================================================================

def linear_fit(xs, ys):
    """Least-squares straight line  y = slope * x + intercept.  Returns
    (slope, intercept, r_squared).

    Worked example: points (1, 3), (2, 5), (3, 7) lie exactly on y = 2x + 1,
    so slope = 2, intercept = 1 and R-squared = 1.0 (a perfect fit).
    R-squared says how well a straight line explains the data: 1.0 = perfectly,
    near 0 = not at all.

    Time complexity: O(n) for n points.
    """
    n = len(xs)
    if n != len(ys) or n < 2:
        raise ValueError("linear_fit needs at least two (x, y) pairs of equal length")
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    # How spread out the x values are, and how x and y move together.
    sxx = sum((x - mean_x) ** 2 for x in xs)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    if sxx == 0:
        raise ValueError("linear_fit needs at least two different x values")
    # The best-fit line passes through the means (mean_x, mean_y).
    slope = sxy / sxx
    intercept = mean_y - slope * mean_x
    # R-squared = 1 - (leftover error) / (total variation in y).
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    ss_tot = sum((y - mean_y) ** 2 for y in ys)
    r_squared = 1.0 if ss_tot == 0 else 1.0 - ss_res / ss_tot
    return slope, intercept, r_squared


def loglog_slope(xs, ys):
    """Slope of log(y) against log(x): the growth exponent.

    If y = c * x**p then log(y) = log(c) + p * log(x), a straight line whose
    slope is p. So:
        p = 1  -> linear      (double x, double y)
        p = 2  -> quadratic   (double x, quadruple y)
        p < 1  -> slower than linear (a fixed cost dominates)
    Worked example: y = 3x gives slope exactly 1.0.

    Time complexity: O(n) for n points.
    """
    slope, _, _ = linear_fit([math.log(x) for x in xs], [math.log(y) for y in ys])
    return slope


def classify_slope(slope):
    """Turn a growth exponent into a label. Never hard-coded to 'linear':
    it is decided from the number each time.

        0.85 <= slope <= 1.15  -> "linear"
        slope < 0.85           -> "sub-linear"
        slope > 1.15           -> "super-linear"
    """
    if slope < LINEAR_SLOPE_LOW:
        return "sub-linear"
    if slope > LINEAR_SLOPE_HIGH:
        return "super-linear"
    return "linear"


def describe_slope(slope, quantity="time"):
    """A plain-English sentence for a growth exponent.

    `quantity` is what is growing: "time" for the timing fits, "memory" for the
    memory test. Worked example: describe_slope(1.0) ->
    "linear (slope 1.000): doubling N roughly doubles the time, which is O(N)".
    """
    label = classify_slope(slope)
    if label == "linear":
        meaning = f"doubling N roughly doubles the {quantity}, which is O(N)"
    elif label == "sub-linear":
        meaning = f"the {quantity} grows more slowly than N here (a fixed cost still matters at these sizes)"
    else:
        meaning = f"the {quantity} grows faster than N here, which is worse than O(N)"
    return f"{label} (slope {slope:.3f}): {meaning}"


# ==========================================================================
# ===== TIMING AND MEMORY (how one measurement is made) =====
# ==========================================================================

def summarise(samples):
    """Median and interquartile range (IQR) of a list of timings.

    The median is the middle value, so one slow outlier cannot ruin it.
    The IQR is the spread of the middle half of the values: (75th percentile
    minus 25th percentile). A small IQR means the measurement was steady.
    Worked example: [1, 2, 3, 4, 100] has median 3; the 100 does not matter.
    """
    median = statistics.median(samples)
    if len(samples) < 2:
        return median, 0.0
    # quantiles(..., n=4) returns the three quartile cut points [Q1, Q2, Q3].
    q = statistics.quantiles(samples, n=4, method="inclusive")
    return median, q[2] - q[0]


def measure(func, settings):
    """Time func() and return {"median_ms", "iqr_ms", "repeats"}.

    Steps: warm-up call (also tells us how long one call takes) -> pick the
    number of repeats R so the whole thing costs about budget_s seconds ->
    time R calls one by one -> summarise. Garbage collection is off while we
    time, and is put back afterwards exactly as we found it.
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        # Warm-up: run once and note how long it took (in seconds).
        start = time.perf_counter()
        func()
        one_call = time.perf_counter() - start
        # R = budget / one call, kept between min_repeats and max_repeats.
        # Example: budget 1.0 s, one call 2 ms -> 1.0 / 0.002 = 500 repeats.
        wanted = int(settings["budget_s"] / one_call) if one_call > 0 else settings["max_repeats"]
        repeats = max(settings["min_repeats"], min(settings["max_repeats"], wanted))
        samples = []
        for _ in range(repeats):
            start = time.perf_counter()
            func()
            samples.append((time.perf_counter() - start) * 1000)  # seconds -> ms
    finally:
        if was_enabled:
            gc.enable()
    median, iqr = summarise(samples)
    return {"median_ms": median, "iqr_ms": iqr, "repeats": repeats}


def measure_peak_kb(func):
    """Peak extra memory (in KB) that Python allocates while func() runs.

    tracemalloc watches Python's own allocations. We start it just before the
    call, so the input text (made earlier) is not counted, only what the
    function itself builds: lists, joined strings, the result. This slows the
    code down, so we never time and trace at the same moment.
    """
    tracemalloc.start()
    try:
        func()
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return peak_bytes / 1024


# ==========================================================================
# ===== INPUTS AND SAFETY (test data and the round-trip check) =====
# ==========================================================================

def make_inputs(n, key_length=DEFAULT_KEY_LENGTH, seed=SEED):
    """Seeded random test data: (plaintext of n capitals, key of key_length capitals).

    The key is drawn first, so for the same seed and key_length it is the same
    key for every n. Worked example: make_inputs(5, 12) -> ("QZMAT", "<12 letters>").
    """
    rng = random.Random(seed)
    key = "".join(rng.choices(string.ascii_uppercase, k=key_length))
    text = "".join(rng.choices(string.ascii_uppercase, k=n))
    return text, key


def verify_round_trip(text, key, rails, custom_encrypt=None, custom_decrypt=None,
                      shift_encrypt=None, shift_decrypt=None):
    """Abort loudly (RoundTripError) unless decrypting an encryption gives back
    the original text, for both the custom cipher and the Shift cipher.

    The four function arguments default to the real cipher functions; they can
    be replaced (the tests pass a deliberately broken one to see the abort).
    """
    custom_encrypt = custom_encrypt or cipher.custom_encrypt
    custom_decrypt = custom_decrypt or cipher.custom_decrypt
    shift_encrypt = shift_encrypt or cipher.shift_encrypt
    shift_decrypt = shift_decrypt or cipher.shift_decrypt

    # custom_encrypt returns (stage1, final); only `final` is the ciphertext.
    _, final = custom_encrypt(text, key, rails)
    if custom_decrypt(final, key, rails) != text:
        raise RoundTripError(
            f"custom cipher round trip FAILED (n={len(text)}, key length={len(key)}, rails={rails})")
    if shift_decrypt(shift_encrypt(text, SHIFT_AMOUNT), SHIFT_AMOUNT) != text:
        raise RoundTripError(f"shift cipher round trip FAILED (n={len(text)})")


# ==========================================================================
# ===== THE BENCHMARKS (Tables A, B, C, the fits, the memory test) =====
# ==========================================================================

def run_table_a(settings, tick=None):
    """Table A: Shift vs custom cipher over the message sizes.

    tick (optional): a function with no arguments, called after each finished
    measurement (used for progress reporting).
    """
    rows = []
    for n in settings["sizes"]:
        text, key = make_inputs(n)
        verify_round_trip(text, key, DEFAULT_RAILS)       # stop if anything is broken
        _, final = cipher.custom_encrypt(text, key, DEFAULT_RAILS)

        # partial(f, a, b) is "f with a and b already filled in": a function
        # of no arguments that measure() can call over and over.
        shift_enc = measure(partial(cipher.shift_encrypt, text, SHIFT_AMOUNT), settings)
        if tick is not None:
            tick()
        custom_enc = measure(partial(cipher.custom_encrypt, text, key, DEFAULT_RAILS), settings)
        if tick is not None:
            tick()
        custom_dec = measure(partial(cipher.custom_decrypt, final, key, DEFAULT_RAILS), settings)
        if tick is not None:
            tick()

        rows.append({
            "n": n,
            "shift_enc_ms": shift_enc["median_ms"],
            "custom_enc_ms": custom_enc["median_ms"],
            "custom_dec_ms": custom_dec["median_ms"],
            # How many times slower the two-stage cipher is than Shift.
            # Example: custom 3.0 ms, shift 0.6 ms -> ratio 5.0.
            "ratio": custom_enc["median_ms"] / shift_enc["median_ms"],
            # ms -> microseconds is x 1000; divide by n for "per character".
            # Example: 7 ms for 10,000 letters = 7000 us / 10,000 = 0.7 us each.
            "us_per_char": custom_enc["median_ms"] * 1000 / n,
            "shift_enc_iqr": shift_enc["iqr_ms"],
            "custom_enc_iqr": custom_enc["iqr_ms"],
            "custom_dec_iqr": custom_dec["iqr_ms"],
            "shift_enc_repeats": shift_enc["repeats"],
            "custom_enc_repeats": custom_enc["repeats"],
            "custom_dec_repeats": custom_dec["repeats"],
        })
    return rows


def run_table_b(settings, tick=None):
    """Table B: where the time goes (Shift, Vigenere, Rail Fence, whole cipher)."""
    n = settings["table_b_n"]
    text, key = make_inputs(n)
    verify_round_trip(text, key, DEFAULT_RAILS)
    jobs = [
        ("Shift enc", partial(cipher.shift_encrypt, text, SHIFT_AMOUNT)),
        ("Vigenere enc (Stage 1 alone)", partial(cipher.vigenere_encrypt, text, key)),
        ("Rail Fence enc (Stage 2 alone)", partial(cipher.rail_encrypt, text, DEFAULT_RAILS)),
        ("Custom enc (total)", partial(cipher.custom_encrypt, text, key, DEFAULT_RAILS)),
    ]
    rows = []
    for name, func in jobs:
        result = measure(func, settings)
        if tick is not None:
            tick()
        rows.append({"operation": name, "n": n, **result})
    # Each operation as a percentage of the custom total (the last row), e.g.
    # Vigenere 3 ms of a 7 ms total = 43 %. Shift is not part of the custom
    # cipher; its percentage is just a comparison with it.
    total = rows[-1]["median_ms"]
    for row in rows:
        row["share_pct"] = 100 * row["median_ms"] / total
    return rows


def run_table_c(settings, tick=None):
    """Table C: rails 2..10 (fixed key) and key length (fixed rails)."""
    n = settings["table_c_n"]
    rails_rows, key_rows = [], []

    # Part 1: change the number of rails, keep the 12-letter key.
    text, key = make_inputs(n)
    for rails in range(cipher.MIN_RAILS, cipher.MAX_RAILS + 1):
        verify_round_trip(text, key, rails)
        result = measure(partial(cipher.custom_encrypt, text, key, rails), settings)
        if tick is not None:
            tick()
        rails_rows.append({"rails": rails, "key_length": len(key), "n": n,
                           "us_per_char": result["median_ms"] * 1000 / n, **result})

    # Part 2: change the key length, keep 4 rails.
    for key_length in settings["key_lengths"]:
        text, key = make_inputs(n, key_length=key_length)
        verify_round_trip(text, key, DEFAULT_RAILS)
        result = measure(partial(cipher.custom_encrypt, text, key, DEFAULT_RAILS), settings)
        if tick is not None:
            tick()
        key_rows.append({"rails": DEFAULT_RAILS, "key_length": key_length, "n": n,
                         "us_per_char": result["median_ms"] * 1000 / n, **result})
    return rails_rows, key_rows


def run_fits(table_a):
    """Complexity check: fit the Table A timings two ways, per cipher operation.

    1. Straight line   time = a*N + b.  If the growth is linear this line fits
       very well (R-squared near 1.0), and 'a' is the cost per character.
    2. Log-log slope.  Plot log(time) against log(N); the slope is the growth
       exponent. About 1.0 means linear.
    """
    sizes = [row["n"] for row in table_a]
    fits = []
    for name, field in (("Shift enc", "shift_enc_ms"),
                        ("Custom enc", "custom_enc_ms"),
                        ("Custom dec", "custom_dec_ms")):
        times = [row[field] for row in table_a]
        a, b, r_squared = linear_fit(sizes, times)
        slope = loglog_slope(sizes, times)
        fits.append({
            "name": name,
            "a_ms_per_char": a,
            "b_ms": b,
            "r_squared": r_squared,
            "loglog_slope": slope,
            "verdict": describe_slope(slope),   # derived from the slope, not typed in
        })
    return fits


def run_memory(settings, tick=None):
    """Peak memory of Shift and custom encryption (tracemalloc), per size.

    Also reports how the peak grows between the sizes tested: if N grows 10x
    and the peak grows about 10x, memory is O(N) too.
    """
    rows = []
    for n in settings["memory_sizes"]:
        text, key = make_inputs(n)
        jobs = [("Shift enc", partial(cipher.shift_encrypt, text, SHIFT_AMOUNT)),
                ("Custom enc", partial(cipher.custom_encrypt, text, key, DEFAULT_RAILS))]
        for name, func in jobs:
            peak_kb = measure_peak_kb(func)
            if tick is not None:
                tick()
            rows.append({"name": name, "n": n, "peak_kb": peak_kb,
                         "bytes_per_char": peak_kb * 1024 / n})

    # Growth exponent of the peak between the smallest and largest size.
    scaling = []
    sizes = sorted(settings["memory_sizes"])
    if len(sizes) >= 2:
        for name in ("Shift enc", "Custom enc"):
            small = next(r for r in rows if r["name"] == name and r["n"] == sizes[0])
            large = next(r for r in rows if r["name"] == name and r["n"] == sizes[-1])
            slope = math.log(large["peak_kb"] / small["peak_kb"]) / math.log(sizes[-1] / sizes[0])
            scaling.append({"name": name, "from_n": sizes[0], "to_n": sizes[-1],
                            "slope": slope, "verdict": describe_slope(slope, "memory")})
    return rows, scaling


def count_cells(settings):
    """How many measurements ("cells") run_benchmarks will make.

    Worked example (full settings): Table A has 3 per size x 6 sizes = 18,
    Table B has 4, Table C has 9 rails + 4 key lengths = 13, and the memory
    test has 2 per size x 2 sizes = 4, so 18 + 4 + 13 + 4 = 39 in total.
    """
    rails_values = cipher.MAX_RAILS - cipher.MIN_RAILS + 1
    return (3 * len(settings["sizes"]) + 4
            + rails_values + len(settings["key_lengths"])
            + 2 * len(settings["memory_sizes"]))


def run_benchmarks(settings, progress=None):
    """Run everything and return all results in one dict.

    progress (optional): a function progress(done, total) called after each
    finished measurement, e.g. progress(5, 39) = 5 of 39 done. If it raises
    CancelledError the run stops there. With progress=None (the default)
    nothing is called and the behaviour is exactly as before.
    """
    # Build the "tick" that the tables call after each measurement. It counts
    # measurements and reports "done of total" to the caller's function.
    tick = None
    if progress is not None:
        total = count_cells(settings)
        counter = [0]       # a list, so the inner function can change the number

        def tick():
            counter[0] += 1
            progress(counter[0], total)

    table_a = run_table_a(settings, tick)
    table_b = run_table_b(settings, tick)
    table_c_rails, table_c_key = run_table_c(settings, tick)
    fits = run_fits(table_a)
    memory, memory_scaling = run_memory(settings, tick)
    return {"table_a": table_a, "table_b": table_b,
            "table_c_rails": table_c_rails, "table_c_key": table_c_key,
            "fits": fits, "memory": memory, "memory_scaling": memory_scaling}


# ==========================================================================
# ===== OUTPUT (tables, CSV file and the command line) =====
# ==========================================================================

def machine_header(settings):
    """Lines describing the machine, so the numbers can be put in context."""
    return [
        "Benchmark of the Vigenere + Rail Fence cipher",
        f"Python        : {platform.python_version()} ({platform.python_implementation()})",
        f"Operating sys : {platform.platform()}",
        f"CPU           : {platform.processor() or platform.machine()}, {os.cpu_count()} logical CPUs",
        f"Mode          : {settings['name']}",
        "NOTE: timings depend on this machine. Compare shapes and ratios, not absolute values.",
    ]


def format_rows(title, columns, rows):
    """Aligned text table. `columns` is a list of (heading, key, format, width).

    Format codes: ".3f" = 3 decimals, "d" = whole number, "" = text as-is.
    Worked example: ("N", "n", "d", 8) prints the value of row["n"] right-aligned
    in 8 characters.
    """
    heads = " ".join(h.rjust(w) for h, _, _, w in columns)
    lines = [title, heads, "-" * len(heads)]
    for row in rows:
        lines.append(" ".join(format(row[k], f).rjust(w) for _, k, f, w in columns))
    return "\n".join(lines)


def format_report(results):
    """All the tables, as one string (the machine header is printed separately)."""
    out = []

    out.append(format_rows(
        "Table A: Shift vs two-stage cipher (median ms; flat us/char = O(N))",
        [("N", "n", "d", 8), ("Shift enc ms", "shift_enc_ms", ".4f", 13),
         ("Custom enc ms", "custom_enc_ms", ".4f", 14), ("Custom dec ms", "custom_dec_ms", ".4f", 14),
         ("ratio c/s", "ratio", ".2f", 10), ("custom us/char", "us_per_char", ".4f", 15)],
        results["table_a"]) + "\n")

    out.append(format_rows(
        "Table A spread: IQR in ms (steadiness) and number of repeats R",
        [("N", "n", "d", 8), ("Shift IQR", "shift_enc_iqr", ".4f", 11),
         ("CustEnc IQR", "custom_enc_iqr", ".4f", 12), ("CustDec IQR", "custom_dec_iqr", ".4f", 12),
         ("R shift", "shift_enc_repeats", "d", 8), ("R enc", "custom_enc_repeats", "d", 7),
         ("R dec", "custom_dec_repeats", "d", 7)],
        results["table_a"]) + "\n")

    n_b = results["table_b"][0]["n"]
    out.append(format_rows(
        f"Table B: where the time goes, N = {n_b}",
        [("operation", "operation", "", 32), ("median ms", "median_ms", ".4f", 10),
         ("IQR ms", "iqr_ms", ".4f", 9), ("% of custom", "share_pct", ".1f", 12),
         ("R", "repeats", "d", 6)],
        results["table_b"]) + "\n")

    n_c = results["table_c_rails"][0]["n"]
    out.append(format_rows(
        f"Table C1: custom encryption vs number of rails, N = {n_c}, key length 12",
        [("rails", "rails", "d", 6), ("median ms", "median_ms", ".4f", 10),
         ("IQR ms", "iqr_ms", ".4f", 9), ("us/char", "us_per_char", ".4f", 9),
         ("R", "repeats", "d", 6)],
        results["table_c_rails"]) + "\n")
    out.append(format_rows(
        f"Table C2: custom encryption vs key length, N = {n_c}, rails {DEFAULT_RAILS}",
        [("key length", "key_length", "d", 11), ("median ms", "median_ms", ".4f", 10),
         ("IQR ms", "iqr_ms", ".4f", 9), ("us/char", "us_per_char", ".4f", 9),
         ("R", "repeats", "d", 6)],
        results["table_c_key"]) + "\n")

    out.append("Complexity check from Table A (time vs N)")
    out.append("  line: time_ms = a*N + b       log-log: slope of log(time) vs log(N)")
    for fit in results["fits"]:
        out.append(f"  {fit['name']:<11} a = {fit['a_ms_per_char']:.3e} ms/char  b = {fit['b_ms']:+.4f} ms  "
                   f"R^2 = {fit['r_squared']:.5f}  slope = {fit['loglog_slope']:.3f}")
        out.append(f"     verdict: {fit['verdict']}")
    out.append("")

    out.append(format_rows(
        "Memory: peak extra memory while encrypting (tracemalloc)",
        [("operation", "name", "", 12), ("N", "n", "d", 8), ("peak KB", "peak_kb", ".1f", 10),
         ("bytes/char", "bytes_per_char", ".1f", 11)],
        results["memory"]))
    for s in results["memory_scaling"]:
        out.append(f"  {s['name']}: peak memory as N goes {s['from_n']} -> {s['to_n']}: {s['verdict']}")
    return "\n".join(out)


# Every column that can appear in the CSV. The file is "long format": one row
# per measurement, with the columns that do not apply left blank.
CSV_FIELDS = ["table", "case", "n", "rails", "key_length", "repeats", "median_ms", "iqr_ms",
              "ratio", "us_per_char", "share_pct", "a_ms_per_char", "b_ms", "r_squared",
              "loglog_slope", "verdict", "peak_kb", "bytes_per_char"]


def write_csv(results, path):
    """Write all measurements to one CSV file (folder created if missing)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    out = []
    for r in results["table_a"]:
        for case, prefix in (("shift_enc", "shift_enc"), ("custom_enc", "custom_enc"), ("custom_dec", "custom_dec")):
            out.append({"table": "A", "case": case, "n": r["n"], "rails": DEFAULT_RAILS,
                        "key_length": DEFAULT_KEY_LENGTH, "repeats": r[prefix + "_repeats"],
                        "median_ms": r[prefix + "_ms"], "iqr_ms": r[prefix + "_iqr"],
                        "ratio": r["ratio"] if case == "custom_enc" else "",
                        "us_per_char": r[prefix + "_ms"] * 1000 / r["n"]})
    for r in results["table_b"]:
        out.append({"table": "B", "case": r["operation"], "n": r["n"], "rails": DEFAULT_RAILS,
                    "key_length": DEFAULT_KEY_LENGTH, "repeats": r["repeats"],
                    "median_ms": r["median_ms"], "iqr_ms": r["iqr_ms"], "share_pct": r["share_pct"]})
    for table, key in (("C_rails", "table_c_rails"), ("C_key", "table_c_key")):
        for r in results[key]:
            out.append({"table": table, "case": "custom_enc", "n": r["n"], "rails": r["rails"],
                        "key_length": r["key_length"], "repeats": r["repeats"],
                        "median_ms": r["median_ms"], "iqr_ms": r["iqr_ms"],
                        "us_per_char": r["us_per_char"]})
    for f in results["fits"]:
        out.append({"table": "fit", "case": f["name"], "a_ms_per_char": f["a_ms_per_char"],
                    "b_ms": f["b_ms"], "r_squared": f["r_squared"],
                    "loglog_slope": f["loglog_slope"], "verdict": f["verdict"]})
    for r in results["memory"]:
        out.append({"table": "memory", "case": r["name"], "n": r["n"],
                    "peak_kb": r["peak_kb"], "bytes_per_char": r["bytes_per_char"]})
    for s in results["memory_scaling"]:
        out.append({"table": "memory_scaling", "case": s["name"], "loglog_slope": s["slope"],
                    "verdict": s["verdict"]})

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, restval="")
        writer.writeheader()
        writer.writerows(out)
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Benchmarks and complexity evidence.")
    parser.add_argument("--quick", action="store_true",
                        help="far fewer repeats, sizes up to 10000, writes a git-ignored quick CSV")
    args = parser.parse_args(argv)
    settings = QUICK_SETTINGS if args.quick else FULL_SETTINGS

    print("\n".join(machine_header(settings)))
    print("\nRunning benchmarks (this takes a while in full mode) ...\n")
    try:
        results = run_benchmarks(settings)
    except RoundTripError as error:
        # A wrong cipher must never produce timing numbers: stop with an error.
        raise SystemExit(f"ABORT: {error}")

    print(format_report(results), end="\n\n")
    path = RESULTS_PATH_QUICK if args.quick else RESULTS_PATH
    print(f"Results written to {write_csv(results, path)}")


# Run main() only when started directly (python benchmark.py), not when imported.
if __name__ == "__main__":
    main()
