"""Attacks on the two-stage cipher (Vigenere, then Rail Fence), plus experiments.

THREAT MODEL
------------
The attacker knows the algorithm (Vigenere followed by Rail Fence) and has the
ciphertext. The attacker does NOT know the key, the key length or the number
of rails. Therefore every attack function takes ONLY the ciphertext (and, for
the known-plaintext attack, the crib). They never receive the key, the rails
or the key length; a unit test inspects their signatures to enforce this.
The attacker does search the public parameter ranges of the system
(rails 2..10, key length 10..25), because those are part of the algorithm's
specification, not part of the secret.

Attacks
-------
frequency_attack          ciphertext only: Index of Coincidence + chi-squared.
known_plaintext_attack    ciphertext + a crib (the first M plaintext letters).

Usage
-----
    python attack.py            full experiments, 100 trials per cell
    python attack.py --quick    10 trials per cell

Standard library only.
"""

import argparse
import csv
import math
import os
import random
import statistics
import string
import time
from collections import Counter

import cipher

ENGLISH_FREQ = {
    "A": .08167, "B": .01492, "C": .02782, "D": .04253, "E": .12702,
    "F": .02228, "G": .02015, "H": .06094, "I": .06966, "J": .00153,
    "K": .00772, "L": .04025, "M": .02406, "N": .06749, "O": .07507,
    "P": .01929, "Q": .00095, "R": .05987, "S": .06327, "T": .09056,
    "U": .02758, "V": .00978, "W": .02360, "X": .00150, "Y": .01974,
    "Z": .00074,
}
if abs(sum(ENGLISH_FREQ.values()) - 1.0) >= 0.001:
    raise AssertionError("ENGLISH_FREQ must sum to 1.0 (within 0.001)")

_FREQ = [ENGLISH_FREQ[ch] for ch in string.ascii_uppercase]

# Public parameter ranges of the cipher (known to the attacker).
RAIL_RANGE = range(cipher.MIN_RAILS, cipher.MAX_RAILS + 1)
KEY_LENGTH_RANGE = range(cipher.MIN_KEY_LENGTH, 26)

# Two key lengths count as "almost equal" in IC when their average IC is within
# this of the best one. Fixed once, up front; not tuned against results.
IC_TIE_TOLERANCE = 0.005

CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "corpus.txt")
RESULTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "attack_results.csv")

TEXT_LENGTHS = [100, 250, 500, 1000, 2500, 5000]
CRIB_SIZES = [10, 15, 20, 30, 40]
DEFAULT_CRIB = 30
TABLE3_LENGTH = 500


# --------------------------------------------------------------------------
# Statistics helpers
# --------------------------------------------------------------------------

def index_of_coincidence(text):
    """Index of Coincidence: the chance two letters drawn from text are equal.

        IC = sum_i n_i * (n_i - 1) / (N * (N - 1))

    where n_i is the count of letter i (A..Z) and N the text length.
    English prose gives about 0.065; uniformly random letters give about 0.038.
    Returns 0.0 for texts shorter than 2 letters.

    Time complexity: O(N).
    """
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(text).values()) / (n * (n - 1))


def _chi_squared(text):
    """Chi-squared distance of text's letter counts from ENGLISH_FREQ. O(N)."""
    n = len(text)
    if n == 0:
        return math.inf
    counts = Counter(text)
    total = 0.0
    for i, ch in enumerate(string.ascii_uppercase):
        expected = n * _FREQ[i]
        total += (counts.get(ch, 0) - expected) ** 2 / expected
    return total


def _best_shift(column):
    """Shift s (0..25) minimising chi-squared of column decrypted by s.

    Plaintext letter p appears in the ciphertext as p + s, so the expected
    count of ciphertext letter (p + s) is n * freq(p). O(n + 26 * 26).
    """
    n = len(column)
    if n == 0:
        return 0
    counts = [0] * 26
    for ch in column:
        counts[ord(ch) - 65] += 1
    best_shift, best_chi = 0, math.inf
    for s in range(26):
        chi = 0.0
        for p in range(26):
            expected = n * _FREQ[p]
            chi += (counts[(p + s) % 26] - expected) ** 2 / expected
        if chi < best_chi:
            best_shift, best_chi = s, chi
    return best_shift


# --------------------------------------------------------------------------
# Attack result shape
# --------------------------------------------------------------------------

def _failure(message):
    """Result dict for an attack that could not run. Same keys as a success."""
    return {"ok": False, "key": None, "key_length": None, "rails": None,
            "plaintext": None, "guesses": 0, "score": None, "error": message}


def _result(key, rails, plaintext, guesses, score):
    """Result dict for an attack that produced a candidate.

    "ok" means a candidate was produced, not that it is correct: the attacker
    cannot know that. Correctness is judged by the experiments afterwards.
    """
    return {"ok": True, "key": key, "key_length": len(key), "rails": rails,
            "plaintext": plaintext, "guesses": guesses, "score": score,
            "error": None}


def _valid_text(text):
    return isinstance(text, str) and text != "" and text.isascii() and text.isalpha() and text.isupper()


# --------------------------------------------------------------------------
# Attack 1: ciphertext only
# --------------------------------------------------------------------------

def frequency_attack(ciphertext):
    """Ciphertext-only attack: Index of Coincidence + chi-squared.

    For every rails value r in 2..10:
      1. Undo Rail Fence to get a candidate Stage-1 (Vigenere) text.
      2. For each key length L in 10..25, average the Index of Coincidence of
         the L columns (letters i, i+L, i+2L, ...). The right L makes each
         column a single Caesar shift of English, so its IC is high (~0.065).
      3. Take the L with the highest average IC; if several are within
         IC_TIE_TOLERANCE of the best (multiples of the true length), take the
         smallest.
      4. Solve each column independently: the best of 26 shifts by chi-squared
         against ENGLISH_FREQ. The shifts spell the candidate key.
      5. Decrypt and score the whole text by chi-squared against ENGLISH_FREQ.
    The r whose decrypted text scores lowest wins (ties go to the smaller r).

    Returns a dict: ok, key, key_length, rails, plaintext, guesses (number of
    (rails, key length) combinations evaluated), score, error.

    Time complexity: O(R * K * N) with R = 9 rails and K = 16 key lengths, both
    constants, so O(N) in the ciphertext length.
    """
    if not _valid_text(ciphertext):
        return _failure("ciphertext must be a non-empty string of uppercase A-Z")

    best = None
    guesses = 0
    for rails in RAIL_RANGE:
        stage1 = cipher.rail_decrypt(ciphertext, rails)

        avg_ic = {}
        for length in KEY_LENGTH_RANGE:
            columns = [stage1[j::length] for j in range(length)]
            avg_ic[length] = sum(index_of_coincidence(c) for c in columns) / length
            guesses += 1
        top = max(avg_ic.values())
        length = min(L for L, ic in avg_ic.items() if ic >= top - IC_TIE_TOLERANCE)

        shifts = [_best_shift(stage1[j::length]) for j in range(length)]
        key = "".join(chr(65 + s) for s in shifts)
        plaintext = cipher.vigenere_decrypt(stage1, key)
        score = _chi_squared(plaintext)
        if best is None or score < best[0]:
            best = (score, rails, key, plaintext)

    score, rails, key, plaintext = best
    return _result(key, rails, plaintext, guesses, score)


# --------------------------------------------------------------------------
# Attack 2: known plaintext (crib)
# --------------------------------------------------------------------------

def known_plaintext_attack(ciphertext, crib):
    """Known-plaintext attack. The crib is the first M plaintext letters.

    For every rails value r in 2..10:
      1. Undo Rail Fence to get the candidate Stage-1 text S1.
      2. Derive the key stream k[i] = (S1[i] - crib[i]) mod 26 for i < M.
      3. For every key length L in 10..min(M, 25): candidate key = k[:L];
         decrypt all of S1 with it and score by chi-squared against
         ENGLISH_FREQ. Ties go to the smaller r, then the smaller L.
    Returns the best (r, L) combination, in the same dict shape as
    frequency_attack. guesses counts the (r, L) combinations evaluated.

    The attack can only work when M >= the true key length. With M < 10 it
    returns a failure dict ("crib too short") instead of raising.

    Time complexity: O(R * K * N) with constants R = 9, K <= 16, so O(N).
    """
    if not _valid_text(ciphertext):
        return _failure("ciphertext must be a non-empty string of uppercase A-Z")
    if not isinstance(crib, str):
        return _failure("crib must be a string of letters A-Z")
    m = len(crib)
    if m < cipher.MIN_KEY_LENGTH:
        return _failure(f"crib too short: {m} letters, need at least {cipher.MIN_KEY_LENGTH}")
    if not crib.isascii() or not crib.isalpha():
        return _failure("crib must be a string of letters A-Z")
    crib = crib.upper()
    if m > len(ciphertext):
        return _failure("crib is longer than the ciphertext")

    best = None
    guesses = 0
    for rails in RAIL_RANGE:
        stage1 = cipher.rail_decrypt(ciphertext, rails)
        stream = [(ord(stage1[i]) - ord(crib[i])) % 26 for i in range(m)]
        for length in range(cipher.MIN_KEY_LENGTH, min(m, 25) + 1):
            key = "".join(chr(65 + s) for s in stream[:length])
            plaintext = cipher.vigenere_decrypt(stage1, key)
            score = _chi_squared(plaintext)
            guesses += 1
            if best is None or score < best[0]:
                best = (score, rails, key, plaintext)

    score, rails, key, plaintext = best
    return _result(key, rails, plaintext, guesses, score)


# --------------------------------------------------------------------------
# Scoring an attack against the truth (experiments only)
# --------------------------------------------------------------------------

def key_letter_accuracy(true_key, found_key):
    """Fraction of key letters recovered, comparing the effective key streams.

    Both keys repeat forever, so they are compared over lcm(len(true_key),
    len(found_key)) positions. This is how a period multiple is handled: if the
    found key is the true key repeated (e.g. the true key twice), the two
    streams are identical and the accuracy is 1.0, so it counts as correct.
    A found key with the wrong period scores near chance (about 1/26).
    """
    if not found_key:
        return 0.0
    span = math.lcm(len(true_key), len(found_key))
    hits = sum(true_key[i % len(true_key)] == found_key[i % len(found_key)] for i in range(span))
    return hits / span


def _letter_accuracy(truth, guess):
    if not guess or len(guess) != len(truth):
        return 0.0
    return sum(a == b for a, b in zip(truth, guess)) / len(truth)


def load_corpus(path=CORPUS_PATH):
    """Read the corpus and keep only A-Z (via cipher.sanitize)."""
    try:
        with open(path, encoding="utf-8") as fh:
            clean, _ = cipher.sanitize(fh.read())
    except FileNotFoundError:
        raise SystemExit(f"Corpus not found: {path}")
    return clean


# --------------------------------------------------------------------------
# Experiments
# --------------------------------------------------------------------------

def _make_trial(rng, corpus, n):
    """One random trial: window of n corpus letters, key 10..20, rails 2..10."""
    start = rng.randrange(len(corpus) - n + 1)
    plaintext = corpus[start:start + n]
    key = "".join(rng.choices(string.ascii_uppercase, k=rng.randint(10, 20)))
    rails = rng.randint(cipher.MIN_RAILS, cipher.MAX_RAILS)
    _, ciphertext = cipher.custom_encrypt(plaintext, key, rails)
    return plaintext, key, rails, ciphertext


def _run_cell(rng, corpus, n, trials, crib_size=None):
    """Run `trials` attacks at length n; crib_size None means frequency attack."""
    exact, pt_acc, key_acc, rails_ok, times, guesses = [], [], [], [], [], []
    for _ in range(trials):
        plaintext, key, rails, ciphertext = _make_trial(rng, corpus, n)
        start = time.perf_counter()
        if crib_size is None:
            found = frequency_attack(ciphertext)
        else:
            found = known_plaintext_attack(ciphertext, plaintext[:crib_size])
        times.append((time.perf_counter() - start) * 1000)
        guesses.append(found["guesses"])
        exact.append(found["plaintext"] == plaintext)
        pt_acc.append(_letter_accuracy(plaintext, found["plaintext"]))
        key_acc.append(key_letter_accuracy(key, found["key"]))
        rails_ok.append(found["rails"] == rails)
    return {
        "text_length": n,
        "crib": crib_size if crib_size is not None else "",
        "trials": trials,
        "exact_pct": 100 * sum(exact) / trials,
        "plaintext_acc_pct": 100 * statistics.mean(pt_acc),
        "key_acc_pct": 100 * statistics.mean(key_acc),
        "rails_pct": 100 * sum(rails_ok) / trials,
        "median_ms": statistics.median(times),
        "median_guesses": statistics.median(guesses),
    }


def run_experiments(trials=100, seed=486):
    """Run Tables 1-3 and return {"table1": rows, "table2": rows, "table3": rows}.

    One random.Random(seed) drives every trial, so results are reproducible
    on the same Python version. Corpus windows are random; keys are random
    letters of random length 10..20; rails are random 2..10.
    """
    rng = random.Random(seed)
    corpus = load_corpus()
    if len(corpus) < max(TEXT_LENGTHS):
        raise SystemExit("Corpus is shorter than the longest test text.")
    return {
        "table1": [_run_cell(rng, corpus, n, trials) for n in TEXT_LENGTHS],
        "table2": [_run_cell(rng, corpus, n, trials, DEFAULT_CRIB) for n in TEXT_LENGTHS],
        "table3": [_run_cell(rng, corpus, TABLE3_LENGTH, trials, m) for m in CRIB_SIZES],
    }


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

_TITLES = {
    "table1": "Table 1: frequency attack (ciphertext only)",
    "table2": f"Table 2: known-plaintext attack, crib M = {DEFAULT_CRIB}",
    "table3": f"Table 3: known-plaintext attack vs crib size, N = {TABLE3_LENGTH}",
}


def format_table(title, rows, vary):
    """Aligned text table. `vary` is 'text_length' or 'crib'."""
    label = "N" if vary == "text_length" else "crib M"
    head = (f"{label:>7} {'exact %':>8} {'text acc %':>11} {'key acc %':>10} "
            f"{'rails %':>8} {'median ms':>10} {'median guesses':>15}")
    lines = [title, head, "-" * len(head)]
    for r in rows:
        lines.append(
            f"{r[vary]:>7} {r['exact_pct']:>8.1f} {r['plaintext_acc_pct']:>11.1f} "
            f"{r['key_acc_pct']:>10.1f} {r['rails_pct']:>8.1f} "
            f"{r['median_ms']:>10.2f} {r['median_guesses']:>15.0f}"
        )
    return "\n".join(lines)


def write_csv(results, path=RESULTS_PATH):
    """Write all three tables to one CSV file, creating the folder if needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = ["table", "text_length", "crib", "trials", "exact_pct", "plaintext_acc_pct",
              "key_acc_pct", "rails_pct", "median_ms", "median_guesses"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for name, rows in results.items():
            for row in rows:
                writer.writerow({"table": name, **row})
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attack experiments on Vigenere + Rail Fence.")
    parser.add_argument("--quick", action="store_true", help="10 trials per cell instead of 100")
    args = parser.parse_args(argv)
    trials = 10 if args.quick else 100

    print(f"Running attack experiments: {trials} trials per cell, seed 486 ...\n")
    results = run_experiments(trials=trials)
    print(format_table(_TITLES["table1"], results["table1"], "text_length"), end="\n\n")
    print(format_table(_TITLES["table2"], results["table2"], "text_length"), end="\n\n")
    print(format_table(_TITLES["table3"], results["table3"], "crib"), end="\n\n")
    print(f"Results written to {write_csv(results)}")


if __name__ == "__main__":
    main()
