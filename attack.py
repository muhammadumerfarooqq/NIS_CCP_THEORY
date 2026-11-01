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
                                (writes results/attack_results.csv)
    python attack.py --quick    10 trials per cell
                                (writes results/attack_results_quick.csv,
                                 never the full-run file)

Standard library only.

How to read this file (top to bottom):
    1. SETTINGS AND REFERENCE DATA   the English letter table and search ranges
    2. STATISTICS HELPERS            Index of Coincidence and chi-squared
    3. RESULT SHAPE                  what every attack returns
    4. FREQUENCY ATTACK              needs only the ciphertext
    5. KNOWN-PLAINTEXT ATTACK        needs the ciphertext and a crib
    6. EXPERIMENTS                   run the attacks many times and measure
    7. OUTPUT                        tables, CSV file and the command line
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


# ==========================================================================
# ===== SETTINGS AND REFERENCE DATA (English letter table, search ranges) =====
# ==========================================================================

# How often each letter appears in ordinary English (fractions of 1.0).
# E is the most common (about 12.7 %), Z and Q are the rarest. Both attacks
# use this table as their idea of "what normal English looks like".
ENGLISH_FREQ = {
    "A": .08167, "B": .01492, "C": .02782, "D": .04253, "E": .12702,
    "F": .02228, "G": .02015, "H": .06094, "I": .06966, "J": .00153,
    "K": .00772, "L": .04025, "M": .02406, "N": .06749, "O": .07507,
    "P": .01929, "Q": .00095, "R": .05987, "S": .06327, "T": .09056,
    "U": .02758, "V": .00978, "W": .02360, "X": .00150, "Y": .01974,
    "Z": .00074,
}
# Safety check when the file is loaded: the 26 fractions must add up to 1
# (100 %). This catches a typo in the table straight away. We use "raise"
# instead of "assert" so the check still runs when Python is started with -O.
if abs(sum(ENGLISH_FREQ.values()) - 1.0) >= 0.001:
    raise AssertionError("ENGLISH_FREQ must sum to 1.0 (within 0.001)")

# The same table as a plain list in alphabet order, _FREQ[0] for A ... _FREQ[25]
# for Z. A list is quicker to index with numbers in the loops below.
_FREQ = [ENGLISH_FREQ[ch] for ch in string.ascii_uppercase]

# Public parameter ranges of the cipher (known to the attacker).
# range(a, b) stops BEFORE b, hence the "+ 1" and the 26 (which means up to 25).
RAIL_RANGE = range(cipher.MIN_RAILS, cipher.MAX_RAILS + 1)
KEY_LENGTH_RANGE = range(cipher.MIN_KEY_LENGTH, 26)

# Two key lengths count as "almost equal" in IC when their average IC is within
# this of the best one. Fixed once, up front; not tuned against results.
IC_TIE_TOLERANCE = 0.005

# Known-plaintext attack: the least number of periodicity checks a candidate
# must pass (with zero violations) before we trust it as "verified".
# A random key stream passes k checks by pure chance with probability
# (1/26)^k. We examine 144 (rails, key length) candidates, so with k = 3 we
# expect about 144 / 26^3 = 0.008 false positives per attack. Fixed up front,
# not tuned on results.
MIN_CHECKS = 3

# Where the test text and the results file live, found relative to THIS file
# so the program works no matter which folder you start it from.
CORPUS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "corpus.txt")
RESULTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "attack_results.csv")
# A --quick run (only 10 trials) writes HERE, so it can never overwrite the
# full 100-trial results file above. This file is ignored by git.
RESULTS_PATH_QUICK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "attack_results_quick.csv")

# Experiment settings: message lengths to test, crib sizes to test, and the
# fixed crib size / message length used by Table 2 and Table 3.
TEXT_LENGTHS = [50, 100, 250, 500, 1000, 2500, 5000]      # 50 added in Phase 6 (a very short message)
CRIB_SIZES = [10, 15, 20, 30, 40]
DEFAULT_CRIB = 30
TABLE3_LENGTH = 500


# ==========================================================================
# ===== STATISTICS HELPERS (Index of Coincidence and chi-squared) =====
# ==========================================================================

def index_of_coincidence(text):
    """Index of Coincidence: the chance two letters drawn from text are equal.

        IC = sum_i n_i * (n_i - 1) / (N * (N - 1))

    where n_i is the count of letter i (A..Z) and N the text length.
    English prose gives about 0.065; uniformly random letters give about 0.038.
    Returns 0.0 for texts shorter than 2 letters.

    In simple words: pick two different letters from the text at random. In
    English the same letter turns up fairly often (lots of E's and T's), so IC
    is high. In a jumble of random letters it is low. We use this to tell
    "this is still plain English letters, just shifted" from "this is a mix".

    Time complexity: O(N).
    """
    n = len(text)
    # With fewer than 2 letters there are no pairs to compare.
    if n < 2:
        return 0.0
    # Counter(text) counts each letter. c * (c - 1) is the number of ordered
    # pairs of two different positions that both hold that letter. Dividing by
    # n * (n - 1), the number of all such pairs, gives the chance of a match.
    return sum(c * (c - 1) for c in Counter(text).values()) / (n * (n - 1))


def _chi_squared(text):
    """Chi-squared distance of text's letter counts from ENGLISH_FREQ. O(N)."""
    # In simple words: a score for "how un-English is this text?". For each
    # letter we compare how many times it really appears with how many times
    # it SHOULD appear in English text of this length, square the difference
    # (so over and under count both hurt), and divide by the expected count (so
    # a miss on a common letter matters less than a miss on a rare one). Add up
    # all 26. LOWER = more like English, 0 would be perfectly English.
    n = len(text)
    if n == 0:
        return math.inf
    counts = Counter(text)
    total = 0.0
    for i, ch in enumerate(string.ascii_uppercase):
        # How many of this letter we expect in n letters of English.
        expected = n * _FREQ[i]
        # counts.get(ch, 0) is 0 when the letter never appears.
        total += (counts.get(ch, 0) - expected) ** 2 / expected
    return total


def _best_shift(column):
    """Shift s (0..25) minimising chi-squared of column decrypted by s.

    Plaintext letter p appears in the ciphertext as p + s, so the expected
    count of ciphertext letter (p + s) is n * freq(p). O(n + 26 * 26).
    """
    # A "column" is every L-th letter of the Vigenere text, so they were all
    # shifted by the SAME key letter: it is just a Caesar cipher. We try all 26
    # shifts and keep the one whose result looks most like English.
    n = len(column)
    # An empty column has nothing to analyse; any shift will do.
    if n == 0:
        return 0
    # counts[x] = how many times letter number x (A=0 ... Z=25) occurs.
    counts = [0] * 26
    for ch in column:
        counts[ord(ch) - 65] += 1
    best_shift, best_chi = 0, math.inf
    for s in range(26):
        chi = 0.0
        for p in range(26):
            # If the key letter were s, plaintext letter p would appear as
            # letter (p + s) in the column. Compare how often that really
            # happens (counts) with how often p should occur (n * freq).
            expected = n * _FREQ[p]
            chi += (counts[(p + s) % 26] - expected) ** 2 / expected
        # Keep the shift with the smallest score so far.
        if chi < best_chi:
            best_shift, best_chi = s, chi
    return best_shift


# ==========================================================================
# ===== RESULT SHAPE (what every attack returns) =====
# ==========================================================================
# Both attacks return a dict with the same keys, so the experiment code can
# treat them the same way:
#   ok, key, key_length, rails, plaintext, guesses, score, error

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
    # True only for a non-empty string made purely of capital letters A-Z.
    # (isascii: plain characters only; isalpha: letters only; isupper: capitals.)
    return isinstance(text, str) and text != "" and text.isascii() and text.isalpha() and text.isupper()


# ==========================================================================
# ===== FREQUENCY ATTACK (ciphertext only, no key, no crib) =====
# ==========================================================================
# Big idea: a Vigenere key of length L shifts letters 0, L, 2L, ... all by the
# same amount, letters 1, L+1, 2L+1, ... by another amount, and so on. So if we
# split the text into L "columns" (every L-th letter), each column is just an
# ordinary Caesar cipher of English. Two steps follow:
#   1. Find L: the right L makes every column look like shifted English
#      (high Index of Coincidence); a wrong L mixes shifts together (low IC).
#   2. Solve each column on its own by trying 26 shifts (chi-squared).
# Rail Fence only moves letters around, so we simply try all 9 rail counts and
# keep whichever gives the most English-looking result.

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
    # Refuse anything that is not a non-empty string of capital letters.
    if not _valid_text(ciphertext):
        return _failure("ciphertext must be a non-empty string of uppercase A-Z")

    # best = the best (score, rails, key, plaintext) found so far.
    best = None
    # guesses counts every (rails, key length) pair we examine.
    guesses = 0
    for rails in RAIL_RANGE:
        # Guess a rail count and undo Rail Fence with it. If the guess is right
        # we now hold the Vigenere ciphertext; if wrong, just scrambled letters.
        stage1 = cipher.rail_decrypt(ciphertext, rails)

        # --- Step A: find the key length ---
        avg_ic = {}
        for length in KEY_LENGTH_RANGE:
            # stage1[j::length] = letters j, j+length, j+2*length, ... (column j).
            columns = [stage1[j::length] for j in range(length)]
            # Average the IC of all the columns for this guess of the length.
            avg_ic[length] = sum(index_of_coincidence(c) for c in columns) / length
            guesses += 1
        # The highest average IC is the best sign of a correct length...
        top = max(avg_ic.values())
        # ...but a multiple of the true length (2L, 3L) scores almost the same,
        # so among all lengths close to the top we choose the SMALLEST.
        length = min(L for L, ic in avg_ic.items() if ic >= top - IC_TIE_TOLERANCE)

        # --- Step B: solve each column as a Caesar cipher ---
        # One best shift per column; together they are the key as numbers.
        shifts = [_best_shift(stage1[j::length]) for j in range(length)]
        # Turn the numbers into letters (0 -> A, 1 -> B, ...): the candidate key.
        key = "".join(chr(65 + s) for s in shifts)
        # Decrypt with that key and score how English the result looks.
        plaintext = cipher.vigenere_decrypt(stage1, key)
        score = _chi_squared(plaintext)
        # Keep this rail guess only if it beats all earlier ones (lower = better).
        if best is None or score < best[0]:
            best = (score, rails, key, plaintext)

    score, rails, key, plaintext = best
    return _result(key, rails, plaintext, guesses, score)


# ==========================================================================
# ===== KNOWN-PLAINTEXT ATTACK (ciphertext + the first M plaintext letters) =====
# ==========================================================================
# Big idea: encryption is  cipher = plain + key  (mod 26), so if we know the
# plain letters we can get the key back:  key = cipher - plain  (mod 26).
# The "crib" gives us the first M key letters this way (the "key stream").
# The real key repeats every L letters, so in the true key stream
# stream[i] == stream[i - L]. We use that repeat as PROOF that we guessed the
# rails and the key length correctly. This never looks at what English is like,
# so it works on any plaintext, even random letters.
# The proof only counts if it was checked at least MIN_CHECKS (3) times, which
# needs a crib at least 3 letters longer than the key. If no candidate can be
# proved, the attack falls back to picking the most English-looking one, which
# only works on English-like plaintext.
#
# Tiny example (key "CAT", crib "HEL", cipher "JEE" from the Vigenere example):
#   J(9) - H(7) = 2 -> C,   E(4) - E(4) = 0 -> A,   E(4) - L(11) = -7 -> 19 -> T
#   The key stream is C, A, T: we recovered the first 3 key letters.

def known_plaintext_attack(ciphertext, crib):
    """Known-plaintext attack. The crib is the first M plaintext letters.

    Idea in plain English: the key repeats. If we guess the right rails value,
    undoing Rail Fence gives the Vigenere ciphertext, and subtracting the crib
    from it gives the first M letters of the key stream. The true key stream
    repeats every L letters (L = key length), so k[i] equals k[i - L]. A wrong
    rails value, or a wrong L, gives a stream that does not repeat. The crib
    itself is therefore the evidence; no knowledge of English is needed.

    For every rails value r in 2..10:
      1. Undo Rail Fence to get the candidate Stage-1 text S1.
      2. Derive the key stream k[i] = (S1[i] - crib[i]) mod 26 for i < M.
      3. For every key length L in 10..min(M, 25): count the periodicity
         violations, i.e. the positions i in [L, M) where k[i] != k[i - L].
         There are M - L such checks. The candidate key is k[:L].
    A candidate is "verified" when it has zero violations AND at least
    MIN_CHECKS (3) checks. Three or more clean checks are very unlikely to
    happen by chance (see MIN_CHECKS), so a verified candidate is real evidence.
      * If at least one candidate is verified, the winner is chosen among the
        verified ones by: (a) more checks first, which means the smaller L
        (this also stops a multiple of the true length from beating the true
        length); (b) lower English chi-squared of the whole decrypted text;
        (c) the smaller r.
      * If NO candidate is verified (the crib is too short to prove anything),
        the winner is the candidate with the lowest English chi-squared over
        all candidates (ties: smaller r, then smaller L). This fallback needs
        English-like plaintext to work.
    Returns the best (r, L) combination, in the same dict shape as
    frequency_attack. guesses counts the (r, L) combinations evaluated.

    Needs M >= (true key length) + MIN_CHECKS for the evidence to exist. With
    M <= L + 2 there are fewer than 3 checks, so the English-scoring fallback
    decides, and with M < L the key cannot be recovered at all.
    With M < 10 it returns a failure dict ("crib too short") instead of raising.

    Time complexity: O(R * K * N) with constants R = 9, K <= 16, so O(N).
    """
    # --- Check the inputs; return a failure result instead of crashing ---
    if not _valid_text(ciphertext):
        return _failure("ciphertext must be a non-empty string of uppercase A-Z")
    if not isinstance(crib, str):
        return _failure("crib must be a string of letters A-Z")
    # m = M = how many known plaintext letters we were given.
    m = len(crib)
    # The shortest key is 10 letters, so a crib under 10 cannot even cover it.
    # (This check comes before the letters check so "" gets the right message.)
    if m < cipher.MIN_KEY_LENGTH:
        return _failure(f"crib too short: {m} letters, need at least {cipher.MIN_KEY_LENGTH}")
    if not crib.isascii() or not crib.isalpha():
        return _failure("crib must be a string of letters A-Z")
    crib = crib.upper()
    if m > len(ciphertext):
        return _failure("crib is longer than the ciphertext")

    # Two "best so far" slots:
    #   best_verified = best candidate that passed the periodicity test
    #   best_any      = best candidate by English score alone (the fallback)
    # Each holds (rank, rails, key, plaintext, score); a smaller rank wins.
    best_verified = None
    best_any = None
    guesses = 0
    for rails in RAIL_RANGE:
        # Guess the rail count and undo Rail Fence with it.
        stage1 = cipher.rail_decrypt(ciphertext, rails)
        # The key stream: for each known position, cipher letter minus plain
        # letter (mod 26). Only the first m letters are known, so only m values.
        stream = [(ord(stage1[i]) - ord(crib[i])) % 26 for i in range(m)]
        for length in range(cipher.MIN_KEY_LENGTH, min(m, 25) + 1):
            # If the key really has this length, letter i must equal letter
            # i - length for every i from length up to m - 1. That is
            # (m - length) comparisons ("checks"); each mismatch is a "violation".
            # Example: M = 30, L = 12 gives 18 checks (i = 12..29).
            checks = m - length
            violations = sum(stream[i] != stream[i - length] for i in range(length, m))
            # The candidate key is the first `length` letters of the key stream.
            key = "".join(chr(65 + s) for s in stream[:length])
            # Decrypt everything with it and measure how English it looks
            # (lower = more English). Used as a tie-breaker or as the fallback.
            plaintext = cipher.vigenere_decrypt(stage1, key)
            score = _chi_squared(plaintext)
            guesses += 1
            # Verified = the stream repeated perfectly AND we made enough
            # checks for that to mean something (not just luck).
            if violations == 0 and checks >= MIN_CHECKS:
                # Smaller L first (more checks), then English score, then r.
                # Python compares tuples left to right, so the later items only
                # matter when the earlier ones are exactly equal.
                rank = (length, score, rails)
                if best_verified is None or rank < best_verified[0]:
                    best_verified = (rank, rails, key, plaintext, score)
            # Fallback ranking, kept for every candidate: English score first,
            # then smaller r, then smaller L.
            rank = (score, rails, length)
            if best_any is None or rank < best_any[0]:
                best_any = (rank, rails, key, plaintext, score)

    # Trust a verified candidate if there is one; otherwise fall back to the
    # candidate that looks most like English.
    chosen = best_verified if best_verified is not None else best_any
    rank, rails, key, plaintext, score = chosen
    return _result(key, rails, plaintext, guesses, score)


# ==========================================================================
# ===== EXPERIMENTS (run the attacks many times and measure the results) =====
# ==========================================================================
# We cannot know if an attack is "good" from one run. So we make many random
# test messages, encrypt each with a random key, attack the ciphertext, and
# compare the attack's answer with the truth we kept to one side.

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
    # lcm = least common multiple, the first length at which both repeating
    # keys line up again. Comparing that many letters covers every pairing.
    # Example: keys of length 4 and 6 are compared over 12 positions.
    span = math.lcm(len(true_key), len(found_key))
    # i % len(key) wraps around, so each key repeats as it does in encryption.
    hits = sum(true_key[i % len(true_key)] == found_key[i % len(found_key)] for i in range(span))
    return hits / span


def _letter_accuracy(truth, guess):
    # Share of positions where the guessed text has the right letter.
    # A missing guess or one of the wrong length counts as 0.
    if not guess or len(guess) != len(truth):
        return 0.0
    return sum(a == b for a, b in zip(truth, guess)) / len(truth)


def load_corpus(path=CORPUS_PATH):
    """Read the corpus and keep only A-Z (via cipher.sanitize)."""
    try:
        with open(path, encoding="utf-8") as fh:
            # sanitize returns (clean_text, removed_count); we only need the text.
            clean, _ = cipher.sanitize(fh.read())
    except FileNotFoundError:
        raise SystemExit(f"Corpus not found: {path}")
    return clean


def _make_trial(rng, corpus, n):
    """One random trial: window of n corpus letters, key 10..20, rails 2..10."""
    # Pick a random starting point so that n letters still fit in the corpus.
    start = rng.randrange(len(corpus) - n + 1)
    plaintext = corpus[start:start + n]
    # Random key: 10 to 20 random capital letters.
    key = "".join(rng.choices(string.ascii_uppercase, k=rng.randint(10, 20)))
    rails = rng.randint(cipher.MIN_RAILS, cipher.MAX_RAILS)
    # custom_encrypt returns (stage1, final); the attacker only gets `final`.
    _, ciphertext = cipher.custom_encrypt(plaintext, key, rails)
    return plaintext, key, rails, ciphertext


def _run_cell(rng, corpus, n, trials, crib_size=None):
    """Run `trials` attacks at length n; crib_size None means frequency attack."""
    # One list per measurement, with one entry per trial.
    exact, pt_acc, key_acc, rails_ok, times, guesses = [], [], [], [], [], []
    for _ in range(trials):
        plaintext, key, rails, ciphertext = _make_trial(rng, corpus, n)
        # Time only the attack itself, in milliseconds.
        start = time.perf_counter()
        if crib_size is None:
            # Ciphertext only: the attacker gets nothing else.
            found = frequency_attack(ciphertext)
        else:
            # The crib is the first crib_size letters of the true plaintext.
            found = known_plaintext_attack(ciphertext, plaintext[:crib_size])
        times.append((time.perf_counter() - start) * 1000)
        guesses.append(found["guesses"])
        # Now compare the attack's answer with the truth.
        exact.append(found["plaintext"] == plaintext)
        pt_acc.append(_letter_accuracy(plaintext, found["plaintext"]))
        key_acc.append(key_letter_accuracy(key, found["key"]))
        rails_ok.append(found["rails"] == rails)
    # Summarise all trials: percentages, means and medians.
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


class CancelledError(Exception):
    """Raised by a progress callback to stop run_experiments early.

    The GUI's Cancel button works like this: the callback notices the user
    pressed Cancel and raises CancelledError; run_experiments does not catch
    it, so it travels up to whoever started the run.
    """


def run_experiments(trials=100, seed=486, progress=None):
    """Run Tables 1-3 and return {"table1": rows, "table2": rows, "table3": rows}.

    One random.Random(seed) drives every trial, so results are reproducible
    on the same Python version. Corpus windows are random; keys are random
    letters of random length 10..20; rails are random 2..10.

    progress (optional): a function progress(done, total) called after each
    finished table row ("cell"), e.g. progress(3, 17) = 3 of 17 rows done.
    If it raises CancelledError the run stops there. With progress=None
    (the default) nothing is called and the results are exactly as before.
    """
    # A fixed seed makes the "random" choices repeat exactly on every run, so
    # anyone can reproduce the numbers.
    rng = random.Random(seed)
    corpus = load_corpus()
    if len(corpus) < max(TEXT_LENGTHS):
        raise SystemExit("Corpus is shorter than the longest test text.")
    # Every table row to compute, in the same order as always (all of
    # Table 1, then Table 2, then Table 3), so the random numbers are drawn in
    # exactly the same order and the results do not change.
    #   Table 1: frequency attack at each message length.
    #   Table 2: known-plaintext attack, crib of 30, each message length.
    #   Table 3: known-plaintext attack, message of 500, different crib sizes.
    jobs = ([("table1", n, None) for n in TEXT_LENGTHS]
            + [("table2", n, DEFAULT_CRIB) for n in TEXT_LENGTHS]
            + [("table3", TABLE3_LENGTH, m) for m in CRIB_SIZES])
    results = {"table1": [], "table2": [], "table3": []}
    for done, (table, n, crib) in enumerate(jobs, start=1):
        results[table].append(_run_cell(rng, corpus, n, trials, crib))
        # Tell the caller how far we are (the caller may raise CancelledError).
        if progress is not None:
            progress(done, len(jobs))
    return results


# ==========================================================================
# ===== OUTPUT (printed tables, the CSV file and the command line) =====
# ==========================================================================

_TITLES = {
    "table1": "Table 1: frequency attack (ciphertext only)",
    "table2": f"Table 2: known-plaintext attack, crib M = {DEFAULT_CRIB}",
    "table3": f"Table 3: known-plaintext attack vs crib size, N = {TABLE3_LENGTH}",
}


def format_table(title, rows, vary):
    """Aligned text table. `vary` is 'text_length' or 'crib'."""
    # The first column is either the message length N or the crib size M.
    label = "N" if vary == "text_length" else "crib M"
    # Format codes like {:>8} mean "right-align in 8 characters"; the .1f /
    # .2f / .0f codes set the number of decimals. This keeps columns straight.
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
    # exist_ok=True: do nothing if the results folder is already there.
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fields = ["table", "text_length", "crib", "trials", "exact_pct", "plaintext_acc_pct",
              "key_acc_pct", "rails_pct", "median_ms", "median_guesses"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for name, rows in results.items():
            for row in rows:
                # {"table": name, **row} = the row's values plus its table name.
                writer.writerow({"table": name, **row})
    return path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Attack experiments on Vigenere + Rail Fence.")
    parser.add_argument("--quick", action="store_true", help="10 trials per cell instead of 100")
    args = parser.parse_args(argv)
    # --quick is the fast demo; no flag is the full 100-trial run.
    trials = 10 if args.quick else 100

    print(f"Running attack experiments: {trials} trials per cell, seed 486 ...\n")
    results = run_experiments(trials=trials)
    print(format_table(_TITLES["table1"], results["table1"], "text_length"), end="\n\n")
    print(format_table(_TITLES["table2"], results["table2"], "text_length"), end="\n\n")
    print(format_table(_TITLES["table3"], results["table3"], "crib"), end="\n\n")
    # Choose where to save: a quick run goes to its own file so the full-run
    # results are never replaced by the smaller, noisier quick numbers.
    csv_path = RESULTS_PATH_QUICK if args.quick else RESULTS_PATH
    print(f"Results written to {write_csv(results, csv_path)}")


# Run main() only when this file is started directly (python attack.py), not
# when another file imports it (the tests do that).
if __name__ == "__main__":
    main()
