# CT-486 Network & Information Security — CCP

A two-stage classical cipher: **Stage 1 Vigenere**, **Stage 2 Rail Fence**.
Python 3, standard library only (no pip installs).

## Progress

| Step | Scope | Status |
|------|-------|--------|
| 1 | Core cipher (`cipher.py`), unit tests, repo hygiene, limitations log | Done |
| 2 | Attacks (`attack.py`): frequency attack, known-plaintext attack, experiments | Done |
| 3 | Attack hardening (known-plaintext attack no longer relies on English scoring) and beginner-friendly comments in `cipher.py` and `attack.py` | Done |
| 4 | Benchmarks and complexity evidence (`benchmark.py`): timings, log-log fits, memory | Done |
| 5 | Desktop GUI (`gui.py`): lock/unlock with working shown, attacks, speed test, explanations | Done |
| 6 | Simpler GUI: tabs named after the requirements, shorter on-screen text, N = 50 added to the attack experiments (a tour and a weak-key note were added, then removed in Phase 7) | Done |
| 7 | GUI cut down to a viva demo tool: four tabs, one per line of the course project, only the buttons needed | Done |

### Step 1 — what exists

- `cipher.py`
  - `sanitize`, `validate_key` (key and rails are two separate inputs)
  - Shift cipher (baseline for later comparison)
  - Vigenere encrypt/decrypt (Stage 1)
  - Rail Fence via `rail_order` permutation (Stage 2)
  - `custom_encrypt` (Vigenere, then Rail Fence) and `custom_decrypt` (Rail Fence undone first, then Vigenere)
- `tests/test_cipher.py` — known vectors, 5000 seeded random round-trips, edge cases, validation
- `docs/LIMITATIONS.md` — running log of every known limitation, with viva defence and planned fix

### Step 2 — what exists

- `data/corpus.txt` — about 35,000 letters of original English prose (weather, travel, cooking, history, technology, sports, nature), used as test plaintext
- `attack.py`
  - `ENGLISH_FREQ` (asserted to sum to 1.0), `index_of_coincidence`
  - `frequency_attack(ciphertext)` — ciphertext only. For each rails value 2..10 it undoes Rail Fence, picks the key length 10..25 by average Index of Coincidence (smallest length wins near-ties), solves each column by chi-squared, and keeps the rails value whose decrypted text scores best.
  - `known_plaintext_attack(ciphertext, crib)` — the crib is the first M plaintext letters. For each rails value it derives the key stream from the crib; for each key length 10..min(M, 25) it checks whether the stream repeats with that period. A candidate that repeats perfectly over at least 3 checks (`MIN_CHECKS`) is "verified" and the smallest such key length wins; if nothing can be verified (crib too short) it falls back to English scoring (Phase 3). A crib shorter than 10 returns a failure result instead of raising.
  - `run_experiments(trials, seed)` and a CLI that prints three tables and writes `results/attack_results.csv`
- `tests/test_attack.py` — exact recovery on fixed cases, short-crib handling, a signature test for the threat model, frequency-table check

### Phase 3 — what changed

- **Attack hardening:** `known_plaintext_attack` now treats the crib as evidence. The key stream derived from the crib must repeat with the key length, so a wrong rails value or key length shows up as a failed repeat. A candidate that repeats perfectly over at least 3 checks is trusted; only when no candidate can be trusted does the attack fall back to English scoring. Works on any plaintext, not only English, when the crib is at least 3 letters longer than the key. Same function signature, same result shape, same threat model.
- **Comments:** `cipher.py` and `attack.py` have banner comments for every part and plain-English explanations of the mod-26 arithmetic, the repeating key, the Rail Fence zigzag order, the Index of Coincidence, chi-squared and the periodicity ranking. No logic was changed (checked by comparing the code's syntax tree before and after).
- New tests: random-letter plaintext recovered exactly (20 trials, crib 30), random letters with a 12-letter key and a crib of 20 (20 trials), failure result has the same shape as a success.

### Phase 4 — what exists

- `benchmark.py` — times the Shift cipher and the two-stage cipher over many message sizes (median and interquartile range of many repeats, garbage collection off, a warm-up call, and a round-trip check before every size that aborts the run if the cipher is wrong), fits the growth, and measures peak memory. See the Complexity section below.
- `tests/test_benchmark.py` — the maths helpers, the derived "linear" verdict, a tiny benchmark run, the round-trip abort.
- **Small fix:** `python attack.py --quick` now writes `results/attack_results_quick.csv` and never overwrites the full-run `results/attack_results.csv`. Quick CSV files (`results/*_quick.csv`) are git-ignored. A test checks this using a temporary folder.

### Phase 5 — what exists

- `gui.py` — one window, opened with `python gui.py` (standard library only: tkinter + ttk). It was simplified in Phase 7; what it looks like now is described under "The GUI" below.
- `explain.py` — the "show working" data (Vigenere table rows, Rail Fence zigzag grid), with no tkinter in it. Every row and grid is worked out independently and then compared with the real functions in `cipher.py`; if they ever disagree an error is raised, and the GUI shows "All rows match cipher.py: yes".
- `help_text.py` — the words for the Design tab (cut down to one short screen in Phase 7).
- Small additive changes: `attack.run_experiments(..., progress=None)` and `benchmark.run_benchmarks(..., progress=None)` accept an optional callback `progress(done, total)` that is called after each finished table row / measurement. If the callback raises that module's `CancelledError` the run stops. Without a callback nothing changes (tests check that the results are identical).
- Tests: `tests/test_explain.py`, `tests/test_gui_helpers.py` (no display needed), `tests/test_gui_smoke.py` (builds the window hidden; skipped, not failed, if there is no display), `tests/test_progress.py`.

### Phase 6 — what changed

The cipher and its results are the same; the window got simpler to follow.

- **Tabs renamed** after the course requirements: Req 2 · Encrypt & Decrypt, Req 3 · Deliverable 2 · Attack, Req 4 · Efficiency, Req 1 · Deliverable 1 · Design. The window measures the names against the smallest window size and switches to shorter names (`Req 2: Encrypt/Decrypt`, ...) if the long ones would be cut off.
- **Shorter on-screen text** and a different status-bar "Ready" message on each tab, which remembers what each tab last said.
- **N = 50 added** to the attack experiments (`attack.TEXT_LENGTHS` is now 50, 100, 250, 500, 1000, 2500, 5000). The full 100-trial run was repeated, so `results/attack_results.csv` has new numbers (see "Attack results" below).
- **No tkinter:** `python gui.py` prints one friendly line and exits; the GUI test files are skipped, not errored.
- (A guided tour and a weak-key note were also added in Phase 6; both were removed again in Phase 7.)

### Phase 7 — what changed (the GUI is now a viva demo tool)

Only `gui.py` and `help_text.py` changed (plus their tests and these docs). `cipher.py`, `attack.py`, `benchmark.py`, `explain.py`, `results/*.csv` and `data/corpus.txt` are untouched.

- **Four tabs only, one per line of the course project**, each with a short text and few buttons (see "The GUI" below).
- **Removed:** the START HERE tour and its banner, the Run Self-Test button and label (the checks still run with `python -m unittest`), the Move output to input and Copy output buttons, the sub-tabs in the Attack tab, the live 100-trial experiment run and Table 3, the "Paste my own ciphertext" option, the Full benchmark option and the Load saved results button, the weak-key note, the Save as CSV button, the Design tab's long help text, and all code that became unused.
- **Attack tab:** one page. "Try an attack" on a random test message, and one table of the SAVED experiment results (from `results/attack_results.csv`).
- **Efficiency tab:** the saved table and charts load when the tab opens; Run is the quick measurement only.
- **Design tab:** one screen, no scrolling. Its two worked examples are checked against `cipher.py` every time (a red warning replaces one that disagrees) and its speed and attack numbers are read from the saved CSV files.
- The window now starts no larger than the screen allows (a 1366 x 768 laptop gets a smaller window than a 1920 x 1080 desktop); the minimum size is still 950 x 680.
- Tests: GUI tests for the removed features were removed or rewritten; new ones cover the four tabs, the Design examples, the saved attack table, a missing CSV, and the absence of the removed widgets. The tests for `cipher`, `attack`, `benchmark` and `explain` are unchanged.

## The GUI

Start it with:

```
python gui.py
```

Four tabs, each showing one line of the course project (CCP):

| Tab | CCP line | What it shows |
|-----|----------|---------------|
| Req 2 · Encrypt & Decrypt | Requirement 2 | Type or load a message, enter a key (letters only, at least 10, with a live "n / 10 letters" counter) and the number of rails (2 to 10; two separate inputs), then press Lock or Unlock (Enter in the key box also locks). You see the cleaned text, the result after Stage 1 (Vigenere, blue) and the final result after Stage 2 (Rail Fence, orange), a check that it unlocks back to the original, and how many characters were removed. **Show Working** opens the letter-by-letter Vigenere table and the Rail Fence zigzag grid (the hand calculation). Mistakes appear as a red message under the buttons, never as a pop-up. |
| Req 3 · Deliverable 2 · Attack | Requirement 3, Deliverable 2 | **Try an attack:** choose the length of a random test message (50 to 5,000 letters), the frequency attack or the known-plaintext attack (the crib size only counts for the second), and press Run attack; it shows the rails, key, key length, guesses and time found, the recovered plaintext and whether it is correct. Reveal truth shows the real key. **Saved experiment results:** one table read from `results/attack_results.csv` (success % and median time for both attacks at every message length). It is not recomputed; run `python attack.py` to refresh the file. |
| Req 4 · Efficiency | Requirement 4 | The saved Shift-vs-custom timing table (from `results/benchmark_results.csv`) and two charts, shown when the tab opens. **Run** makes a quick measurement on this computer (messages up to 10,000 letters) with a progress bar and Cancel; it is shown but not saved. |
| Req 1 · Deliverable 1 · Design | Requirement 1, Deliverable 1 | One screen explaining the design: the two stages with their worked examples (checked against `cipher.py` each time), why they are combined, the key rules, and the speed ratio and the message length from which the frequency attack works (both read from the saved CSV files). |

Safety: the GUI uses no network and no local server, never uses `eval`/`exec`, never saves your key anywhere, and writes no file at all (it only reads the two saved result files). Slow jobs (an attack, the quick speed test) run in a background thread, so the window never freezes.

Not shown in the window on purpose (the report covers them): the other attack tables, the complexity fits and memory numbers, and the long explanations. They are in `results/*.csv`, `python attack.py`, `python benchmark.py` and `docs/LIMITATIONS.md`.

## Complexity

N is the message length and k the key length.

| Function | Time | Why |
|----------|------|-----|
| `shift_encrypt` / `shift_decrypt` | O(N) | one pass over the letters |
| `vigenere_encrypt` / `vigenere_decrypt` | O(N + k) | one pass over the letters, plus turning the key into numbers once |
| `rail_order`, `rail_encrypt` / `rail_decrypt` | O(N) | every position is placed on its rail once |
| `custom_encrypt` / `custom_decrypt` | O(N + k) | the two stages one after the other; this is O(N) for a fixed key length |

Extra memory is O(N) for all of them. `python benchmark.py` measures this rather than assuming it. The numbers below are from one full run on the author's machine (Python 3.14.6, Windows 11, 16 logical CPUs). **Timings depend on the machine**, so look at the shape and the ratios, not the absolute milliseconds.

**Table A — Shift vs the two-stage cipher** (median of many repeats; rails 4, key 12 letters)

| N | Shift enc ms | Custom enc ms | Custom dec ms | ratio custom/shift | custom µs per character |
|--------|---------|---------|---------|------|--------|
| 100 | 0.0156 | 0.0308 | 0.0308 | 1.97 | 0.3080 |
| 1,000 | 0.1528 | 0.2966 | 0.2977 | 1.94 | 0.2966 |
| 5,000 | 0.7342 | 1.4783 | 1.4848 | 2.01 | 0.2957 |
| 10,000 | 1.3910 | 3.0899 | 2.9531 | 2.22 | 0.3090 |
| 50,000 | 7.4566 | 16.5350 | 15.3817 | 2.22 | 0.3307 |
| 100,000 | 14.3287 | 32.5444 | 33.5984 | 2.27 | 0.3254 |

The microseconds-per-character column is nearly flat (0.296 to 0.331), which is what O(N) looks like. It is about 10 % higher at the two largest sizes, so it is not perfectly flat. Shift is the fastest, and the two-stage cipher costs about 2 times as much.

**Table B — where the time goes** (N = 10,000): Shift 1.456 ms; Vigenere alone 1.829 ms; Rail Fence alone 1.150 ms; custom total 3.058 ms. The two stages add up to about the total (the rest is input checking), and Vigenere is the bigger share.

**Table C — parameters do not change the big-O** (N = 10,000): with rails 2 to 10 the custom encryption took 2.96 to 3.10 ms, and with key length 10, 20, 50 and 100 it took 2.97 to 3.06 ms. No trend is visible; the differences are about the size of the run-to-run spread (IQR).

**Complexity check** (fits of the Table A timings):

| Operation | line time = a·N + b: R² | log-log slope | verdict (derived from the slope) |
|-----------|------|-------|---------|
| Shift enc | 0.99958 | 0.988 | linear |
| Custom enc | 0.99989 | 1.012 | linear |
| Custom dec | 0.99837 | 1.009 | linear |

A log-log slope of 1.0 means "double the message, double the time"; the program calls a slope between 0.85 and 1.15 "linear" and works the verdict out from the numbers each time. All three come out linear.

**Memory** (peak extra memory while encrypting, `tracemalloc`): Shift about 9 bytes per character, custom about 50 bytes per character, at both N = 10,000 and N = 100,000 (custom: 487.5 KB then 4,873.8 KB). Ten times the message gives about ten times the memory, so space is O(N); the two-stage cipher just uses about 5 times as much as Shift.

These measurements are evidence over sizes from 100 to 100,000 letters on one machine; they support O(N) but do not prove it. See `docs/LIMITATIONS.md` (L13 and L29 to L33).

### Threat model

The attacker knows the algorithm (Vigenere then Rail Fence) and the ciphertext. The attacker does **not** know the key, the key length or the number of rails. Attack functions therefore take only the ciphertext (and, for the known-plaintext attack, the crib). A test inspects their signatures to enforce this. The attacker does search the public parameter ranges of the system (rails 2..10, key length 10..25).

### Attack results (full run: 100 trials per row, seed 486)

Text lengths are letters. Keys are random, length 10..20; rails random, 2..10.

| N | Frequency attack: exact break | Known-plaintext (crib 30): exact break |
|------|------|------|
| 50 | 0 % | 100 % |
| 100 | 0 % | 100 % |
| 250 | 29 % | 100 % |
| 500 | 89 % | 100 % |
| 1000 and up | 100 % | 100 % |

(These are the numbers in `results/attack_results.csv` after the Phase 6 re-run, which added N = 50. Adding a row changes the order in which the random trials are drawn, so every row was drawn afresh; the Phase 5 file had 22 % at N = 250 and 84 % at N = 500 for the frequency attack. Differences of a few points are ordinary sampling noise for 100 trials; see L19 and L40 in `docs/LIMITATIONS.md`.)

Known-plaintext attack against crib size (N = 500, English plaintext): crib 10 gives 12 %, 15 gives 59 %, 20 and above give 100 %. The attack cannot work when the crib is shorter than the key. It now also works on plaintext that is not English as long as the crib is at least 3 letters longer than the key: with random-letter plaintext and a crib of 30, 20 of 20 test messages are recovered exactly (it was 0 of 20 before Phase 3). With a shorter crib it falls back to English scoring; in a separate check on random-letter plaintext, a crib of 20 recovered about 74 % and a crib of 15 about 29 % (see L28 in `docs/LIMITATIONS.md`). Full tables, including accuracy, rails-correct, time and guesses, are printed by `python attack.py` and saved in `results/attack_results.csv`. Timings depend on the machine. These numbers come from the author's own corpus; see `docs/LIMITATIONS.md` for what that does and does not show.

## Usage

```python
from cipher import sanitize, custom_encrypt, custom_decrypt

plain, removed = sanitize("Defend the east wall of the castle")
stage1, final = custom_encrypt(plain, "CRYPTOGRAPHY", 5)   # key >= 10 letters, rails 2..10
assert custom_decrypt(final, "CRYPTOGRAPHY", 5) == plain
```

## Running the tests

From the project root:

```
python -m unittest -v
```

## Running the attacks

```
python attack.py --quick    # 10 trials per row, a few seconds
python attack.py            # 100 trials per row, about a minute
```

Both print the three tables. A full run writes `results/attack_results.csv`; a `--quick` run writes `results/attack_results_quick.csv` instead, so it can never replace the full-run file. The folder is created if missing. `results/*_quick.csv` is git-ignored; the full-run CSV is a normal file that you may choose to commit.

## Running the GUI

```
python gui.py
```

It needs tkinter and a desktop display (tkinter 8.6 ships with the standard Python installer for Windows). If tkinter or the display is missing it prints one plain line saying so and exits, with no traceback. The Attack and Efficiency tabs show saved results, so run `python attack.py` and `python benchmark.py` first if those files are missing.

## Running the benchmarks

```
python benchmark.py --quick    # far fewer repeats, sizes up to 10,000, prints only
python benchmark.py            # everything; about a minute
```

A full run writes `results/benchmark_results.csv`; `--quick` writes the git-ignored `results/benchmark_results_quick.csv`.

## Security notes

This is a coursework project built on classical ciphers. It is **not** secure
for real data — see `docs/LIMITATIONS.md`. Never commit keys, passwords or
`.env` files (they are covered by `.gitignore`).
