# CT-486 Network & Information Security — CCP

A two-stage classical cipher: **Stage 1 Vigenere**, **Stage 2 Rail Fence**.
Python 3, standard library only (no pip installs).

## Progress

| Step | Scope | Status |
|------|-------|--------|
| 1 | Core cipher (`cipher.py`), unit tests, repo hygiene, limitations log | Done |
| 2 | Attacks (`attack.py`): frequency attack, known-plaintext attack, experiments | Done |
| 3 | Attack hardening (known-plaintext attack no longer relies on English scoring) and beginner-friendly comments in `cipher.py` and `attack.py` | Done |

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

Not yet built: GUI, benchmarks.

### Threat model

The attacker knows the algorithm (Vigenere then Rail Fence) and the ciphertext. The attacker does **not** know the key, the key length or the number of rails. Attack functions therefore take only the ciphertext (and, for the known-plaintext attack, the crib). A test inspects their signatures to enforce this. The attacker does search the public parameter ranges of the system (rails 2..10, key length 10..25).

### Attack results (full run: 100 trials per row, seed 486)

Text lengths are letters. Keys are random, length 10..20; rails random, 2..10.

| N | Frequency attack: exact break | Known-plaintext (crib 30): exact break |
|------|------|------|
| 100 | 0 % | 100 % |
| 250 | 22 % | 100 % |
| 500 | 84 % | 100 % |
| 1000 and up | 100 % | 100 % |

Known-plaintext attack against crib size (N = 500, English plaintext): crib 10 gives 12 %, 15 gives 56 %, 20 and above give 100 %. The attack cannot work when the crib is shorter than the key. It now also works on plaintext that is not English as long as the crib is at least 3 letters longer than the key: with random-letter plaintext and a crib of 30, 20 of 20 test messages are recovered exactly (it was 0 of 20 before Phase 3). With a shorter crib it falls back to English scoring; in a separate check on random-letter plaintext, a crib of 20 recovered about 74 % and a crib of 15 about 29 % (see L28 in `docs/LIMITATIONS.md`). Full tables, including accuracy, rails-correct, time and guesses, are printed by `python attack.py` and saved in `results/attack_results.csv`. Timings depend on the machine. These numbers come from the author's own corpus; see `docs/LIMITATIONS.md` for what that does and does not show.

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

Both print the three tables and write `results/attack_results.csv` (the folder is created if missing). Note that `.gitignore` only excludes `results/*.tmp`, so the CSV is a normal file that you may choose to commit.

## Security notes

This is a coursework project built on classical ciphers. It is **not** secure
for real data — see `docs/LIMITATIONS.md`. Never commit keys, passwords or
`.env` files (they are covered by `.gitignore`).
