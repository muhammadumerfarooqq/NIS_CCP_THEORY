# Limitations Log

Every known limitation or issue, big or small, from day 1. New ones are added
when found. Fixed ones are marked `SOLVED in <phase>` and never deleted.

Status values: `OPEN`, `ACCEPTED` (inherent to the design, will not be fixed), `SOLVED in <phase>`.

---

## L1. Only A-Z is supported
- **Limitation:** Spaces, digits, punctuation, case and non-ASCII letters are dropped by `sanitize` on encrypt. They cannot be restored on decrypt, so the decrypted text is the cleaned text, not the original.
- **Viva defence:** The classical Vigenere and Rail Fence ciphers are defined over a 26-letter alphabet; the mod-26 arithmetic is the whole point. Restricting input keeps the maths exact and the round-trip provable.
- **Planned fix:** Optionally record removed characters' positions/values so the original formatting can be re-inserted, or widen the alphabet (e.g. printable ASCII, mod 95).
- **Status:** OPEN (accepted for the A-Z design)

## L2. Rail Fence key space is tiny
- **Limitation:** Rails are limited to 2..10, giving only 9 possible keys, so Stage 2 adds almost no security against exhaustive search.
- **Viva defence:** Rail Fence is a transposition stage; its job is to scramble letter positions and break the periodic structure Vigenere leaves, not to add key-search difficulty. The security of the pair rests mainly on the Vigenere key.
- **Planned fix:** Demonstrate in the attack/benchmark step that all 9 values are brute-forced instantly; note a columnar transposition with a keyword as a stronger alternative.
- **Step 2 evidence:** Both attacks simply try all 9 rails values every time (144 rails/key-length combinations in total). Brute-forcing the Rail Fence stage costs a few milliseconds, so it adds essentially no search difficulty. The demonstration part of the planned fix is done in Step 2.
- **Status:** ACCEPTED (brute-force demonstrated in Step 2)

## L3. Vigenere is vulnerable to Kasiski / Index of Coincidence
- **Limitation:** A short key or a key with a repeated pattern leaves a detectable period. Kasiski examination and the Index of Coincidence can recover the key length, then frequency analysis recovers each key letter.
- **Viva defence:** A minimum key length of 10 raises the amount of ciphertext an attacker needs, and the Rail Fence stage scrambles letter positions so the period is not directly visible in the ciphertext. This is a mitigation, not a cure.
- **Planned fix:** Implement the attacks in a later step and measure how much ciphertext is needed to break keys of different lengths, with and without Rail Fence.
- **Step 2 evidence:** The ciphertext-only frequency attack (undo Rail Fence for each of 9 rails values, then Index of Coincidence + chi-squared) broke 100 % of random 10..20-letter keys from 1000 letters of text upward, 84 % at 500 letters and 22 % at 250 (100 trials per row, seed 486). So Rail Fence does not hide the Vigenere period from an attacker who can try every rails value. Still to do: the comparison without Rail Fence.
- **Status:** OPEN (attack implemented in Step 2; comparison without Rail Fence still to do)

## L4. Classical ciphers are not secure against modern attacks
- **Limitation:** Both stages are classical; they fall to known-plaintext, statistical and computer-assisted attacks. This project must not be used to protect real data.
- **Viva defence:** The project's goal is to study and compare classical techniques, including their weaknesses, not to produce production-grade encryption. Modern ciphers (AES) are the correct choice for real use.
- **Planned fix:** Add a comparison against a modern cipher in the report; state this limitation clearly in the final documentation.
- **Status:** ACCEPTED

## L5. The "at least 10 letters" key rule is only enforced by the combined cipher
- **Limitation:** `vigenere_encrypt/decrypt` accept any non-empty letter key (needed for textbook vectors such as `CIPHER`, `TRICKEM`). Only `validate_key`, called by `custom_encrypt/decrypt`, enforces length >= 10 and rails 2..10. `rail_encrypt/decrypt` accept any rails >= 2.
- **Viva defence:** The primitives are kept general so they can be verified against published examples; the policy lives at the layer users actually call.
- **Planned fix:** GUI and any CLI must always go through `custom_*`/`validate_key`.
- **Status:** OPEN

## L6. Weak keys pass validation
- **Limitation:** `validate_key` checks only characters and length. Keys such as `AAAAAAAAAA` (shift of 0, i.e. no encryption at Stage 1) or `ABABABABAB` (period 2) are accepted.
- **Viva defence:** The spec defines validity as letters-only and >= 10 letters; judging key quality is a separate problem and is warned about here and in L3.
- **Planned fix:** Add a key-strength warning (repeated pattern, low letter variety) in the GUI step.
- **Status:** OPEN

## L7. Deterministic, no IV, no integrity protection
- **Limitation:** The same plaintext, key and rails always give the same ciphertext. There is no nonce/IV and no authentication, so ciphertext can be modified undetected and equal messages are recognisable.
- **Viva defence:** Classical ciphers have neither concept; adding them would turn this into a different (modern-style) construction.
- **Planned fix:** Document only; mention MAC/AEAD in the report as the modern solution.
- **Status:** ACCEPTED

## L8. Ciphertext length equals plaintext length
- **Limitation:** Length is not hidden, and Rail Fence is a pure transposition so letter frequencies in the final ciphertext are the same as in the Stage 1 output.
- **Viva defence:** Inherent to substitution + transposition ciphers; frequencies are already flattened by Vigenere before the transposition.
- **Planned fix:** Document only.
- **Status:** ACCEPTED

## L9. Primitives reject lowercase / non-letter text instead of cleaning it
- **Limitation:** `vigenere_*` and `shift_*` raise `ValueError` for anything outside uppercase A-Z; callers must run `sanitize` first. `custom_*` do not call `sanitize` themselves.
- **Viva defence:** Failing loudly is safer than silently producing wrong output; sanitising is a separate, visible step so the user sees how many characters were dropped.
- **Planned fix:** The GUI will call `sanitize` and show the removed count.
- **Status:** OPEN

## L10. Keys are plain Python strings
- **Limitation:** Keys live in ordinary immutable `str` objects, so they cannot be wiped from memory and could appear in logs or tracebacks if a caller prints them.
- **Viva defence:** Python offers no reliable way to zero immutable strings; for a coursework cipher this is acceptable. Keys are never hardcoded or stored by the code.
- **Planned fix:** Avoid logging keys in later steps; read them from user input only.
- **Status:** ACCEPTED

## L11. No key generation helper
- **Limitation:** The user must invent their own key; nothing generates a strong random one (the `random` module used in tests is not cryptographically secure).
- **Viva defence:** Out of scope for Step 1; tests use seeded `random` deliberately for reproducibility, not for security.
- **Planned fix:** Optional key generator using the `secrets` module in a later step.
- **Status:** OPEN

## L12. Test coverage and platform
- **Limitation:** Tests cover the required vectors, random round-trips, edge cases and validation, but not rejection of bad text input in the primitives or Unicode edge cases (e.g. `ß`, which uppercases to `SS`; handled in `sanitize` but not covered by a test). Only run on Python 3.14 on Windows so far.
- **Viva defence:** The step specified an exact vector list; extra tests were not added to avoid deviating from it.
- **Planned fix:** Add the extra tests in a later step once agreed.
- **Status:** OPEN. The `ß` part is SOLVED in Step 2 (regression test `sanitize("Straße é 1") == ("STRAE", 5)` added). Still open: tests that the primitives reject bad text, and runs on other Python versions / operating systems.

## L13. Pure-Python performance
- **Limitation:** All functions are O(N) but implemented with Python-level loops and temporary lists, so very large inputs (many MB) will be slow and memory-hungry compared with compiled code.
- **Viva defence:** Linear time is the relevant complexity result; constant factors are irrelevant at the text sizes this project handles.
- **Planned fix:** Measure in the benchmark step.
- **Step 2 note:** The attacks time at roughly 20-60 ms (frequency) and 5-170 ms (known-plaintext) for 100-5000 letters, which is fine for this project, but see L18 for how far to trust those timings.
- **Status:** OPEN (formal benchmarks still to do)

---

# Added in Step 2 (attacks)

## L14. The corpus is original, single-style prose
- **Limitation:** `data/corpus.txt` (about 35,000 letters) was written for this project in one general style. Its letter frequencies are within about 1 percentage point of the reference table, so it is a friendly test case. Real-world texts (code, names, abbreviations, numbers stripped out by `sanitize`, other languages, technical jargon) have different letter statistics, so the attack success rates here are likely optimistic for them. Also, windows of at most 5,000 letters are drawn from the same 35,000, so trials overlap and are not fully independent samples of text.
- **Viva defence:** A self-written corpus avoids copying anyone's work and gives a reproducible benchmark. The attacks use only the published `ENGLISH_FREQ` table, never the corpus statistics, so there is no training on the test data.
- **Planned fix:** In a later step, test on a few differently styled texts (formal, informal, technical) and state the spread.
- **Status:** OPEN

## L15. The frequency attack needs enough text per key letter
- **Limitation:** Each key letter is solved from only about N / key-length ciphertext letters. With short messages the statistics are too noisy: in the full run the exact-break rate is 0 % at N = 100, 22 % at 250 and 84 % at 500, and 100 % from 1000 upward. At N = 100 the recovered rails value is right only 13 % of the time, close to chance (1 in 9).
- **Viva defence:** This is the expected behaviour of any statistical attack and is itself a finding: short messages are meaningfully harder to break. It is reported honestly, not tuned away.
- **Planned fix:** Report the minimum ciphertext length for a given success rate in the final analysis; possibly add a dictionary/n-gram score to help on short texts.
- **Status:** OPEN

## L16. The known-plaintext attack needs a crib at least as long as the key
- **Limitation:** The attack derives only M key-stream letters from an M-letter crib, so it can only build keys up to length M. At N = 500 it succeeded 12 % of the time with M = 10, 56 % with M = 15, 100 % with M = 20 and 100 % with M >= 30 (keys were 10..20 letters, English plaintext; current numbers. An intermediate Phase 3 version briefly gave 47 % and 95 % at M = 15 and 20, see L26). It also assumes the crib is the very start of the message (positions 0..M-1) and is already cleaned to A-Z; a crib found elsewhere in the text, or one containing spaces, is not handled.
- **Viva defence:** If the crib is shorter than the key, part of the key stream is simply unknown, so no method could recover it from the crib alone. The start-of-message assumption matches the specification for this step.
- **Planned fix:** Extend to a crib at a known or unknown position (try every offset) if time allows.
- **Status:** OPEN

## L17. Results depend on the parameter ranges chosen
- **Limitation:** Test keys are random letters of length 10..20 and rails 2..10; the attacks search key lengths 10..25 only. The cipher itself allows keys longer than 25 letters (`validate_key` has no upper limit), and such keys lie outside the attack's search range. Only random keys were tested, not deliberately weak ones (see L6). Success percentages would change with other ranges.
- **Viva defence:** The ranges are the ones set for the project. The attacker is allowed to know them because they are part of the public algorithm specification. Search ranges can be widened by changing two constants.
- **Planned fix:** Run a sensitivity check with longer keys in the benchmark step; consider capping key length in `validate_key`.
- **Status:** OPEN

## L18. Timing is machine-dependent
- **Limitation:** Reported milliseconds come from `time.perf_counter` on one machine with one Python version, with other programs running; they will differ elsewhere. Only the medians and the way time grows with N are meaningful.
- **Viva defence:** Medians reduce the effect of outliers, and the project's claim is about linear growth (O(N)), not absolute speed.
- **Planned fix:** The benchmark step should repeat runs and report spread.
- **Status:** OPEN

## L19. Statistical precision of the experiments
- **Limitation:** Each table row uses 100 trials (10 with `--quick`) and one seed (486), so a percentage such as 84 % carries a sampling error of several points. Results are reproducible given the same Python version, but are one sample, not a long-run average.
- **Viva defence:** Fixing the seed makes every number checkable; the trends (a sharp rise between N = 250 and 1000) are far larger than the sampling error.
- **Planned fix:** Add more trials or confidence intervals if the final report needs tighter numbers.
- **Status:** OPEN

## L20. Design choices inside the frequency attack are fixed, not optimised
- **Limitation:** The near-tie rule for key length uses a fixed Index of Coincidence tolerance of 0.005; the rails value is chosen by chi-squared of a text whose columns were already fitted to English, which can overfit on short texts (see L15); each column is solved independently with no word-level check. Better settings may exist.
- **Viva defence:** The tolerance was set once before any results were seen and never tuned against them, so the reported numbers are not inflated by fitting.
- **Planned fix:** Optional experiment comparing a few tolerances and a bigram score, reported separately.
- **Status:** OPEN

## L21. "Guesses" and "key accuracy" are simple metrics
- **Limitation:** "Guesses" counts only (rails, key-length) combinations evaluated (144 for the full range), not the 26 shifts tried per column, so it is not a like-for-like measure of work between the two attacks. "Key accuracy" compares the repeating key streams over the least common multiple of the two key lengths; a recovered key that is the true key repeated (for example twice) therefore counts as 100 % correct even though the text differs. Exact plaintext recovery is the stricter measure.
- **Viva defence:** Both rules are stated in the code and the spec. A key and its repetition encrypt identically, so counting them as the same key is correct.
- **Planned fix:** Possibly also report total candidate decryptions tried.
- **Status:** OPEN

## L22. Attacks assume clean A-Z ciphertext and ideal conditions
- **Limitation:** The attacks reject ciphertext that is empty or contains anything other than uppercase A-Z, and assume the attacker knows the exact algorithm, the ranges, and (for the frequency attack) that the plaintext is ordinary English. Since Phase 3 the known-plaintext attack no longer needs English when the crib is at least 3 letters longer than the key (see L25); with a shorter crib it still falls back to English scoring (L28). The frequency attack always needs English and is expected to fail on random-letter plaintext. Cipher errors, missing letters, or a different language would defeat them.
- **Viva defence:** This is the stated threat model (the attacker knows the algorithm, not the key). Assuming a strong, well-informed attacker is the standard way to judge a cipher.
- **Planned fix:** None planned; document only.
- **Status:** ACCEPTED

## L23. Generated results file and repository hygiene
- **Limitation:** `results/attack_results.csv` is overwritten each run (a `--quick` run replaces a full-run file). `.gitignore` excludes only `results/*.tmp`, so the CSV is not ignored and could be committed in either state by accident.
- **Viva defence:** Keeping the CSV in the repository makes the reported numbers reproducible and checkable.
- **Planned fix:** Write quick runs to a different filename, or ignore the CSV and commit only a chosen final one.
- **Status:** OPEN

## L24. Bug found and fixed while building the known-plaintext attack
- **Limitation:** An empty crib ("") first hit the "letters only" check and returned a misleading error instead of "crib too short" (found by the new test).
- **Viva defence:** Found by a test written before the code was run, fixed in the code (the test was not changed).
- **Planned fix:** Done.
- **Status:** SOLVED in Step 2

---

# Added in Phase 3 (attack hardening and comments)

## L25. The known-plaintext attack depended on English scoring
- **Limitation:** In Step 2 the winning (rails, key length) was chosen by English chi-squared of the whole decrypted text, so the crib was barely used as evidence. On non-English plaintext it failed: in a 20-trial test with 500 uniformly random letters (key 10..20, crib 30) the Step 2 attack recovered the plaintext 0 times out of 20. This was not recorded as its own entry in Step 2 (only touched on in L22); it is recorded here.
- **Viva defence:** Step 2 was built to meet the specified scoring method and was never claimed to work on non-English text; the weakness was found by testing a harder case and then fixed.
- **Planned fix:** Done. A candidate whose key stream repeats perfectly over at least `MIN_CHECKS` (3) comparisons is "verified" and chosen by smaller key length (English score only as a tie-breaker). English scoring alone is used only when no candidate can be verified (that remaining case is L28).
- **Evidence:** The same 20-trial random-plaintext test now recovers the exact plaintext and the right rails 20 times out of 20 (test `test_random_letter_plaintext_is_recovered_exactly`); a second test with key length 12 and crib 20 also passes 20 of 20. Table 2 (crib 30) is unchanged at 100 % for every N.
- **Status:** SOLVED in Phase 3 (for crib length >= key length + 3; shorter cribs: see L28)

## L26. The known-plaintext attack gets WORSE when the crib is barely longer than the key
- **Limitation:** The periodicity check needs M - L comparisons for key length L. If M = L there are none; the specified rule treats such a candidate as violation rate 1.0 (worst), so it loses to wrong, shorter key lengths whose rate is only about 0.96. The attack then fails for every key with L = M. If M = L + 1 there is a single check, which a wrong candidate can pass by luck (about 1 in 26). If M < L the key cannot be recovered at all (L16). Measured effect in the full run (N = 500, 100 trials): M = 15 fell from 56 % (Step 2) to 47 %, and M = 20 fell from 100 % to 95 %. A separate diagnostic (400 trials) showed the failures were exactly the keys with L = M (for M = 15, 38 of 38 keys of length 15 failed; for M = 20, 30 of 30 keys of length 20 failed) plus a few single-check cases (1 of 38 and 2 of 37). The old English-only scoring happened to rescue the L = M case. M = 10 is unchanged at 12 %: every candidate has length 10, so there are never any checks.
- **Viva defence:** With no repeat to check, the crib cannot prove anything about the key length, so an honest attack must either guess or admit it does not know. The ranking was fixed in advance and deliberately not adjusted after seeing the results. The trade is clear: the attack now works on any plaintext when the crib is longer than the key, and is slightly worse than before when the crib length equals the key length.
- **Planned fix:** Done in Phase 3 (second change). A candidate now counts as "verified" only if it has zero violations AND at least `MIN_CHECKS = 3` checks (a random stream passes 3 checks by chance with probability 1/26^3, giving about 0.008 expected false positives over the 144 candidates; the constant was fixed before the run). If any candidate is verified, the smallest-L verified one wins; if none is, the attack falls back to the English chi-squared score over all candidates, as in Step 2. A zero-check candidate is therefore no longer ranked as "worst".
- **Result:** Table 3 (N = 500, 100 trials, seed 486) went from 47 % to 56 % at M = 15 and from 95 % to 100 % at M = 20, i.e. back to the Step 2 numbers, while keeping the Phase 3 gain on non-English plaintext. Nothing got worse; Table 2 is unchanged at 100 %.
- **Status:** SOLVED in Phase 3 (for crib length >= key length + 3). The remaining cases, M <= key length + 2, are tracked in L28.

## L27. Comments can drift away from the code
- **Limitation:** Phase 3 added many explanatory comments and worked examples to `cipher.py` and `attack.py`. Comments are not executed, so a later code change could leave them out of date without any test failing.
- **Viva defence:** Logic was proved unchanged by comparing the syntax tree (comments and docstrings removed) before and after commenting, and the numeric examples in the comments (e.g. HELLO + CAT -> JEENO, ABCDEFGHIJ on 3 rails -> AEIBDFHJCG) were checked against the real functions.
- **Planned fix:** Re-check the examples whenever the code changes; optionally turn them into doctests.
- **Status:** OPEN

## L28. A crib that is too short to verify falls back to English scoring
- **Limitation:** The known-plaintext attack only trusts a candidate that passes at least `MIN_CHECKS` = 3 periodicity checks, which needs M >= L + 3 (L = true key length). When M <= L + 2 the crib gives fewer than 3 checks, nothing can be verified, and the attack falls back to choosing the most English-looking candidate. That fallback works on English text but fails on non-English plaintext such as random letters. Measured separately (outside the test suite, 1,100 trials per row, N = 500, random-letter plaintext, keys 10..20, seed 486): crib 30 recovers 100 %; crib 20 recovers about 74 % (73.8 %), failing only for keys of length 18 to 20; crib 15 recovers about 29 %, succeeding only for keys of length 10 to 12. When M < L the key cannot be recovered at all, whatever the plaintext (L16). Also, a wrong candidate could pass three checks by chance, about 0.8 % of attacks (the figure used to choose `MIN_CHECKS`); this was not observed in testing.
- **Viva defence:** Three clean repeats are the least evidence we accept as proof, and below that the attack honestly reverts to the best guess it has (English statistics) rather than claiming a proof it does not have. A short crib simply contains too little information to pin down a long key.
- **Planned fix:** Return the top few candidates instead of one when nothing is verified; or require a longer crib and report "insufficient crib" instead of guessing. Not done.
- **Status:** OPEN
