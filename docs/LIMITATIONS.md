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
- **Status:** ACCEPTED

## L3. Vigenere is vulnerable to Kasiski / Index of Coincidence
- **Limitation:** A short key or a key with a repeated pattern leaves a detectable period. Kasiski examination and the Index of Coincidence can recover the key length, then frequency analysis recovers each key letter.
- **Viva defence:** A minimum key length of 10 raises the amount of ciphertext an attacker needs, and the Rail Fence stage scrambles letter positions so the period is not directly visible in the ciphertext. This is a mitigation, not a cure.
- **Planned fix:** Implement the attacks in a later step and measure how much ciphertext is needed to break keys of different lengths, with and without Rail Fence.
- **Status:** OPEN

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
- **Status:** OPEN

## L13. Pure-Python performance
- **Limitation:** All functions are O(N) but implemented with Python-level loops and temporary lists, so very large inputs (many MB) will be slow and memory-hungry compared with compiled code.
- **Viva defence:** Linear time is the relevant complexity result; constant factors are irrelevant at the text sizes this project handles.
- **Planned fix:** Measure in the benchmark step.
- **Status:** OPEN
