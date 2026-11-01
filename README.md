# CT-486 Network & Information Security — CCP

A two-stage classical cipher: **Stage 1 Vigenere**, **Stage 2 Rail Fence**.
Python 3, standard library only (no pip installs).

## Progress

| Step | Scope | Status |
|------|-------|--------|
| 1 | Core cipher (`cipher.py`), unit tests, repo hygiene, limitations log | Done |

### Step 1 — what exists

- `cipher.py`
  - `sanitize`, `validate_key` (key and rails are two separate inputs)
  - Shift cipher (baseline for later comparison)
  - Vigenere encrypt/decrypt (Stage 1)
  - Rail Fence via `rail_order` permutation (Stage 2)
  - `custom_encrypt` (Vigenere, then Rail Fence) and `custom_decrypt` (Rail Fence undone first, then Vigenere)
- `tests/test_cipher.py` — known vectors, 5000 seeded random round-trips, edge cases, validation
- `docs/LIMITATIONS.md` — running log of every known limitation, with viva defence and planned fix

Not yet built: GUI, attack code, benchmarks.

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

## Security notes

This is a coursework project built on classical ciphers. It is **not** secure
for real data — see `docs/LIMITATIONS.md`. Never commit keys, passwords or
`.env` files (they are covered by `.gitignore`).
