# Benchmarks
`nexus-shield bench [--seed N] [--json]` runs a seeded, synthetic evaluation (see `nexus_shield/bench.py`). Reference output (seed 0):

**Detection** (4 attack families with mutated hosts/filenames, skipped steps and decoy commands; benign sessions share words like `wget`, `chmod`, `uname`):

| method | recall on held-out variants | benign false-positive rate |
|---|---|---|
| passive vaccine (fuzzy clusters + benign stripping + gating) | 1.00 | 0.00 |
| exact token-set signature (baseline) | 0.22 | 0.00 |

**Attribution** (two emitters 600 Hz apart, 1024 samples @ 250 kS/s):

| SNR (dB) | mean CFO error (Hz) | emitters separated |
|---|---|---|
| 0 | ~690 | 0% |
| 5 | ~234 | 0% |
| 10 | ~70 | 80% |
| 20 | ~8 | 100% |
| 30 | ~1 | 100% |

**Read this carefully:** the corpus is synthetic and its mutations are ones the token approach handles well; a real attacker who
changes vocabulary would evade it. Attribution needs roughly 20 dB SNR at this tolerance; below ~10 dB it is unreliable. Use these numbers to compare
changes to the code, not to predict field performance.
