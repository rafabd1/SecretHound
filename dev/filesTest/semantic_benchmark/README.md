# Semantic filter benchmark

This corpus contains synthetic values only. None of them grants access to a service. Some cases copy public example formats or use provider-like prefixes so SecretHound exercises the same detector paths used for real findings.

Run the detector and entropy checks without Julia-1:

```bash
python benchmark.py --binary /path/to/secrethound --detector-only
```

Run the full mark-only and suppression checks with a local Julia-1 model:

```bash
python benchmark.py --binary /path/to/secrethound --model /path/to/Julia-1
```

`manifest.json` records the expected detector stage, exact pattern type, semantic verdict, and entropy band for each case. The full run reports label accuracy, rejects unsafe suppression, and requires at least 25% recall for expected obvious false positives. Change that floor with `--min-suppression-recall`; add `--strict-semantic-labels` when every exact verdict mismatch should fail the run.
