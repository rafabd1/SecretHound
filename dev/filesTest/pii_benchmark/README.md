# PII semantic benchmark

This corpus contains synthetic records only. It checks the separate PII prompt against plausible values, placeholders, reserved test ranges, and person names near identity labels. URL and domain findings do not enter this filter.

Run detector checks without Julia-1:

```bash
python dev/filesTest/semantic_benchmark/benchmark.py --binary /path/to/secrethound --manifest dev/filesTest/pii_benchmark/manifest.json --corpus dev/filesTest/pii_benchmark/corpus --include-categories pii --detector-only
```

Run the full mark-only and suppression checks:

```bash
python dev/filesTest/semantic_benchmark/benchmark.py --binary /path/to/secrethound --model /path/to/Julia-1 --manifest dev/filesTest/pii_benchmark/manifest.json --corpus dev/filesTest/pii_benchmark/corpus --include-categories pii --min-suppression-recall 1.0
```

The suppression check fails if the model hides plausible or uncertain PII, or misses any labeled obvious false positive.
