# SecretHound Usage Guide

This guide documents the current CLI behavior and examples for SecretHound `v1.1.0`.

## Basic Syntax

```bash
secrethound [flags] [target]
```

You can pass a target directly (`URL`, local file, or directory), or use `-i/--input-file` with a file containing URLs/paths.

## Quick Examples

Scan a single URL:

```bash
secrethound https://example.com/app.js
```

Scan a local file:

```bash
secrethound ./app.bundle.js
```

Scan a directory recursively:

```bash
secrethound ./dist
```

Scan using an input list file:

```bash
secrethound -i ./targets.txt
```

Save output to JSON:

```bash
secrethound -i ./targets.txt -o ./results.json
```

## Flags (Current)

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input-file` | Input file containing URLs or local paths (alternative to direct target arg) | - |
| `-o, --output` | Output file (`.txt` or `.json`) | stdout |
| `--raw` | Output only secret values (affects file output) | false |
| `--group-by-source` | Group findings by URL/file in output | false |
| `-t, --timeout` | HTTP timeout (seconds) | 10 |
| `-r, --retries` | Max HTTP retries | 2 |
| `-c, --concurrency` | Number of concurrent workers | 50 |
| `-l, --rate-limit` | Max req/s per domain (`0` = auto/unlimited) | 0 |
| `-H, --header` | Custom header, repeatable | - |
| `--insecure` | Disable TLS cert verification | true |
| `--max-file-size` | Max local file size in MB (`0` = no limit) | 0 |
| `--include-categories` | Include only selected categories (comma-separated) | all enabled |
| `--exclude-categories` | Exclude selected categories (comma-separated) | none |
| `--scan-urls` | Scan only URL/endpoint patterns | false |
| `--patterns-file` | Use custom YAML patterns file | built-in |
| `--list-patterns` | List loaded categories/patterns and exit | false |
| `-v, --verbose` | Verbose logs | false |
| `-n, --no-progress` | Disable progress bar | false |
| `-s, --silent` | Suppress progress/info logs | false |

## Output Modes

Standard TXT output:

```bash
secrethound -i ./targets.txt -o ./output.txt
```

Standard JSON output:

```bash
secrethound -i ./targets.txt -o ./output.json
```

Grouped output:

```bash
secrethound -i ./targets.txt --group-by-source -o ./grouped.json
```

Raw values:

```bash
secrethound -i ./targets.txt --raw -o ./raw.txt
```

## Pattern and Category Control

List all currently loaded patterns:

```bash
secrethound --list-patterns
```

Include only specific categories:

```bash
secrethound -i ./targets.txt --include-categories aws,gcp,llm
```

Exclude noisy categories:

```bash
secrethound -i ./targets.txt --exclude-categories pii
```

Use a custom pattern file:

```bash
secrethound -i ./targets.txt --patterns-file ./my_patterns.yaml
```

## URL-Only Extraction Mode

If you want endpoints/URLs only:

```bash
secrethound -i ./targets.txt --scan-urls
```

This mode overrides category filtering and scans only URL/endpoint patterns.

## Networking and Performance Examples

Higher throughput:

```bash
secrethound -i ./targets.txt -c 80 -r 1
```

Fixed domain rate:

```bash
secrethound -i ./targets.txt -l 5
```

Custom auth headers:

```bash
secrethound -i ./targets.txt -H "Authorization: Bearer <token>" -H "Cookie: session=..."
```

## Commands

Version:

```bash
secrethound version
```

Help:

```bash
secrethound --help
```

## Notes

- `--insecure` is enabled by default in the current release.
- `--max-file-size 0` means unlimited local file size.
- `pii` is disabled by default unless explicitly included.
- For runtime truth (final loaded patterns/flags), always validate with `--help` and `--list-patterns`.
