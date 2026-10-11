# SecretHound

![Go Version](https://img.shields.io/github/go-mod/go-version/rafabd1/SecretHound)
![Release](https://img.shields.io/github/v/release/rafabd1/SecretHound?include_prereleases)
![Build Status](https://github.com/rafabd1/SecretHound/workflows/Release%20SecretHound/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/rafabd1/SecretHound?style=social)
![Go Report Card](https://goreportcard.com/badge/github.com/rafabd1/SecretHound)


<p align="center">
    <b>A powerful CLI tool designed to find secrets in files, web pages, and other text sources.</b>
</p>

## Features

- **Multi-Source Scanning**: Process remote URLs, local files, and entire directories.
- **Extensive Pattern Library**: Over 500 regex patterns (currently 555 in the default catalog) to identify a wide range of secrets, including API keys (AWS, Google Cloud, Stripe, etc.), authentication tokens (JWT, OAuth, Bearer), database credentials, private keys, PII (email, phone), Web3 secrets (crypto addresses, private keys), and more.
- **URL/Domain Extraction Mode**: Dedicated mode (`--scan-urls`) to efficiently extract only URL and domain patterns from sources.
- **Flexible Pattern Control**: Fine-tune scans by including or excluding specific pattern categories (e.g., `--include-categories aws,pii`).
- **YAML-Based Patterns**: Patterns are now managed in `core/patterns/default_patterns.yaml` for easier maintenance and extension.
- **Shannon Entropy Validation**: Token-like patterns can enforce entropy thresholds to reduce false positives.
- **Hybrid Context Scoring**: Detection confidence now combines entropy, context signals, and reusable pattern rules instead of hard-only keyword filtering.
- **Concurrent Processing**: Fast multi-threaded architecture for efficient scanning.
- **Domain-Aware Scheduling**: Smart distribution of requests to avoid rate limiting when scanning remote URLs.
- **429-Aware Rate-Limit Hardening**: Strict HTTP `429` handling with adaptive per-domain backoff, plus safe domain discard after persistent throttling.
- **HTTP Status Visibility**: Final scan summary includes explicit status hit counts (e.g., `429=...`, `403=...`, `503=...`).
- **Context Analysis**: Reduces false positives by analyzing surrounding code and context.
- **Optional Semantic Filter**: Reviews validated findings with the local [Julia-1](https://huggingface.co/SupersonicLabs/Julia-1) model and marks likely false positives without hiding uncertain results.
- **Real-Time Progress**: Live updates with progress bar and statistics (can be disabled with `--no-progress` or in `--silent` mode).
- **Multiple Output Formats**: Output results in standard text, JSON, or raw values. Supports a new grouped format (`--group-by-source`) for TXT and JSON, organizing findings by their source URL/file.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/rafabd1/SecretHound.git
cd SecretHound

# Install dependencies
go mod download

# Build the binary
go build -o secrethound ./cmd/secrethound

# Optional: Move to path (Linux/macOS)
sudo mv secrethound /usr/local/bin/

# Optional: Add to PATH (Windows - in PowerShell as Admin)
# Copy-Item .\secrethound.exe C:\Windows\System32\
```

### Using Go Install

```bash
go install github.com/rafabd1/SecretHound/cmd/secrethound@latest
```

### Binary Releases

You can download pre-built binaries for your platform from the [releases page](https://github.com/rafabd1/SecretHound/releases).

## Quick Start

Scan a single URL:

```bash
secrethound https://example.com/script.js
```

Scan multiple URLs:

```bash
secrethound https://example.com/script1.js https://example.com/script2.js
```

Scan from a list of URLs:

```bash
secrethound -i url-list.txt
```

Scan a local file:

```bash
secrethound -i /path/to/file.js
```

Scan an entire directory:

```bash
secrethound -i /path/to/directory
```

Save results to a file:

```bash
secrethound -i url-list.txt -o results.txt
```

### Optional Julia-1 false-positive filter

The semantic filter runs after the existing pattern, context, and entropy checks. It does not replace secret detection. By default, likely false positives remain in the terminal and saved output with `filter_status: likely_false_positive` and `review_priority: low`.

[Julia-1](https://huggingface.co/SupersonicLabs/Julia-1) requires Python 3.11 or newer. Download the official model repository and install its Python runtime:

```bash
python -m pip install huggingface_hub
python -c "from huggingface_hub import snapshot_download; snapshot_download('SupersonicLabs/Julia-1', local_dir='Julia-1')"
python -m pip install -e ./Julia-1
```

The queue and filtering policy are separated from inference, but the bundled Python worker and current CLI flags target Julia-1's classification interface.

CPU inference needs no GPU. Before using `--semantic-device cuda`, install the PyTorch wheel that matches the machine and confirm that `torch.cuda.is_available()` returns `True`.

Review findings without suppressing them:

```bash
secrethound -i ./source --semantic-filter --semantic-model ./Julia-1 -o results.json
```

Suppress only high-confidence likely false positives:

```bash
secrethound -i ./source --semantic-filter --semantic-model ./Julia-1 --suppress-likely-false-positives -o results.json
```

Uncertain findings and classification errors are always retained. A high model score alone cannot suppress a finding: the candidate must also have benign evidence, such as a documentation, fixture, example, generated, or public-key context. Candidate values stay on the local machine and reach the Python worker through a local pipe.

URL/domain extraction and suspicious Bash command findings bypass the secret classifier. PII findings use a separate question, while reserved test ranges and clear PII placeholders are rejected by deterministic validation.

The synthetic benchmark covers positive findings, likely false positives, uncertain cases, and values above and below the entropy gates:

```bash
python dev/filesTest/semantic_benchmark/benchmark.py --binary ./secrethound --model ./Julia-1
```

The PII corpus can be run with `--manifest dev/filesTest/pii_benchmark/manifest.json --corpus dev/filesTest/pii_benchmark/corpus --include-categories pii`.

## Command Line Options

SecretHound supports the following options:

| Flag | Description | Default |
|------|-------------|---------|
| `-i, --input-file` | Input file (URLs/paths), directory, or a single URL/file path as a target argument. | - |
| `-o, --output` | Output file for results (default: stdout). Format (txt, json) inferred from extension. | - |
| `--raw` | Output only raw secret values (affects TXT and grouped JSON file output). | false |
| `--group-by-source` | Group secrets by source URL/file in TXT and JSON output. | false |
| `-t, --timeout` | HTTP request timeout in seconds. | 10 |
| `-r, --retries` | Maximum number of retry attempts for HTTP requests. | 2 |
| `-c, --concurrency` | Number of concurrent workers. | 50 |
| `-l, --rate-limit` | Max requests per second per domain (0 for auto/unlimited). | 0 |
| `-H, --header` | Custom HTTP header to add (e.g., "Authorization: Bearer token"). Can be used multiple times. | - |
| `--verify-tls` | Enable SSL/TLS certificate verification for HTTPS requests. | false |
| `--include-categories` | Comma-separated list of pattern categories to include (e.g., aws,gcp). | all enabled |
| `--exclude-categories` | Comma-separated list of pattern categories to exclude (e.g., pii,url). | none |
| `--scan-urls` | URL Extraction Mode: Scan ONLY for URL/Endpoint patterns (overrides category filters). | false |
| `--patterns-file` | Path to a custom YAML patterns file to replace embedded defaults. | - |
| `--semantic-filter` | Review validated findings with a local Julia-1 model. | false |
| `--semantic-model` | Path to the local Julia-1 repository and weights. | - |
| `--semantic-python` | Python executable used by the Julia-1 worker. | python |
| `--semantic-device` | Julia-1 inference device (`cpu` or `cuda`). | cpu |
| `--semantic-fp-threshold` | Minimum score for a likely false-positive verdict. | 0.80 |
| `--semantic-decision-threshold` | Minimum score for a normal-priority verdict; lower scores become uncertain. | 0.60 |
| `--semantic-batch-size` | Maximum candidates per semantic inference batch. | 16 |
| `--semantic-queue-size` | Maximum candidates waiting for semantic review. | 512 |
| `--semantic-batch-wait` | Maximum wait used to fill an inference batch. | 25ms |
| `--semantic-timeout` | Timeout for one inference batch. | 30s |
| `--semantic-startup-timeout` | Timeout for loading the model worker. | 2m |
| `--semantic-max-length` | Maximum combined Julia-1 input length. | 8192 |
| `--semantic-head-length` | Julia-1 question and options token budget. | 512 |
| `--suppress-likely-false-positives` | Omit only findings classified as likely false positives. | false |
| `--max-file-size` | Maximum file size to scan in MB (0 for no limit). | 0 |
| `--list-patterns` | List available pattern categories and patterns, then exit. | false |
| `-v, --verbose` | Enable verbose logging output. | false |
| `-n, --no-progress` | Disable the progress bar display. | false |
| `-s, --silent` | Silent mode (suppress progress bar and info logs). | false |

## Documentation

For more detailed information, see the [documentation directory](docs/):

- [Usage Examples](docs/USAGE.md) - Detailed usage examples
- [Technical Details](docs/TECHNICAL.md) - Internal architecture and design
- [Supported Secrets](docs/SUPPORTED_SECRETS.md) - List of secret types detected
- [Changelog](CHANGELOG.md) - Check the latest updates and version history

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Third-party adapted pattern content is documented in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), including attribution and license terms for imported/adapted regex pattern sources.


