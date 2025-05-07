# SecretHound

![Go Version](https://img.shields.io/github/go-mod/go-version/rafabd1/SecretHound)
![Release](https://img.shields.io/github/v/release/rafabd1/SecretHound?include_prereleases)
![Build Status](https://github.com/rafabd1/SecretHound/workflows/Release%20SecretHound/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/rafabd1/SecretHound?style=social)
![Go Report Card](https://goreportcard.com/badge/github.com/rafabd1/SecretHound)

<!-- <p align="center">
    <img src="https://raw.githubusercontent.com/rafabd1/SecretHound/main/docs/banner.png" alt="SecretHound Banner" width="600">
</p> -->

<p align="center">
    <b>A powerful CLI tool designed to find secrets in JavaScript files, web pages, and other text sources.</b>
</p>

## Features

- **Multi-Source Scanning**: Process remote URLs, local files, and entire directories.
- **Extensive Pattern Library**: Over 60 meticulously crafted regex patterns to identify a wide range of secrets, including API keys (AWS, Google Cloud, Stripe, etc.), authentication tokens (JWT, OAuth, Bearer), database credentials, private keys, PII (email, phone), Web3 secrets (crypto addresses, private keys), and more.
- **URL/Domain Extraction Mode**: Dedicated mode (`--scan-urls`) to efficiently extract only URL and domain patterns from sources.
- **Flexible Pattern Control**: Fine-tune scans by including or excluding specific pattern categories (e.g., `--include-categories aws,pii`).
- **Concurrent Processing**: Fast multi-threaded architecture for efficient scanning.
- **Domain-Aware Scheduling**: Smart distribution of requests to avoid rate limiting when scanning remote URLs.
- **WAF/Rate Limit Evasion**: Strategies for handling common web security measures.
- **Context Analysis**: Reduces false positives by analyzing surrounding code and context.
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
| `--insecure` | Disable SSL/TLS certificate verification. | false |
| `--include-categories` | Comma-separated list of pattern categories to include (e.g., aws,gcp). | all enabled |
| `--exclude-categories` | Comma-separated list of pattern categories to exclude (e.g., pii,url). | none |
| `--scan-urls` | URL Extraction Mode: Scan ONLY for URL/Endpoint patterns (overrides category filters). | false |
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

## Acknowledgements

- Built with [Go](https://golang.org/)
- Uses [Cobra](https://github.com/spf13/cobra) for CLI functionality
<!-- - Special thanks to all [contributors](https://github.com/rafabd1/SecretHound/graphs/contributors) -->

<p align="center">
    <sub>Made with 🖤 by Rafael (github.com/rafabd1)</sub>
</p>

<p align="center">
    <a href="https://ko-fi.com/rafabd1" target="_blank"><img src="https://storage.ko-fi.com/cdn/kofi2.png?v=3" alt="Buy Me A Coffee" style="height: 60px !important;"></a>
</p>

