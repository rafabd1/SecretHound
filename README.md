# SecretHound

SecretHound is a powerful CLI tool designed to find secrets in JavaScript files, web pages, and other text sources. Built for security professionals, bug bounty hunters, and developers, it helps identify accidentally exposed API keys, tokens, and credentials.

![SecretHound Banner](https://raw.githubusercontent.com/rafabd1/SecretHound/main/docs/banner.png)

## Features

- **Multi-Source Scanning**: Process remote URLs, local files, and entire directories
- **Intelligent Detection**: 50+ regex patterns to identify different types of secrets
- **Concurrent Processing**: Fast multi-threaded architecture for efficient scanning
- **Domain-Aware Scheduling**: Smart distribution of requests to avoid rate limiting
- **WAF/Rate Limit Evasion**: Automatic detection and handling of security measures
- **Context Analysis**: Reduces false positives by analyzing surrounding code
- **Real-Time Progress**: Live updates with progress bar and statistics
- **Multiple Output Formats**: Output to JSON or formatted text

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/rafabd1/SecretHound.git
cd SecretHound

# Install dependencies
go mod download

# Build the binary
go build -o secrethound

# Optional: Move to path (Linux/macOS)
sudo mv secrethound /usr/local/bin/

# Optional: Add to PATH (Windows - in PowerShell as Admin)
# Copy-Item .\secrethound.exe C:\Windows\System32\
```

### Using Go Install

```bash
go install github.com/rafabd1/SecretHound@latest
```

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
| `-i, --input` | Input file, directory, or URL list | - |
| `-o, --output` | Output file for results | - |
| `-t, --timeout` | HTTP request timeout in seconds | 30 |
| `-r, --retries` | Maximum number of retry attempts | 3 |
| `-n, --concurrency` | Number of concurrent workers | 10 |
| `-l, --rate-limit` | Requests per second per domain (0 = auto) | 0 |
| `--regex-file` | File containing custom regex patterns | - |
| `-v, --verbose` | Enable verbose output | false |

## Documentation

For more detailed information, see the [documentation directory](docs/):

- [Usage Examples](docs/USAGE.md) - Detailed usage examples
- [Technical Details](docs/TECHNICAL.md) - Internal architecture and design
- [Supported Secrets](docs/SUPPORTED_SECRETS.md) - List of secret types detected

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- Inspired by various secret scanning tools
- Built with [Go](https://golang.org/)
- Uses [Cobra](https://github.com/spf13/cobra) for CLI functionality