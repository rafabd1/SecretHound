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
- Special thanks to all [contributors](https://github.com/rafabd1/SecretHound/graphs/contributors)

<p align="center">
    <sub>Made with 🖤 by Rafael (github.com/rafabd1)</sub>
</p>

<p align="center">
    <a href="https://ko-fi.com/rafabd1" target="_blank"><img src="https://storage.ko-fi.com/cdn/kofi2.png?v=3" alt="Buy Me A Coffee" style="height: 60px !important;"></a>
</p>