# SecretHound Documentation

Welcome to the SecretHound documentation. This directory contains detailed information about the tool, its features, and how to use it.

## Documentation Index

- [Technical Documentation](TECHNICAL.md): Detailed information about the technical architecture and design of SecretHound.
- [Usage Guide](USAGE.md): Comprehensive examples and scenarios for using SecretHound.
- [Supported Secrets](SUPPORTED_SECRETS.md): List of all secret types that SecretHound can detect.

## Getting Started

If you're new to SecretHound, we recommend starting with the [README.md](../README.md) in the root directory, which provides an overview of the tool and basic usage instructions.

## Additional Resources

- [Examples Directory](../examples/): Contains example files you can use to test SecretHound.
- [Issue Tracker](https://github.com/rafabd1/SecretHound/issues): Report bugs or request features.

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
- **Multiple Output Formats**: Output to formatted text

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
| `-H, --header` | Custom HTTP header (format: 'Name: Value') | - |
| `--insecure` | Disable SSL/TLS certificate verification | false |
| `-v, --verbose` | Enable verbose output | false |

## Input Sources

SecretHound can process various input sources:

1. **Remote URLs**: Any HTTP/HTTPS accessible URL
2. **Local Files**: Any text-based file format
3. **Directories**: Recursively scan all text files in a directory
4. **URL Lists**: Text files containing URLs or file paths (one per line)

Lists can be specified with the `-i` flag or by providing the filepath directly as an argument. URLs can be provided directly as arguments.

## Supported Patterns

SecretHound can detect over 100 different types of secrets, including:

- API keys (Google, AWS, Firebase, etc.)
- Access tokens (Facebook, Twitter, GitHub, etc.)
- Credentials (passwords, Basic and Bearer tokens)
- Private keys (RSA, SSH, PGP)
- JWT tokens
- Sensitive URLs (Firebase, AWS S3)
- Database connection strings
- And much more!

For a complete list of supported regexes, see the [Supported Secrets](SUPPORTED_SECRETS.md) document.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
