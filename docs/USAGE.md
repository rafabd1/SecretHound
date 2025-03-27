# SecretHound Usage Guide

This guide provides detailed usage instructions and examples for SecretHound.

## Basic Usage

SecretHound is designed to be simple to use while providing powerful functionality. The basic syntax is:

```bash
secrethound [flags] [urls/files/directories...]
```

You can provide input directly as arguments or use the `-i` flag to specify an input file or directory.

## Common Scenarios

### 1. Scanning Remote URLs

Scan a single URL:

```bash
secrethound -i https://example.com/script.js
```

Scan multiple URLs:

```bash
secrethound -i https://example.com/script1.js https://example.com/script2.js
```

### 2. Scanning Local Files

Scan a single file:

```bash
secrethound -i /path/to/file.js
```

Scan multiple files:

```bash
secrethound -i /path/to/file1.js /path/to/file2.js
```

### 3. Scanning Directories

Scan all files in a directory:

```bash
secrethound -i /path/to/directory
```

The tool will recursively scan all text-based files, automatically skipping binary files.

### 4. Scanning from a List

Use a file containing URLs or file paths:

```bash
secrethound -i urls.txt
```

Format of urls.txt:

```plaintext
https://example.com/script1.js
https://example.com/script2.js
```

5. Saving Results
Save results to a text file:

```bash
secrethound -i urls.txt -o results.txt
```

Advanced Options
Controlling Concurrency
Adjust number of concurrent workers:

```bash
secrethound -i urls.txt -n 20
```

Higher values = faster scanning but more resource usage.

Setting Timeouts
Modify HTTP request timeout:

```bash
secrethound -i urls.txt -t 60
```
Default is 30 seconds.

Rate Limiting
Control requests per domain:

```bash
secrethound -i urls.txt -l 5
```
Use 0 for automatic adjustment (default).

Retries
Configure retry attempts:
    
```bash
secrethound -i urls.txt -r 5
```
Default is 3 retries.

Verbose Output
Enable detailed logging:
    
```bash
secrethound -i urls.txt -v
```

Custom Regex Patterns
Use custom patterns file:

```bash
secrethound -i urls.txt --regex-file custom_patterns.txt
```

Format of custom_patterns.txt:

```plaintext
REGEX_PATTERNS = {
    "custom_api_key": "ApiKey_[0-9a-zA-Z]{32}",
    "internal_token": "INT_TOKEN_[a-zA-Z0-9]{16}"
}
```

### Combined Examples
Complete Scan

```bash
secrethound -i urls.txt -o results.json -n 15 -t 45 -r 4 -l 3 -v
```

This command:

- Reads URLs from urls.txt
- Saves results to results.json
- Uses 15 concurrent workers
- Sets 45-second timeout
- Retries up to 4 times
- Limits to 3 requests/second per domain
- Enables verbose output

Bug Bounty Workflow
Download and scan JS files:

```bash
# Download JS files
wget -r -l 2 -A .js https://example.com

# Create file list
find ./example.com -name "*.js" > js-files.txt

# Scan files
secrethound -i js-files.txt -o bounty-results.json -v
```

Security Audit
Scan entire project:

```bash
# Scan project directory
secrethound -i /path/to/project -o audit-results.txt -n 30 -v

# Review results
cat audit-results.txt
```

### Exit Codes

- 0: Success
- 1: General error
- 2: Input error (invalid input, no files found, etc.)

### Shell Completion
Generate completion scripts:

```bash
# Bash
secrethound completion bash > secrethound_completion.bash
source secrethound_completion.bash

# Zsh
secrethound completion zsh > ~/.zfunc/_secrethound

# Fish
secrethound completion fish > ~/.config/fish/completions/secrethound.fish

# PowerShell
secrethound completion powershell > secrethound.ps1
. ./secrethound.ps1
```

### Best Practices

1. Start Small: Test with a subset of inputs first to tune settings.

2. Optimize Concurrency:
    - Local files: Set to CPU core count
    - Web requests: Consider target server capacity
    - Respect Rate Limits: Adjust -l flag based on target websites.
3. Review Results: Always verify detected secrets.
4. Custom Patterns: Add patterns specific to your needs.
5. Monitor Resources: Watch memory and CPU usage with large scans.
6. Backup Results: Save important findings securely.