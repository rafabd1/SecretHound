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
secrethound https://example.com/script.js
```

Scan multiple URLs:

```bash
secrethound https://example.com/script1.js https://example.com/script2.js
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

### 5. Saving Results

Save results to a text file:

```bash
secrethound -i urls.txt -o results.txt
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

## Advanced Options

### Controlling Concurrency
Adjust number of concurrent workers:

```bash
secrethound -i urls.txt -n 20
```
Higher values = faster scanning but more resource usage.

### Setting Timeouts
Modify HTTP request timeout:

```bash
secrethound -i urls.txt -t 60
```
Default is 30 seconds.

### Rate Limiting
Control requests per domain:

```bash
secrethound -i urls.txt -l 5
```
Use 0 for automatic adjustment (default).

### Retries
Configure retry attempts:
    
```bash
secrethound -i urls.txt -r 5
```
Default is 3 retries.

### Verbose Output
Enable detailed logging:
    
```bash
secrethound -i urls.txt -v
```

### Custom HTTP Headers

You can specify custom HTTP headers for requests using the `-H` flag. This is useful for authentication, setting cookies, or customizing the user agent:

```bash
secrethound -i urls.txt -H "User-Agent: Mozilla/5.0 Firefox" -H "Authorization: Bearer token123"
```

If you specify a User-Agent header, it will override the default user agent.

### Bypassing SSL Certificate Verification

For sites with invalid or self-signed certificates, you can disable certificate verification:

```bash
secrethound -i urls.txt --insecure
```

**Note**: This reduces security as it doesn't validate the identity of the remote server.

### Combined Examples
Complete Scan

```bash
secrethound -i urls.txt -o results.txt -n 15 -t 45 -r 4 -l 3 -v --insecure -H "User-Agent: Custom-Agent"
```

This command:

- Reads URLs from urls.txt
- Saves results to results.txt
- Uses 15 concurrent workers
- Sets 45-second timeout
- Retries up to 4 times
- Limits to 3 requests/second per domain
- Enables verbose output
- Disables SSL certificate verification
- Uses a custom User-Agent

### Bug Bounty Workflow
Download and scan JS files:

```bash
# Download JS files
wget -r -l 2 -A .js https://example.com

# Create file list
find ./example.com -name "*.js" > js-files.txt

# Scan files
secrethound -i js-files.txt -o bounty-results.txt -v
```

### Security Audit
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
    
3. Custom Headers:
    - Use custom headers for sites requiring authentication
    - Set appropriate User-Agent to avoid being blocked
    
4. SSL Certificate Issues:
    - If websites report certificate errors, use `--insecure` option
    - Be aware that disabling certificate verification reduces security
    
5. Review Results: Always verify detected secrets.

6. Monitor Resources: Watch memory and CPU usage with large scans.

7. Backup Results: Save important findings securely.

## Advanced Usage

### Filtering by Pattern Category

You can control which types of secrets are scanned by specifying categories.

List available categories and patterns:
```bash
secrethound --list-patterns
```

Scan only for AWS and Google Cloud secrets:
```bash
secrethound --include-categories aws,gcp -i <target>
```

Scan for all secrets except Personal Identifiable Information (PII):
```bash
secrethound --exclude-categories pii -i <target>
```

### URL/Domain Extraction Mode

If you only want to find URLs and domains within files/sources:
```bash
secrethound --scan-urls -i <target>
```

### Grouping Output by Source

For scans with many sources, you can group the findings by the source URL or file path. This affects TXT and JSON output.

```bash
secrethound --group-by-source -i url-list.txt -o results_grouped.txt
secrethound --group-by-source -i url-list.txt -o results_grouped.json
```

**Example Grouped TXT Output (`results_grouped.txt`):**
```text
https://example.com/file1.js:
	[api-key] S3CR3T_K3Y_V4LU3_F1L31
	URL: https://example.com/file1.js
	Line: 42
	Context: var apiKey = "S3CR3T_K3Y_V4LU3_F1L31";
	Description: Generic API Key pattern

	[jwt-token] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
	URL: https://example.com/file1.js
	Line: 101
	Context: const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
	Description: JSON Web Token

https://example.com/another/script.js:
	[aws-secret-key] wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
	URL: https://example.com/another/script.js
	Line: 12
	Context: aws.secretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
	Description: AWS Secret Access Key

```

**Example Grouped JSON Output (`results_grouped.json`):**
```json
{
  "https://example.com/another/script.js": [
    {
      "type": "aws-secret-key",
      "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "source_url": "https://example.com/another/script.js",
      "line_number": 12,
      "context": "aws.secretAccessKey = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\";",
      "description": "AWS Secret Access Key"
    }
  ],
  "https://example.com/file1.js": [
    {
      "type": "api-key",
      "value": "S3CR3T_K3Y_V4LU3_F1L31",
      "source_url": "https://example.com/file1.js",
      "line_number": 42,
      "context": "var apiKey = \"S3CR3T_K3Y_V4LU3_F1L31\";",
      "description": "Generic API Key pattern"
    },
    {
      "type": "jwt-token",
      "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
      "source_url": "https://example.com/file1.js",
      "line_number": 101,
      "context": "const token = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\";",
      "description": "JSON Web Token"
    }
  ]
}
```

### Using Raw Output Mode

To output only the raw secret values (one per line for TXT, or an array of strings for JSON if not grouped, or map source -> []string for grouped JSON):

```bash
secrethound --raw -i <target>
# Example output (TXT or stdout):
# S3CR3T_K3Y_V4LU3_F1L31
# wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

```bash
secrethound --raw --group-by-source -i <target> -o results_raw_grouped.json
# Example output (results_raw_grouped.json):
# {
#   "https://example.com/file1.js": [
#     "S3CR3T_K3Y_V4LU3_F1L31",
#     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
#   ],
#   "https://example.com/another/script.js": [
#     "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#   ]
# }
```