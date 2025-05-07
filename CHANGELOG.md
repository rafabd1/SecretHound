# SecretHound Changelog

## v1.0.0 (2025-05-06)

### New Features
- **Expanded Pattern Library**: Introduced new pattern categories including PII (Personally Identifiable Information) and Web3 (e.g., Ethereum/Bitcoin addresses, private keys), increasing total patterns to over 60.
- **URL/Domain Extraction Mode**: Added `--scan-urls` flag to exclusively scan for URL and domain patterns, overriding other category filters.
- **Grouped Output Format**: Introduced `--group-by-source` flag to group found secrets by their source URL/file in TXT and JSON output formats, improving readability for large scans.
- **Pattern Category Control**: Implemented `--include-categories` and `--exclude-categories` flags to allow users to specify which pattern categories to use or ignore during scans.

### Improvements
- **Enhanced Pattern Accuracy**: Iteratively refined numerous existing patterns (IPv4, Bitcoin Address, Email Address, MAC Address, Generic Domain, Session Token) to significantly reduce false positives and improve detection of legitimate secrets based on extensive real-world test cases.
- **Log Custom Headers**: Initial configuration log now indicates if custom HTTP headers (`-H`) are being used.
- **Queue Logic & Rate Limiting**: Improved URL processing queue logic and refined the auto mode for rate limiting for more efficient and considerate scanning.
- **CLI Options Refinement**: Corrected and improved behavior of `--silent` and `--no-progress` flags.
- **Regex Engine Compatibility**: Added internal logging for regex compilation errors and refactored incompatible regex syntax (e.g., unsupported lookaheads) to ensure all patterns load correctly with Go's standard regex engine.

### Bug Fixes
- **JSON Output Formatting**: Addressed issues to ensure valid JSON output, especially when no secrets are found or in raw mode.
- **Progress Bar Rendering**: Fixed a bug where the progress bar would sometimes only update when new logs were printed, ensuring it now refreshes independently and consistently.
- **Execution Deadlocks**: Resolved potential deadlocks and improved goroutine management for more stable execution during long scans.
- **Pattern Loading**: Fixed an issue where the incorrect number of loaded patterns was reported when using category filters, ensuring accurate reflection of active patterns.

## v0.2.0 (2025-04-03)

### Improvements
- Added support for skipping SSL/TLS certificate verification with `--insecure`
- Complete redesign of the regex pattern system
- Added support for custom HTTP headers with `-H/--header`
- Fixed timeout and concurrency issues
- Fixed `-r/--retries` parameter that wasn't being applied
- Reorganized patterns package for better maintenance
- Redesigned error handling system
- Temporarily disabled `--regex-file` option

### Bug Fixes
- Fixed issue with URLs having invalid certificates
- Resolved timeout problems in large scans
- Improved thread synchronization to prevent resource leaks
- Fixed false positive issues in certain regex patterns

### Technical Changes
- Added new error type for certificate issues
- Improved HTTP response handling logic
- Added utility functions for certificate validation
- Optimized regex patterns for better performance and accuracy

## v0.1.1 (2025-03-28)

### Improvements
- Removed global execution timeout allowing scans to run without time constraints
- Enhanced error logging with better visibility for critical errors
- Improved log output reducing redundant messages and clarifying statistics
- Fixed build information display in version command
- Added proper build date and git commit tracking

### Bug Fixes
- Fixed issue with timeout prematurely ending large scans
- Resolved silent errors in verbose mode
- Enhanced terminal output coordination for cleaner display

### Technical Changes
- Added build script with proper ldflags for version information
- Improved GitHub Actions workflow for releases
- Updated documentation for clarity and completeness

## v0.1.0 (2025-03-26)

### Core Features
- Multi-threaded scanning of remote URLs and local files
- 50+ built-in regex patterns to detect common API keys and secrets
- Smart request scheduling with domain-aware rate limiting
- Detection and handling of WAF blocks and rate limits
- Real-time progress bar with detailed statistics
- Structured output with context for each discovered secret

### Technical Highlights
- Concurrent processing architecture for maximum performance
- Configurable timeout and retry mechanisms
- Customizable regex patterns via external file
- Cross-platform support (Windows, macOS, and Linux)

### Getting Started
Download the appropriate binary for your platform or install via:
```bash
go install github.com/rafabd1/SecretHound/cmd/secrethound@latest
```

Check the README for detailed usage instructions and examples.

