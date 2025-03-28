# SecretHound Changelog

## v0.1.1 (2024-07-05)

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

## v0.1.0 (2024-06-15)

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
