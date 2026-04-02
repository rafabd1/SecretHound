# SecretHound Changelog

## v1.2.0 (2026-04-02)

### Networking Reliability
- Hardened URL fetching pipeline with safer retry accounting and improved domain-state handling.
- Added adaptive HTTP `429` backoff strategy with bounded cycles and safe domain discard to avoid endless retry loops.
- Simplified and tightened rate-limit detection to focus on explicit HTTP `429` semantics.
- Improved scheduler/domain coordination so blocked/discarded-domain behavior is more deterministic under high concurrency.
- Added safer queue cleanup/accounting when domains are discarded after repeated `429` responses.

### Runtime Visibility
- Final processing summary now includes clearer HTTP status insights for troubleshooting (status-code oriented reporting).
- Domain discard alerts were improved to be explicit about the reason for discard (`persistent HTTP 429` after bounded backoff).
- Logging flow was refined so local and remote findings are consistently emitted in real time.

### Finding Risk Classification
- Added per-finding risk classification model with four levels:
  - `informative`
  - `low`
  - `medium`
  - `high`
- Added risk-aware colored terminal finding logs by severity level.
- Kept URL extraction mode (`--scan-urls`) behavior stable by emitting findings as `INFO` in that mode.
- Added structured `risk` metadata to non-raw output formats (`json`, `txt`, `csv`).
- Implemented initial mapping by pattern type/category with targeted overrides for high-impact credentials and commonly public keys.
- Tuned risk model and token heuristics:
  - `session_token` classified as `low`
  - `stripe_test_secret_key` classified as `informative`
  - publishable/public-style keys kept in lower severity bands unless misuse risk is clearer.

### Detection Quality
- Refined `huggingface_api_token` detection regex with stricter boundaries, reducing false positives in minified payloads.
- Reduced `session_token` false positives by tightening contextual requirements and adding penalties for common config/reference fields (for example `referenceId`, `tokenLogin`, retry config snippets).

### Documentation
- Refreshed `docs/USAGE.md` to match current CLI behavior and defaults.
- Clarified rate-limit/backoff behavior in docs, including distinction between adaptive mode (`-l 0`) and fixed RPS mode.
- Updated TLS verification docs to reflect current default behavior (`--verify-tls` to enable certificate verification).
- Documented risk levels and output behavior in:
  - `docs/USAGE.md`
  - `docs/TECHNICAL.md`
  - `docs/SUPPORTED_SECRETS.md`

## v1.1.0 (2026-04-01)

### New Features
- Expanded default pattern catalog to **555** YAML-managed patterns across multiple categories.
- Added dedicated categories to improve organization and scanning precision:
  - `llm`
  - `bash`
  - `communication`
  - `observability`
- Added extensive provider coverage from `secrets-patterns-db` with in-project tuning and context scoring controls.
- Added grouped dedup behavior improvements:
  - duplicate findings are aggregated with occurrences count
  - contextual evidence is retained as arrays for repeated matches

### Improvements
- Pattern loading diagnostics were significantly improved:
  - load statistics now track `loaded/selected/total`
  - compile and validation failures are surfaced with detailed logs
  - invalid `excluderegexes` are reported per pattern
- Added explicit Shannon entropy validation flow in the detection pipeline to better gate token-like candidates and reduce false positives.
- Introduced a hybrid confidence scoring heuristic (context boosts/penalties + hard guards + entropy) replacing heavy dependence on hardcoded keyword exclusion.
- Startup summary now reports pattern loading as `loaded/total` for clearer visibility.
- `--list-patterns` now reflects only successfully compiled/loaded patterns.
- Pattern taxonomy was refined:
  - `gitlab_personal_token` aligned with code/platform token category
  - multiple imported patterns recategorized to reduce ambiguity and improve filter usability.

### Bug Fixes
- Fixed root CLI flag exposure for custom pattern files (`--patterns-file`) so it works in the standard command path.
- Fixed custom-pattern listing behavior where invalid regex definitions could appear as loadable in listing output.
- Fixed raw output flow and logging reliability from prior refactors (writer close error visibility and output path stability).

### Detection Quality
- Hardened imported provider patterns with:
  - `requiredcontextany` constraints
  - stronger entropy thresholds
  - revised descriptions and semantic category placement
- Reduced common false positives in imported generic service rules by tightening service anchors.
- Disabled `pii` category by default to avoid noisy scans unless explicitly requested.

### Release & Docs
- Release workflow modernized to use GitHub-generated release notes (`generate_release_notes: true`).
- `SUPPORTED_SECRETS.md` synchronized with current YAML pattern inventory and category structure.
- Added `THIRD_PARTY_NOTICES.md` and explicit attribution/licensing references for adapted `secrets-patterns-db` pattern content (CC BY-SA 4.0).

## v1.0.1 (2025-12-05)

### New Features
- **Max File Size Flag**: Added `--max-file-size` flag to set the maximum file size for local file scanning, allowing users to skip large files that may slow down scans.
- **Netlify Access Token Pattern**: Added new detection pattern for Netlify Access Tokens.

### Improvements
- **Enhanced Pattern Accuracy**: Refined multiple regex patterns to significantly reduce false positives:
  - **MAC Address**: Now requires explicit keywords (`mac_address`, `ethernet_addr`, `hw_addr`) and only matches colon-separated format to avoid false positives from SVG paths.
  - **IPv4 Address**: More restrictive pattern requiring explicit keywords (`ip_addr`, `host_addr`, `server_ip`). Added exclusions for OIDs (`1.3.6.1`, `2.16.840`).
  - **IPv6 Address**: Simplified regex requiring `ipv6` or `ip6` keywords. Added exclusions for SHA-256 fingerprints.
  - **PayPal/Braintree**: Now requires specific keywords (`paypal_client_id`, `braintree_secret`) instead of loose matching. Added exclusions for CSS class names.
  - **Private Key Variable**: Added exclusions for tracking/event patterns (`click_`, `export_`, `track_`).
  - **Phone Number**: More restrictive US format pattern, now keyword-dependent.

### Bug Fixes
- Fixed false positives where SVG path data was being detected as MAC addresses.
- Fixed false positives where OIDs (Object Identifiers) were being detected as IPv4 addresses.
- Fixed false positives where SHA-256 fingerprints were being detected as IPv6 addresses.
- Fixed false positives where CSS class names containing "paypal" were being detected as PayPal credentials.
- Fixed false positives where event tracking strings were being detected as private keys.
- Fixed Private Key Content pattern to require actual key data after the BEGIN header, preventing false positives from standalone headers.

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

