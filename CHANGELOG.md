# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-11-28

### Added

#### IPv6 Support
- Added full IPv6 (AAAA record) resolution support alongside IPv4
- Added Cloudflare IPv6 IP ranges detection (7 ranges)
- Results now display both IPv4 and IPv6 addresses with individual Cloudflare status indicators

#### Multiple IPs Detection
- DNS resolution now returns ALL IPs for a domain, not just the first one
- Each IP is individually checked against Cloudflare ranges
- Output displays all IPs in list format: `v4:[ip1, ip2, ip3]`
- CSV export uses semicolon separator for multiple IPs

#### Progress Bar
- Added real-time progress bar during subdomain scanning using `tqdm`
- Shows elapsed time and estimated time remaining
- Displays live stats: found count and cloudflare count
- Automatically disabled in quiet mode (`-q`)

#### Wordlist Improvements
- Added support for comments in wordlists (lines starting with `#` are ignored)
- Empty lines are automatically skipped

#### Dynamic Cloudflare IP Ranges
- Added dynamic fetching of Cloudflare IP ranges from official API endpoints (`https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`)
- Added fallback mechanism to hardcoded ranges if API is unreachable
- Added status logging indicating whether ranges were fetched from API or fallback

#### Multiple Output Formats
- Added JSON output format (`-f json`)
- Added YAML output format (`-f yaml`) with custom serializer (no external dependency)
- Added CSV output format (`-f csv`)
- Enhanced normal text output with structured report sections

#### Multiple Wordlists Support
- Added ability to specify multiple wordlist files using repeated `-w` flags
- Wordlists are automatically merged and deduplicated
- Each loaded wordlist is logged individually

#### Verbosity Controls
- Added verbose mode (`-v, --verbose`) to show all results including "not found" entries
- Added quiet mode (`-q, --quiet`) for minimal output showing only found IPs
- Implemented structured logging system with verbosity levels

#### Root Domain Check
- Added automatic checking of the root domain before subdomain enumeration

#### Scan Summary
- Added comprehensive end-of-scan summary showing:
  - Total domains checked
  - Count of found (non-Cloudflare) IPs
  - Count of Cloudflare-protected domains
  - Count of not found domains
  - Count of errors (if any)

#### Data Classes and Type Hints
- Added `ResolveResult` dataclass for structured result storage with list-based IP fields
- `ResolveResult.ipv4` and `ResolveResult.ipv6` are now `list[str]` to store multiple IPs
- `ResolveResult.ipv4_cloudflare` and `ResolveResult.ipv6_cloudflare` store which IPs are behind CF
- Added `ipv4_non_cf` and `ipv6_non_cf` properties to filter non-Cloudflare IPs
- Added `ScanReport` dataclass for complete scan reports with serialization support
- Added `CloudflareIPRanges` class for IP range management
- Added `ReportWriter` class for multi-format output handling
- Added `CloudRip` main scanner class with encapsulated state
- Added `Colors` class for terminal color constants
- Added `OutputFormat` enum for output format types
- Added comprehensive type hints throughout the codebase

### Changed

#### Architecture
- Refactored from procedural to object-oriented architecture
- Encapsulated scanner state and configuration in `CloudRip` class
- Separated concerns into dedicated classes (IP ranges, reporting, scanning)

#### Cloudflare IP Detection
- Changed from inline import of `ipaddress` module to module-level import
- Separated IPv4 and IPv6 address parsing with proper error handling using `AddressValueError`
- IP ranges are now lazily loaded on first check

#### Error Handling
- Added handling for `dns.resolver.LifetimeTimeout` exception
- Added `EOFError` handling for interrupt signal during input prompt
- Improved file encoding handling with explicit UTF-8 specification

#### Signal Handling
- Moved signal handler from global function to instance method
- Added `cancel_futures=True` to executor shutdown for cleaner interruption

#### Rate Limiting
- Reduced inter-request delay from 0.1s to 0.05s for faster scanning

#### Output Formatting
- Changed result logging to show both IPv4 and IPv6 with `[CF]` tags for Cloudflare IPs
- Added colored `[CLOUDFLARE]` status for domains behind Cloudflare
- Improved report structure with categorized sections (found, cloudflare, not_found, errors)

#### Documentation
- Added module-level docstring describing the tool's purpose
- Added docstrings to all classes and methods

### Removed

- Removed `os` module import (replaced with `pathlib.Path`)
- Removed global `stop_requested` variable (now instance attribute)
- Removed standalone color constant variables (now in `Colors` class)

### Technical Improvements

#### Code Quality
- Added shebang line (`#!/usr/bin/env python3`) for direct execution
- Added proper module structure with `__all__` implicit through class definitions
- Used `pathlib.Path` for file operations instead of `os.path`
- Used `set` for wordlist deduplication with sorted output
- Added proper encoding parameter to all file operations

#### Dependencies
- Added `requests` library for HTTP API calls
- Added `tqdm` library for progress bar
- Added `csv` module usage for CSV export
- Added `json` module for JSON serialization
- Added `datetime` with timezone support for scan timestamps
- Added `dataclasses` for structured data
- Added `enum` for type-safe enumerations

#### CLI Improvements
- Added `RawDescriptionHelpFormatter` for better help text formatting
- Added usage examples in argument parser epilog
- Improved argument descriptions and help text

## [2.0.0]

### Added

- Massive wordlist upgrade - Took dom.txt from 100 to 600+ subdomains
- Added API variants, cloud infrastructure, IoT endpoints
- Covers auth/security, payment gateways, analytics, CI/CD pipelines
- Way better geo coverage - cities and more countries
- Handles modern cloud-native and microservices setups
- Better database and service discovery hits

## [1.5.0]

### Added

- Rate limiting so you don't get blocked

### Changed

- Thread handling works better now

### Fixed

- Doesn't crash on DNS failures anymore
- Prettier output with colors

## [1.0.0]

### Added

- First drop with the core stuff
- Multi-threaded subdomain scanning
- Filters out Cloudflare IPs
- Bring your own wordlist
- Save results to file
- Basic dom.txt with ~100 entries

