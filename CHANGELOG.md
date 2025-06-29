# Changelog

All notable changes to the MTR-Trace NSE script will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2025-06-29

### Fixed
- Fixed ASN lookup for non-private networks (like Google, Facebook, etc.)
- Added special handling for well-known IP ranges for faster and more reliable ASN lookups
- Added debug output for ASN lookups to help troubleshoot issues
- Ensured target IP is correctly identified with proper ASN information

## [1.0.1] - 2025-06-29

### Changed
- Replaced built-in ASN database with real-time ASN lookups using Team Cymru's whois service via DNS
- Updated README.md to reflect the change to real-time ASN lookups

## [1.0.0] - 2025-06-29

### Added
- Initial release of the MTR-Trace NSE script
- Per-hop latency measurements (average, standard deviation, jitter)
- Packet loss statistics for each hop
- OS fingerprinting based on pattern matching and heuristics
- ASN information lookup for each hop
- TTFB (Time To First Byte) measurement for target websites
- Comprehensive documentation in README.md
- Script arguments for customizing number of packets and timeout
- Detailed output formatting with tabular display
