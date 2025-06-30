# Changelog

All notable changes to the MTR-Trace NSE script will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2025-06-29

### Added
- Implemented real traceroute functionality using Nmap's native packet crafting capabilities
- Added support for capturing and analyzing ICMP responses
- Added proper packet capture and analysis for accurate hop detection

### Changed
- Replaced simulated traceroute with real packet-based traceroute
- Updated README.md to reflect the real traceroute implementation
- Added requirement for root/sudo privileges in documentation

### Fixed
- Fixed issues with ASN lookups for certain IP ranges
- Improved error handling for packet capture and network operations

## [1.0.3] - 2025-06-29

### Changed
- Reverted to an enhanced simulated traceroute implementation
- Improved the simulated traceroute to provide more realistic results
- Updated README.md to clarify that the script uses a simulated traceroute
- Added more detailed debugging information for ASN lookups

### Fixed
- Fixed issues with the real traceroute implementation that was not working correctly
- Improved error handling and fallback mechanisms

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
