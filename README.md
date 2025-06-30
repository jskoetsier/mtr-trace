# MTR-Trace NSE Script

## Overview

MTR-Trace is an Nmap Scripting Engine (NSE) script that performs MTR-like (My Traceroute) traces to a target host. It provides comprehensive information about each hop in the path, including latency, jitter, packet loss, OS fingerprinting, and ASN information.

Version: 1.2.0

## Features

- **Per-hop latency measurements**: Shows average, standard deviation, and jitter
- **Packet loss statistics**: Displays sent/received packets and loss percentage
- **OS fingerprinting**: Attempts to identify the operating system of each hop using pattern matching and heuristics
- **ASN information**: Shows ASN number and organization name for each hop
- **TTFB measurement**: Measures Time To First Byte for the target website

## Requirements

- Nmap 7.70 or higher
- Root/sudo privileges (required for sending raw packets)

## Installation

1. Copy the `mtr-trace.nse` script to your Nmap scripts directory:

```bash
sudo cp mtr-trace.nse /usr/local/share/nmap/scripts/
```

2. Update the Nmap script database:

```bash
sudo nmap --script-updatedb
```

## Usage

Basic usage:

```bash
sudo nmap --script mtr-trace <target>
```

Example:

```bash
sudo nmap --script mtr-trace www.example.com
```

With custom parameters:

```bash
sudo nmap --script mtr-trace --script-args mtr-trace.packets=20,mtr-trace.timeout=3 www.example.com
```

### Script Arguments

- `mtr-trace.packets`: Number of packets to send to each hop (default: 10)
- `mtr-trace.timeout`: Maximum time in seconds to wait for responses (default: 5)

## Output Example

```
| mtr-trace:
| Target: www.example.com (93.184.216.34)
| TTFB: 124.56 ms
|
| Hop  IP Address       Loss%  Sent  Recv  Avg(ms)  StDev(ms)  Jitter(ms)  ASN        Organization           OS Guess
| 1    192.168.1.1      0.0%   10    10    1.52     0.23       0.12        Private    Private Network        Cisco Router
| 2    10.0.0.1         0.0%   10    10    12.45    1.32       0.87        Private    Private Network        Juniper Router
| 3    172.16.0.1       10.0%  10    9     25.31    2.45       1.23        Private    Private Network        Linux Router
| 4    203.0.113.1      0.0%   10    10    32.56    3.12       1.56        AS64496    Example ISP            Cisco IOS XR
| 5    198.51.100.1     20.0%  10    8     45.78    5.67       3.21        AS64500    Backbone Provider      Juniper MX Series
|_6    93.184.216.34    0.0%   10    10    50.23    2.34       1.12        AS15133    EdgeCast Networks      Web Server
```

## Limitations

- OS fingerprinting is based on pattern matching and heuristics, not actual OS detection
- ASN information is looked up in real-time using NTT's IRRD service and other routing registries
- The script requires root/sudo privileges to send raw packets for traceroute
- For full OS detection capabilities, run Nmap with the `-O` flag against specific hops

## License

Same as Nmap - See https://nmap.org/book/man-legal.html

## Author

Sebastiaan Koetsier
