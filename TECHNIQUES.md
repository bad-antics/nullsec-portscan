# Port Scanning Techniques Guide

## Overview
Network port scanning methodologies and detection evasion.

## Scan Types

### TCP Scans
- **Connect Scan**: Full handshake
- **SYN Scan**: Half-open stealth
- **FIN Scan**: Firewall evasion
- **XMAS Scan**: Flag combination
- **NULL Scan**: No flags set

### UDP Scans
- Direct UDP probes
- ICMP unreachable analysis
- Service-specific payloads
- Timeout handling

### Specialized Scans
- **ACK Scan**: Firewall mapping
- **Window Scan**: Open detection
- **Maimon Scan**: BSD detection
- **Idle Scan**: Zombie host

## Evasion Techniques

### Timing
- Paranoid (5 min intervals)
- Sneaky (15 sec intervals)
- Polite (400ms intervals)
- Normal (default)
- Aggressive (5ms intervals)

### Fragmentation
- MTU manipulation
- Packet splitting
- Reassembly evasion
- Decoy hosts

### Source Manipulation
- IP spoofing
- Source port tricks
- Decoy addresses
- Proxy chains

## Service Detection
- Banner grabbing
- Version probing
- Script scanning
- OS fingerprinting

## Target Specification
- CIDR notation
- IP ranges
- Hostname resolution
- File input

## Legal Notice
For authorized security assessments only.
