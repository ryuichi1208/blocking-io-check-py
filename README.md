# blocking-io-check-py

[![Lint and Format](https://github.com/ryuichi1208/blocking-io-check-py/actions/workflows/lint.yml/badge.svg)](https://github.com/ryuichi1208/blocking-io-check-py/actions/workflows/lint.yml)

A Python-based eBPF tool to monitor and detect blocking I/O operations in Python applications.

## Overview

This tool uses eBPF (extended Berkeley Packet Filter) to trace Python socket I/O operations and identify whether they are blocking or non-blocking. It helps diagnose performance issues related to I/O blocking in Python applications.

## Features

- Real-time monitoring of Python socket operations (sendto, recvfrom, sendmsg, recvmsg, read, write)
- Detection of non-blocking flags (O_NONBLOCK, MSG_DONTWAIT)
- epoll integration tracking
- Support for IPv4, IPv6, and Netlink sockets
- Minimal performance overhead using eBPF

## Requirements

- Linux kernel 4.9+
- Python 3.12+
- BCC (BPF Compiler Collection)
- Root privileges for eBPF operations

## Usage

### Basic Usage

Run as root to trace all Python processes:

```bash
sudo uv run blocking_io_check.py
```

### Filter by PID

Trace a specific process by PID:

```bash
sudo uv run blocking_io_check.py --pid 12345
```

### Filter by Process Name

Trace processes with a different name (default is "python3"):

```bash
sudo uv run blocking_io_check.py -p python
sudo uv run blocking_io_check.py -p myapp
```

### Additional Options

```bash
# Hide DNS traffic (port 53)
sudo uv run blocking_io_check.py --hide-dns

# Hide Netlink socket traffic  
sudo uv run blocking_io_check.py --hide-netlink

# Combine options
sudo uv run blocking_io_check.py --pid 12345 --hide-dns
```

### Output

The tool will trace socket I/O operations and display:
- Process ID and command name
- File descriptor
- Operation type
- Blocking status
- epoll usage
- Remote peer information

