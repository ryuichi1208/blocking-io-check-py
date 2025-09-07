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

Run as root:

```bash
sudo uv run blocking_io_check.py
```

The tool will trace all Python socket I/O operations and display:
- Process ID and command name
- File descriptor
- Operation type
- Blocking status
- epoll usage
- Remote peer information

## Development

### Linting and Formatting

This project uses Ruff for code quality:

```bash
# Check code
ruff check .

# Format code  
ruff format .
```
