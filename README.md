# mcp-server-nmap

MCP server that exposes the python-nmap library as MCP tools for network scanning operations.

[![PyPI](https://img.shields.io/pypi/v/mcp-server-nmap.svg)](https://pypi.org/project/mcp-server-nmap/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-server-nmap.svg)](https://pypi.org/project/mcp-server-nmap/)

## What is this?

This MCP server wraps the python-nmap library, allowing AI assistants to perform network reconnaissance through MCP tools. It provides three scanning interfaces:

1. **PortScanner** (synchronous) - Blocking scans that wait for completion
2. **PortScannerAsync** (asynchronous) - Non-blocking scans with callbacks
3. **PortScannerYield** (generator) - Streaming results as hosts are discovered

## Prerequisites

- [nmap](https://nmap.org/) must be installed on the system
- Python 3.10+

## Install

```bash
pip install mcp-server-nmap
```

## MCP Server Registration

Add this to your MCP settings file:

```json
{
  "mcpServers": {
    "mcp-server-nmap": {
      "command": "mcp-server-nmap"
    }
  }
}
```

Or with custom nmap path:

```json
{
  "mcpServers": {
    "mcp-server-nmap": {
      "command": "mcp-server-nmap",
      "env": {
        "PATH": "/custom/path:$PATH"
      }
    }
  }
}
```

## Available Tools

### Initialization

| Tool | Description |
|------|-------------|
| `port_scanner_init` | Initialize synchronous PortScanner |
| `port_scanner_async_init` | Initialize async PortScannerAsync |
| `port_scanner_yield_init` | Initialize generator-based PortScannerYield |

### Scanning

| Tool | Description |
|------|-------------|
| `port_scanner_scan` | Scan hosts with nmap (synchronous) |
| `port_scanner_async_scan` | Scan hosts (async, non-blocking) |
| `port_scanner_yield_scan` | Scan with streaming results |
| `port_scanner_listscan` | List hosts without scanning |

### Results & State

| Tool | Description |
|------|-------------|
| `port_scanner_all_hosts` | Get all scanned hosts |
| `port_scanner_has_host` | Check if host was scanned |
| `port_scanner_get_item` | Get detailed host scan data |
| `port_scanner_scaninfo` | Get scan configuration info |
| `port_scanner_scanstats` | Get scan statistics |
| `port_scanner_command_line` | Get nmap command used |
| `port_scanner_csv` | Get CSV output |
| `port_scanner_last_output` | Get raw nmap text output |

### Async Control

| Tool | Description |
|------|-------------|
| `port_scanner_async_still_scanning` | Check if scan in progress |
| `port_scanner_async_stop` | Stop running scan |
| `port_scanner_async_wait` | Wait for scan to complete |

### XML Parsing

| Tool | Description |
|------|-------------|
| `port_scanner_analyse_xml` | Parse existing nmap XML output |

## Common Scan Workflows

### Basic port scan

```python
# Initialize scanner
port_scanner_init()

# Scan target
port_scanner_scan(hosts="192.168.1.1", ports="22,80,443", arguments="-sV")

# Get results
port_scanner_get_item(host="192.168.1.1")
```

### Service version detection

```python
port_scanner_scan(hosts="scanme.nmap.org", arguments="-sV -sC")
```

### Scan multiple hosts

```python
port_scanner_scan(hosts="192.168.1.1-254", arguments="-sS -p 22")
port_scanner_all_hosts()
```

### Network sweep

```python
port_scanner_scan(hosts="192.168.1.0/24", arguments="-sn")
port_scanner_csv()  # Export to CSV
```

## nmap Arguments Reference

| Argument | Description |
|----------|-------------|
| `-sn` | Ping scan (host discovery) |
| `-sS` | TCP SYN scan |
| `-sT` | TCP connect scan |
| `-sU` | UDP scan |
| `-sV` | Service version detection |
| `-sC` | Default scripts |
| `-O` | OS detection |
| `-p` | Port range |
| `-oA` | Output all formats |

## Development

```bash
git clone https://github.com/daedalus/mcp-server-nmap.git
cd mcp-server-nmap
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```