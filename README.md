# mcp-server-nmap

MCP server that exposes the python-nmap 0.7.1 API for network scanning operations.

[![PyPI](https://img.shields.io/pypi/v/mcp-server-nmap.svg)](https://pypi.org/project/mcp-server-nmap/)
[![Python](https://img.shields.io/pypi/pyversions/mcp-server-nmap.svg)](https://pypi.org/project/mcp-server-nmap/)

## Install

```bash
pip install mcp-server-nmap
```

## MCP Server

mcp-name: io.github.daedalus/mcp-server-nmap

## Usage

Configure in your MCP settings file:

```json
{
  "mcpServers": {
    "mcp-server-nmap": {
      "command": "mcp-server-nmap"
    }
  }
}
```

## Available Tools

### PortScanner (Synchronous)

- `port_scanner_init` - Initialize PortScanner
- `port_scanner_scan` - Scan hosts with nmap
- `port_scanner_all_hosts` - Get all scanned hosts
- `port_scanner_has_host` - Check if host was scanned
- `port_scanner_get_item` - Get host scan details
- `port_scanner_scaninfo` - Get scaninfo structure
- `port_scanner_scanstats` - Get scan statistics
- `port_scanner_command_line` - Get command line used
- `port_scanner_csv` - Get CSV output
- `port_scanner_analyse_xml` - Parse XML scan output
- `port_scanner_listscan` - List hosts without scanning
- `port_scanner_nmap_version` - Get nmap version
- `port_scanner_last_output` - Get raw nmap output

### PortScannerAsync (Asynchronous)

- `port_scanner_async_init` - Initialize async scanner
- `port_scanner_async_scan` - Async scan with callback
- `port_scanner_async_still_scanning` - Check if scanning
- `port_scanner_async_stop` - Stop current scan
- `port_scanner_async_wait` - Wait for scan to complete

### PortScannerYield (Generator-based)

- `port_scanner_yield_init` - Initialize yield scanner
- `port_scanner_yield_scan` - Scan with generator yields

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
