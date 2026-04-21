# MCP Server Nmap

MCP server exposing python-nmap library for network scanning.

## When to use this skill

Use this skill when you need to:
- Scan networks for hosts
- Port scanning
- Service detection
- OS detection

## Tools

**Initialization:**
- `port_scanner_init` - Synchronous scanner
- `port_scanner_async_init` - Async scanner
- `port_scanner_yield_init` - Generator scanner

**Scanning:**
- `port_scanner_scan` - Scan hosts (sync)
- `port_scanner_async_scan` - Scan (async)
- `port_scanner_yield_scan` - Scan with streaming
- `port_scanner_listscan` - List hosts

**Results:**
- `port_scanner_all_hosts`, `port_scanner_has_host`
- `port_scanner_get_item`, `port_scanner_scaninfo`
- `port_scanner_scanstats`, `port_scanner_command_line`
- `port_scanner_csv`, `port_scanner_last_output`

## Install

```bash
pip install mcp-server-nmap
```

Requires: nmap installed on system