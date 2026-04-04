# SPEC.md — mcp-server-nmap

## Purpose

MCP server that exposes the python-nmap 0.7.1 API, allowing AI assistants to perform network scanning operations via nmap through the Model Context Protocol.

## Scope

- Expose PortScanner, PortScannerAsync, PortScannerYield classes via MCP tools
- Provide scan operations for hosts, ports, with various nmap arguments
- Return structured results from nmap scans (XML, CSV formats)
- Support async scanning with callbacks and generator-based yielding

## Not in Scope

- Direct manipulation of nmap binary (handled by python-nmap)
- GUI or interactive terminal features
- Persistent scan state across server restarts

## Public API / Interface

### Tools (MCP Tools)

#### PortScanner Methods

1. **`port_scanner_init`** - Initialize PortScanner
   - Args: `nmap_search_path` (list[str], optional) - Paths to search for nmap
   - Returns: success status

2. **`port_scanner_scan`** - Scan hosts with nmap
   - Args:
     - `hosts` (str, default="127.0.0.1") - Target hosts
     - `ports` (str, optional) - Ports to scan
     - `arguments` (str, default="-sV") - Nmap arguments
     - `sudo` (bool, default=False) - Run with sudo
     - `timeout` (int, default=0) - Scan timeout in seconds
   - Returns: scan_result dictionary

3. **`port_scanner_all_hosts`** - Get all scanned hosts
   - Returns: sorted list of host IP addresses

4. **`port_scanner_has_host`** - Check if host was scanned
   - Args: `host` (str) - Host IP
   - Returns: bool

5. **`port_scanner_get_item`** - Get host scan details
   - Args: `host` (str) - Host IP
   - Returns: host details dictionary

6. **`port_scanner_scaninfo`** - Get scaninfo structure
   - Returns: scaninfo dict

7. **`port_scanner_scanstats`** - Get scan statistics
   - Returns: scanstats dict

8. **`port_scanner_command_line`** - Get command line used
   - Returns: command line string

9. **`port_scanner_csv`** - Get CSV output
   - Returns: CSV formatted string

10. **`port_scanner_analyse_xml`** - Parse XML scan output
    - Args: `nmap_xml_output` (str) - XML output string
    - Returns: parsed scan result

11. **`port_scanner_listscan`** - List hosts without scanning
    - Args: `hosts` (str, default="127.0.0.1") - Target hosts
    - Returns: list of hosts

12. **`port_scanner_nmap_version`** - Get nmap version
    - Returns: tuple (version, subversion)

13. **`port_scanner_last_output`** - Get raw nmap output
    - Returns: raw text output

#### PortScannerAsync Methods

14. **`port_scanner_async_init`** - Initialize async scanner

15. **`port_scanner_async_scan`** - Async scan with callback
    - Args:
      - `hosts` (str)
      - `ports` (str, optional)
      - `arguments` (str)
      - `sudo` (bool)
      - `timeout` (int)
    - Returns: success status

16. **`port_scanner_async_still_scanning`** - Check if scanning
    - Returns: bool

17. **`port_scanner_async_stop`** - Stop current scan

18. **`port_scanner_async_wait`** - Wait for scan to complete
    - Args: `timeout` (int, optional)
    - Returns: None

#### PortScannerYield Methods

19. **`port_scanner_yield_init`** - Initialize yield scanner

20. **`port_scanner_yield_scan`** - Scan with generator yields
    - Args:
      - `hosts` (str)
      - `ports` (str, optional)
      - `arguments` (str)
      - `sudo` (bool)
      - `timeout` (int)
    - Returns: yields scan results for each host

### Data Types

- **PortScannerHostDict**: Dictionary with host scan results
- **ScanResult**: Dict with keys: 'nmap', 'scan'
- **ScanInfo**: Dict like {'tcp': {'services': '22', 'method': 'connect'}}
- **ScanStats**: Dict like {'uphosts': '3', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

### Error Handling

- `PortScannerError` raised when nmap not found or XML parsing fails
- `PortScannerTimeout` raised when scan times out
- All tools return error messages in structured format

## Edge Cases

1. Nmap not installed on system - return descriptive error
2. Invalid hosts format - let nmap handle, pass through error
3. Scan timeout exceeded - terminate and return partial results
4. Empty scan results - return empty dict/list
5. XML parsing failure - raise PortScannerError
6. Network connectivity issues - nmap handles, pass through results

## Performance & Constraints

- Synchronous scans block until complete (use async for large scans)
- No built-in rate limiting
- Depends on external nmap binary availability
