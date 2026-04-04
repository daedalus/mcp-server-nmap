"""MCP server for python-nmap network scanning."""

from __future__ import annotations

from typing import Any

import nmap
from fastmcp import FastMCP

mcp = FastMCP("mcp-server-nmap")

_port_scanner: nmap.PortScanner | None = None
_port_scanner_async: nmap.PortScannerAsync | None = None
_port_scanner_yield: nmap.PortScannerYield | None = None


@mcp.tool()
def port_scanner_init(nmap_search_path: list[str] | None = None) -> dict[str, Any]:
    """Initialize the PortScanner instance.

    Args:
        nmap_search_path: Optional tuple of strings where to search for nmap executable.
                          Change this if you want to use a specific version of nmap.

    Returns:
        Dictionary with success status and nmap version.

    Example:
        >>> port_scanner_init()
        {"success": True, "version": (7, 94)}
    """
    global _port_scanner
    try:
        if nmap_search_path:
            _port_scanner = nmap.PortScanner(tuple(nmap_search_path))
        else:
            _port_scanner = nmap.PortScanner()
        return {
            "success": True,
            "version": _port_scanner.nmap_version(),
        }
    except nmap.PortScannerError as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_scan(
    hosts: str = "127.0.0.1",
    ports: str | None = None,
    arguments: str = "-sV",
    sudo: bool = False,
    timeout: int = 0,
) -> dict[str, Any]:
    """Scan given hosts using nmap.

    May raise PortScannerError exception if nmap output was not xml.
    Test existence of the following key to know if something went wrong:
    ['nmap']['scaninfo']['error']. If not present, everything was ok.

    Args:
        hosts: String for hosts as nmap uses it 'scanme.nmap.org' or '198.116.0-255.1-127'
               or '216.163.128.20/20'
        ports: String for ports as nmap uses it '22,53,110,143-4564'
        arguments: String of arguments for nmap '-sU -sX -sC'
        sudo: Launch nmap with sudo if True
        timeout: Int, if > zero, will terminate scan after seconds, otherwise wait indefinitely

    Returns:
        Scan result as dictionary.

    Example:
        >>> port_scanner_scan(hosts="127.0.0.1", ports="22,80", arguments="-sV")
        {"nmap": {...}, "scan": {...}}
    """
    global _port_scanner
    if _port_scanner is None:
        _port_scanner = nmap.PortScanner()
    try:
        result = _port_scanner.scan(
            hosts=hosts, ports=ports, arguments=arguments, sudo=sudo, timeout=timeout
        )
        return {"success": True, "result": result}
    except nmap.PortScannerError as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_all_hosts() -> dict[str, Any]:
    """Return a sorted list of all hosts that have been scanned.

    Returns:
        Dictionary with list of host IP addresses.

    Example:
        >>> port_scanner_all_hosts()
        {"hosts": ["127.0.0.1", "192.168.1.1"]}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"hosts": [], "error": "PortScanner not initialized"}
    return {"hosts": _port_scanner.all_hosts()}


@mcp.tool()
def port_scanner_has_host(host: str) -> dict[str, Any]:
    """Check if host has scan results.

    Args:
        host: Host IP address to check.

    Returns:
        Dictionary with boolean result.

    Example:
        >>> port_scanner_has_host("127.0.0.1")
        {"has_host": True}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"has_host": False, "error": "PortScanner not initialized"}
    return {"has_host": _port_scanner.has_host(host)}


@mcp.tool()
def port_scanner_get_item(host: str) -> dict[str, Any]:
    """Get host scan details.

    Args:
        host: Host IP address.

    Returns:
        Dictionary with host details.

    Example:
        >>> port_scanner_get_item("127.0.0.1")
        {"host": {"status": "up", "addresses": {...}}}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"host": None, "error": "PortScanner not initialized"}
    try:
        return {"host": _port_scanner[host]}
    except KeyError:
        return {"host": None, "error": f"Host {host} not found"}


@mcp.tool()
def port_scanner_scaninfo() -> dict[str, Any]:
    """Return scaninfo structure.

    Returns dictionary like {'tcp': {'services': '22', 'method': 'connect'}}.

    Example:
        >>> port_scanner_scaninfo()
        {"scaninfo": {"tcp": {"services": "22", "method": "connect"}}}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"scaninfo": None, "error": "PortScanner not initialized"}
    try:
        return {"scaninfo": _port_scanner.scaninfo()}
    except AssertionError:
        return {"scaninfo": None, "error": "No scan results. Call scan() first."}


@mcp.tool()
def port_scanner_scanstats() -> dict[str, Any]:
    """Return scanstats structure.

    Returns dictionary like {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010',
    'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}.

    Example:
        >>> port_scanner_scanstats()
        {"scanstats": {"uphosts": "1", "downhosts": "0", "totalhosts": "1"}}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"scanstats": None, "error": "PortScanner not initialized"}
    return {"scanstats": _port_scanner.scanstats()}


@mcp.tool()
def port_scanner_command_line() -> dict[str, Any]:
    """Return the command line used for the scan.

    Example:
        >>> port_scanner_command_line()
        {"command_line": "nmap -oX - -sV 127.0.0.1"}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"command_line": None, "error": "PortScanner not initialized"}
    try:
        return {"command_line": _port_scanner.command_line()}
    except AssertionError:
        return {"command_line": None, "error": "No scan results. Call scan() first."}


@mcp.tool()
def port_scanner_csv() -> dict[str, Any]:
    """Return CSV output as text.

    Example:
        >>> port_scanner_csv()
        {"csv": "host;hostname;hostname_type;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe\\n127.0.0.1;..."}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"csv": "", "error": "PortScanner not initialized"}
    return {"csv": _port_scanner.csv()}


@mcp.tool()
def port_scanner_analyse_xml(nmap_xml_output: str) -> dict[str, Any]:
    """Analyse NMAP xml scan output.

    May raise PortScannerError exception if nmap output was not xml.
    Test existence of the following key to know if something went wrong:
    ['nmap']['scaninfo']['error']. If not present, everything was ok.

    Args:
        nmap_xml_output: XML string to analyse.

    Returns:
        Scan result as dictionary.

    Example:
        >>> xml_output = '<?xml version="1.0"?><nmaprun>...</nmaprun>'
        >>> port_scanner_analyse_xml(xml_output)
        {"result": {...}}
    """
    global _port_scanner
    if _port_scanner is None:
        _port_scanner = nmap.PortScanner()
    try:
        result = _port_scanner.analyse_nmap_xml_scan(nmap_xml_output=nmap_xml_output)
        return {"success": True, "result": result}
    except nmap.PortScannerError as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_listscan(hosts: str = "127.0.0.1") -> dict[str, Any]:
    """Do not scan but interpret target hosts and return a list of hosts.

    Args:
        hosts: Target hosts string.

    Returns:
        List of hosts.

    Example:
        >>> port_scanner_listscan("192.168.1.1-10")
        {"hosts": ["192.168.1.1", "192.168.1.2", ...]}
    """
    global _port_scanner
    if _port_scanner is None:
        _port_scanner = nmap.PortScanner()
    try:
        return {"hosts": _port_scanner.listscan(hosts)}
    except Exception as e:
        return {"hosts": [], "error": str(e)}


@mcp.tool()
def port_scanner_nmap_version() -> dict[str, Any]:
    """Return nmap version if detected (int version, int subversion) or (0, 0) if unknown.

    Example:
        >>> port_scanner_nmap_version()
        {"version": (7, 94)}
    """
    global _port_scanner
    if _port_scanner is None:
        _port_scanner = nmap.PortScanner()
    return {"version": _port_scanner.nmap_version()}


@mcp.tool()
def port_scanner_last_output() -> dict[str, Any]:
    """Return the last text output of nmap in raw text.

    This may be used for debugging purposes.

    Example:
        >>> port_scanner_last_output()
        {"output": "Starting Nmap..."}
    """
    global _port_scanner
    if _port_scanner is None:
        return {"output": "", "error": "PortScanner not initialized"}
    return {"output": _port_scanner.get_nmap_last_output()}


@mcp.tool()
def port_scanner_async_init() -> dict[str, Any]:
    """Initialize the PortScannerAsync instance.

    Returns:
        Dictionary with success status and nmap version.

    Example:
        >>> port_scanner_async_init()
        {"success": True, "version": (7, 94)}
    """
    global _port_scanner_async
    try:
        _port_scanner_async = nmap.PortScannerAsync()
        return {"success": True, "version": (0, 0)}
    except nmap.PortScannerError as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_async_scan(
    hosts: str = "127.0.0.1",
    ports: str | None = None,
    arguments: str = "-sV",
    sudo: bool = False,
    timeout: int = 0,
) -> dict[str, Any]:
    """Scan given hosts in a separate process and return host by host result using callback.

    PortScannerError exception from standard nmap is caught and you won't know about
    but get None as scan_data.

    Args:
        hosts: String for hosts as nmap uses it.
        ports: String for ports as nmap uses it.
        arguments: String of arguments for nmap.
        sudo: Launch nmap with sudo if true.
        timeout: Int, if > zero, will terminate scan after seconds.

    Returns:
        Dictionary with success status.

    Example:
        >>> port_scanner_async_scan(hosts="127.0.0.1", ports="22,80")
        {"success": True}
    """
    global _port_scanner_async
    if _port_scanner_async is None:
        _port_scanner_async = nmap.PortScannerAsync()
    try:
        _port_scanner_async.scan(
            hosts=hosts, ports=ports, arguments=arguments, sudo=sudo, timeout=timeout
        )
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_async_still_scanning() -> dict[str, Any]:
    """Check if a scan is currently running.

    Example:
        >>> port_scanner_async_still_scanning()
        {"still_scanning": False}
    """
    global _port_scanner_async
    if _port_scanner_async is None:
        return {"still_scanning": False, "error": "PortScannerAsync not initialized"}
    return {"still_scanning": _port_scanner_async.still_scanning()}


@mcp.tool()
def port_scanner_async_stop() -> dict[str, Any]:
    """Stop the current scan process.

    Example:
        >>> port_scanner_async_stop()
        {"success": True}
    """
    global _port_scanner_async
    if _port_scanner_async is None:
        return {"success": False, "error": "PortScannerAsync not initialized"}
    _port_scanner_async.stop()
    return {"success": True}


@mcp.tool()
def port_scanner_async_wait(timeout: int | None = None) -> dict[str, Any]:
    """Wait for the current scan process to finish, or timeout.

    Args:
        timeout: Wait timeout in seconds.

    Example:
        >>> port_scanner_async_wait(timeout=30)
        {"success": True}
    """
    global _port_scanner_async
    if _port_scanner_async is None:
        return {"success": False, "error": "PortScannerAsync not initialized"}
    try:
        _port_scanner_async.wait(timeout=timeout)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_yield_init() -> dict[str, Any]:
    """Initialize the PortScannerYield instance.

    Returns:
        Dictionary with success status and nmap version.

    Example:
        >>> port_scanner_yield_init()
        {"success": True, "version": (7, 94)}
    """
    global _port_scanner_yield
    try:
        _port_scanner_yield = nmap.PortScannerYield()
        return {"success": True, "version": (0, 0)}
    except nmap.PortScannerError as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
def port_scanner_yield_scan(
    hosts: str = "127.0.0.1",
    ports: str | None = None,
    arguments: str = "-sV",
    sudo: bool = False,
    timeout: int = 0,
) -> dict[str, Any]:
    """Scan hosts with generator that yields results for each host.

    Args:
        hosts: String for hosts as nmap uses it.
        ports: String for ports as nmap uses it.
        arguments: String of arguments for nmap.
        sudo: Launch nmap with sudo if true.
        timeout: Int, if > zero, will terminate scan after seconds.

    Returns:
        Dictionary with success status and scan results.

    Example:
        >>> port_scanner_yield_scan(hosts="127.0.0.1")
        {"success": True, "results": [...]}
    """
    global _port_scanner_yield
    if _port_scanner_yield is None:
        _port_scanner_yield = nmap.PortScannerYield()
    try:
        results = []
        for host, scan_data in _port_scanner_yield.scan(
            hosts=hosts, ports=ports, arguments=arguments, sudo=sudo, timeout=timeout
        ):
            results.append({"host": host, "data": scan_data})
        return {"success": True, "results": results}
    except Exception as e:
        return {"success": False, "error": str(e)}
