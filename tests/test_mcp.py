"""Tests for mcp-server-nmap MCP tools."""

from unittest.mock import MagicMock

from pytest_mock import MockerFixture


class TestPortScannerInit:
    def test_port_scanner_init_default(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_init

        mock_scanner = MagicMock()
        mock_scanner.nmap_version.return_value = (7, 94)
        mocker.patch("nmap.PortScanner", return_value=mock_scanner)
        mcp_module._port_scanner = None
        result = port_scanner_init()
        assert result["success"] is True
        assert result["version"] == (7, 94)

    def test_port_scanner_init_with_custom_path(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_init

        mock_scanner = MagicMock()
        mock_scanner.nmap_version.return_value = (7, 94)
        mocker.patch("nmap.PortScanner", return_value=mock_scanner)
        mcp_module._port_scanner = None
        result = port_scanner_init(nmap_search_path=["/custom/nmap"])
        assert result["success"] is True

    def test_port_scanner_init_nmap_not_found(self, mocker: MockerFixture) -> None:
        import nmap

        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_init

        mocker.patch(
            "nmap.PortScanner", side_effect=nmap.PortScannerError("nmap not found")
        )
        mcp_module._port_scanner = None
        result = port_scanner_init()
        assert result["success"] is False
        assert "error" in result


class TestPortScannerScan:
    def test_port_scanner_scan_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scan

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {"nmap": {"scaninfo": {}}, "scan": {}}
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_scan(hosts="127.0.0.1", ports="80", arguments="-sV")
        assert result["success"] is True
        assert "result" in result

    def test_port_scanner_scan_with_timeout(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scan

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {}
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_scan(hosts="127.0.0.1", timeout=30)
        assert result["success"] is True

    def test_port_scanner_scan_with_sudo(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scan

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = {}
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_scan(hosts="127.0.0.1", sudo=True)
        assert result["success"] is True


class TestPortScannerAllHosts:
    def test_port_scanner_all_hosts_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_all_hosts

        mock_scanner = MagicMock()
        mock_scanner.all_hosts.return_value = ["127.0.0.1", "192.168.1.1"]
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_all_hosts()
        assert "hosts" in result
        assert result["hosts"] == ["127.0.0.1", "192.168.1.1"]

    def test_port_scanner_all_hosts_not_initialized(
        self, mocker: MockerFixture
    ) -> None:
        from mcp_server_nmap.mcp import port_scanner_all_hosts

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_all_hosts()
        assert "error" in result


class TestPortScannerHasHost:
    def test_port_scanner_has_host_true(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_has_host

        mock_scanner = MagicMock()
        mock_scanner.has_host.return_value = True
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_has_host(host="127.0.0.1")
        assert result["has_host"] is True

    def test_port_scanner_has_host_false(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_has_host

        mock_scanner = MagicMock()
        mock_scanner.has_host.return_value = False
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_has_host(host="192.168.1.100")
        assert result["has_host"] is False

    def test_port_scanner_has_host_not_initialized(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_has_host

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_has_host(host="127.0.0.1")
        assert "error" in result


class TestPortScannerGetItem:
    def test_port_scanner_get_item_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_get_item

        mock_scanner = MagicMock()
        mock_scanner.__getitem__.return_value = {"status": "up"}
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_get_item(host="127.0.0.1")
        assert result["host"] is not None

    def test_port_scanner_get_item_not_found(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_get_item

        mock_scanner = MagicMock()
        mock_scanner.__getitem__.side_effect = KeyError("Host not found")
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_get_item(host="192.168.1.100")
        assert "error" in result


class TestPortScannerScaninfo:
    def test_port_scanner_scaninfo_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scaninfo

        mock_scanner = MagicMock()
        mock_scanner.scaninfo.return_value = {
            "tcp": {"services": "80", "method": "connect"}
        }
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_scaninfo()
        assert "scaninfo" in result
        assert result["scaninfo"]["tcp"]["method"] == "connect"

    def test_port_scanner_scaninfo_not_initialized(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scaninfo

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_scaninfo()
        assert "error" in result


class TestPortScannerScanstats:
    def test_port_scanner_scanstats_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_scanstats

        mock_scanner = MagicMock()
        mock_scanner.scanstats.return_value = {
            "uphosts": "1",
            "downhosts": "0",
            "totalhosts": "1",
        }
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_scanstats()
        assert "scanstats" in result

    def test_port_scanner_scanstats_not_initialized(
        self, mocker: MockerFixture
    ) -> None:
        from mcp_server_nmap.mcp import port_scanner_scanstats

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_scanstats()
        assert "error" in result


class TestPortScannerCommandLine:
    def test_port_scanner_command_line_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_command_line

        mock_scanner = MagicMock()
        mock_scanner.command_line.return_value = "nmap -sV 127.0.0.1"
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_command_line()
        assert "command_line" in result

    def test_port_scanner_command_line_not_initialized(
        self, mocker: MockerFixture
    ) -> None:
        from mcp_server_nmap.mcp import port_scanner_command_line

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_command_line()
        assert "error" in result


class TestPortScannerCsv:
    def test_port_scanner_csv_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_csv

        mock_scanner = MagicMock()
        mock_scanner.csv.return_value = "host;port;state"
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_csv()
        assert "csv" in result

    def test_port_scanner_csv_not_initialized(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_csv

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_csv()
        assert "error" in result


class TestPortScannerAnalyzeXml:
    def test_port_scanner_analyse_xml_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_analyse_xml

        mock_scanner = MagicMock()
        mock_scanner.analyse_nmap_xml_scan.return_value = {"nmap": {}, "scan": {}}
        mcp_module._port_scanner = mock_scanner
        xml_output = '<?xml version="1.0"?><nmaprun></nmaprun>'
        result = port_scanner_analyse_xml(nmap_xml_output=xml_output)
        assert result["success"] is True


class TestPortScannerListscan:
    def test_port_scanner_listscan_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_listscan

        mock_scanner = MagicMock()
        mock_scanner.listscan.return_value = ["192.168.1.1", "192.168.1.2"]
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_listscan(hosts="192.168.1.1-10")
        assert "hosts" in result
        assert result["hosts"] == ["192.168.1.1", "192.168.1.2"]


class TestPortScannerNmapVersion:
    def test_port_scanner_nmap_version(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_nmap_version

        mock_scanner = MagicMock()
        mock_scanner.nmap_version.return_value = (7, 94)
        mcp_module._port_scanner = mock_scanner
        result = port_scanner_nmap_version()
        assert result["version"] == (7, 94)


class TestPortScannerLastOutput:
    def test_port_scanner_last_output_success(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_last_output

        mock_scanner = MagicMock()
        mock_scanner.get_nmap_last_output.return_value = "Starting Nmap..."
        mocker.patch("mcp_server_nmap.mcp._port_scanner", mock_scanner)
        result = port_scanner_last_output()
        assert "output" in result

    def test_port_scanner_last_output_not_initialized(
        self, mocker: MockerFixture
    ) -> None:
        from mcp_server_nmap.mcp import port_scanner_last_output

        mocker.patch("mcp_server_nmap.mcp._port_scanner", None)
        result = port_scanner_last_output()
        assert "error" in result


class TestPortScannerAsync:
    def test_port_scanner_async_init(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_async_init

        mock_scanner = MagicMock()
        mock_scanner.nmap_version.return_value = (7, 94)
        mocker.patch("nmap.PortScannerAsync", return_value=mock_scanner)
        mcp_module._port_scanner_async = None
        result = port_scanner_async_init()
        assert result["success"] is True

    def test_port_scanner_async_init_nmap_not_found(
        self, mocker: MockerFixture
    ) -> None:
        import nmap

        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_async_init

        mocker.patch(
            "nmap.PortScannerAsync", side_effect=nmap.PortScannerError("nmap not found")
        )
        mcp_module._port_scanner_async = None
        result = port_scanner_async_init()
        assert result["success"] is False

    def test_port_scanner_async_scan(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_async_scan

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = None
        mocker.patch("mcp_server_nmap.mcp._port_scanner_async", mock_scanner)
        result = port_scanner_async_scan(hosts="127.0.0.1")
        assert result["success"] is True

    def test_port_scanner_async_still_scanning(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_async_still_scanning

        mock_scanner = MagicMock()
        mock_scanner.still_scanning.return_value = False
        mocker.patch("mcp_server_nmap.mcp._port_scanner_async", mock_scanner)
        result = port_scanner_async_still_scanning()
        assert result["still_scanning"] is False

    def test_port_scanner_async_stop(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_async_stop

        mock_scanner = MagicMock()
        mock_scanner.stop.return_value = None
        mocker.patch("mcp_server_nmap.mcp._port_scanner_async", mock_scanner)
        result = port_scanner_async_stop()
        assert result["success"] is True

    def test_port_scanner_async_wait(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_async_wait

        mock_scanner = MagicMock()
        mock_scanner.wait.return_value = None
        mocker.patch("mcp_server_nmap.mcp._port_scanner_async", mock_scanner)
        result = port_scanner_async_wait(timeout=30)
        assert result["success"] is True


class TestPortScannerYield:
    def test_port_scanner_yield_init(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_yield_init

        mock_scanner = MagicMock()
        mock_scanner.nmap_version.return_value = (7, 94)
        mocker.patch("nmap.PortScannerYield", return_value=mock_scanner)
        mcp_module._port_scanner_yield = None
        result = port_scanner_yield_init()
        assert result["success"] is True

    def test_port_scanner_yield_init_nmap_not_found(
        self, mocker: MockerFixture
    ) -> None:
        import nmap

        from mcp_server_nmap import mcp as mcp_module
        from mcp_server_nmap.mcp import port_scanner_yield_init

        mocker.patch(
            "nmap.PortScannerYield", side_effect=nmap.PortScannerError("nmap not found")
        )
        mcp_module._port_scanner_yield = None
        result = port_scanner_yield_init()
        assert result["success"] is False

    def test_port_scanner_yield_scan(self, mocker: MockerFixture) -> None:
        from mcp_server_nmap.mcp import port_scanner_yield_scan

        mock_scanner = MagicMock()
        mock_scanner.scan.return_value = [("127.0.0.1", {"state": "up"})]
        mocker.patch("mcp_server_nmap.mcp._port_scanner_yield", mock_scanner)
        result = port_scanner_yield_scan(hosts="127.0.0.1")
        assert result["success"] is True
        assert len(result["results"]) == 1
        assert result["results"][0]["host"] == "127.0.0.1"
