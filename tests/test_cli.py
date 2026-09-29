"""Integration tests for the PECFF Click CLI tool."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pecff.cli import main


class TestCLI:
    """Validate CLI commands, arguments, and report format options."""

    def test_cli_version_and_help(self) -> None:
        """--help and --version return clean status codes."""
        runner = CliRunner()
        res_help = runner.invoke(main, ["--help"])
        assert res_help.exit_code == 0
        assert "PECFF: Passive Email Cryptographic Forensics Framework" in res_help.output

        res_ver = runner.invoke(main, ["--version"])
        assert res_ver.exit_code == 0
        assert "0.1.0" in res_ver.output

    def test_cli_cipher_lookup(self) -> None:
        """pecff cipher looks up IANA knowledge base accurately."""
        runner = CliRunner()
        res = runner.invoke(main, ["cipher", "0x1301"])
        assert res.exit_code == 0
        assert "TLS_AES_128_GCM_SHA256" in res.output
        assert "AEAD" in res.output

    def test_cli_export_schema(self, tmp_path: Path) -> None:
        """pecff export-schema writes JSON schema to destination."""
        runner = CliRunner()
        res = runner.invoke(main, ["export-schema", "--output-dir", str(tmp_path)])
        assert res.exit_code == 0
        schema_file = tmp_path / "pecff-analysis-1.0.0.json"
        assert schema_file.exists()

    def test_cli_analyze_command(self, tmp_path: Path) -> None:
        """pecff analyze runs passive analysis on sample PCAP and outputs report."""
        # Create a minimal valid PCAP file header + dummy packet
        pcap_header = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01\x00\x00"
        pcap_file = tmp_path / "test_sample.pcap"
        pcap_file.write_bytes(pcap_header)

        runner = CliRunner()

        # Text mode
        res_text = runner.invoke(main, ["analyze", str(pcap_file)])
        assert res_text.exit_code == 0
        assert "PECFF Analysis Summary" in res_text.output

        # JSON mode
        res_json = runner.invoke(main, ["analyze", str(pcap_file), "--format", "json"])
        assert res_json.exit_code == 0
        assert '"schema_version": "1.0.0"' in res_json.output

        # HTML export mode
        html_out = tmp_path / "cli_report.html"
        res_html = runner.invoke(
            main, ["analyze", str(pcap_file), "--format", "html", "-o", str(html_out)]
        )
        assert res_html.exit_code == 0
        assert html_out.exists()
        assert "<!DOCTYPE html>" in html_out.read_text(encoding="utf-8")

        # PDF export mode
        pdf_out = tmp_path / "cli_report.pdf"
        res_pdf = runner.invoke(
            main, ["analyze", str(pcap_file), "--format", "pdf", "-o", str(pdf_out)]
        )
        assert res_pdf.exit_code == 0
        assert pdf_out.exists()
        assert pdf_out.read_bytes().startswith(b"%PDF-")
