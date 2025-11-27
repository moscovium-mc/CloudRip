#!/usr/bin/env python3
"""
CloudRip v2 - CloudFlare Bypasser.

Find real IP addresses behind Cloudflare by resolving subdomains
and filtering out Cloudflare's IP ranges (fetched dynamically).
Supports both IPv4 and IPv6.
"""

import argparse
import csv
import json
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, AddressValueError
from pathlib import Path
from typing import Optional, TextIO

import dns.resolver
import pyfiglet
import requests
from colorama import Fore, Style, init

init(autoreset=True)


class OutputFormat(Enum):
    """Supported output formats."""

    NORMAL = "normal"
    JSON = "json"
    YAML = "yaml"
    CSV = "csv"


class Colors:
    """Terminal color constants."""

    RED = Fore.RED
    GREEN = Fore.GREEN
    BLUE = Fore.LIGHTBLUE_EX
    YELLOW = Fore.LIGHTYELLOW_EX
    WHITE = Fore.WHITE
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL


@dataclass
class ResolveResult:
    """Result of a DNS resolution attempt."""

    domain: str
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    status: str = "unknown"
    ipv4_cloudflare: bool = False
    ipv6_cloudflare: bool = False
    error: Optional[str] = None

    @property
    def has_non_cf_ip(self) -> bool:
        """Check if at least one IP is not behind Cloudflare."""
        has_v4 = self.ipv4 and not self.ipv4_cloudflare
        has_v6 = self.ipv6 and not self.ipv6_cloudflare
        return has_v4 or has_v6

    @property
    def all_cloudflare(self) -> bool:
        """Check if all resolved IPs are Cloudflare."""
        if not self.ipv4 and not self.ipv6:
            return False
        v4_cf = self.ipv4_cloudflare if self.ipv4 else True
        v6_cf = self.ipv6_cloudflare if self.ipv6 else True
        return v4_cf and v6_cf


@dataclass
class ScanReport:
    """Complete scan report."""

    target_domain: str
    scan_date: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_checked: int = 0
    found: list[ResolveResult] = field(default_factory=list)
    cloudflare: list[ResolveResult] = field(default_factory=list)
    not_found: list[ResolveResult] = field(default_factory=list)
    errors: list[ResolveResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert report to dictionary."""
        return {
            "target_domain": self.target_domain,
            "scan_date": self.scan_date,
            "total_checked": self.total_checked,
            "summary": {
                "found": len(self.found),
                "cloudflare": len(self.cloudflare),
                "not_found": len(self.not_found),
                "errors": len(self.errors),
            },
            "results": {
                "found": [asdict(r) for r in self.found],
                "cloudflare": [asdict(r) for r in self.cloudflare],
                "not_found": [asdict(r) for r in self.not_found],
                "errors": [asdict(r) for r in self.errors],
            },
        }


class CloudflareIPRanges:
    """Manages Cloudflare IP ranges (IPv4 + IPv6) with dynamic fetching."""

    API_URL_V4 = "https://www.cloudflare.com/ips-v4"
    API_URL_V6 = "https://www.cloudflare.com/ips-v6"

    FALLBACK_V4 = [
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "108.162.192.0/18",
        "131.0.72.0/22",
        "141.101.64.0/18",
        "162.158.0.0/15",
        "172.64.0.0/13",
        "173.245.48.0/20",
        "188.114.96.0/20",
        "190.93.240.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
    ]

    FALLBACK_V6 = [
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    ]

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self._networks_v4: list[IPv4Network] = []
        self._networks_v6: list[IPv6Network] = []
        self._loaded = False
        self._used_fallback_v4 = False
        self._used_fallback_v6 = False

    def load(self) -> tuple[bool, bool]:
        """Load Cloudflare IP ranges. Returns (v4_from_api, v6_from_api)."""
        ranges_v4 = self._fetch_from_api(self.API_URL_V4)
        ranges_v6 = self._fetch_from_api(self.API_URL_V6)

        if ranges_v4:
            self._networks_v4 = [IPv4Network(cidr) for cidr in ranges_v4]
            self._used_fallback_v4 = False
        else:
            self._networks_v4 = [IPv4Network(cidr) for cidr in self.FALLBACK_V4]
            self._used_fallback_v4 = True

        if ranges_v6:
            self._networks_v6 = [IPv6Network(cidr) for cidr in ranges_v6]
            self._used_fallback_v6 = False
        else:
            self._networks_v6 = [IPv6Network(cidr) for cidr in self.FALLBACK_V6]
            self._used_fallback_v6 = True

        self._loaded = True
        return (not self._used_fallback_v4, not self._used_fallback_v6)

    def _fetch_from_api(self, url: str) -> list[str]:
        """Fetch IP ranges from Cloudflare's public endpoint."""
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return [line.strip() for line in response.text.strip().split("\n") if line.strip()]
        except requests.RequestException:
            return []

    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if an IP address (v4 or v6) belongs to Cloudflare."""
        if not self._loaded:
            self.load()

        try:
            ip_addr = IPv4Address(ip)
            return any(ip_addr in network for network in self._networks_v4)
        except AddressValueError:
            pass

        try:
            ip_addr = IPv6Address(ip)
            return any(ip_addr in network for network in self._networks_v6)
        except AddressValueError:
            pass

        return False

    @property
    def used_fallback(self) -> tuple[bool, bool]:
        return (self._used_fallback_v4, self._used_fallback_v6)

    @property
    def range_count(self) -> tuple[int, int]:
        return (len(self._networks_v4), len(self._networks_v6))


class ReportWriter:
    """Handles writing scan reports in various formats."""

    @staticmethod
    def write(report: ScanReport, output: TextIO, fmt: OutputFormat) -> None:
        """Write report to output stream in specified format."""
        writers = {
            OutputFormat.NORMAL: ReportWriter._write_normal,
            OutputFormat.JSON: ReportWriter._write_json,
            OutputFormat.YAML: ReportWriter._write_yaml,
            OutputFormat.CSV: ReportWriter._write_csv,
        }
        writers[fmt](report, output)

    @staticmethod
    def _format_ips(result: ResolveResult) -> str:
        """Format IPs with Cloudflare status indicators."""
        parts = []
        if result.ipv4:
            cf_tag = " [CF]" if result.ipv4_cloudflare else ""
            parts.append(f"v4:{result.ipv4}{cf_tag}")
        if result.ipv6:
            cf_tag = " [CF]" if result.ipv6_cloudflare else ""
            parts.append(f"v6:{result.ipv6}{cf_tag}")
        return " | ".join(parts) if parts else "N/A"

    @staticmethod
    def _write_normal(report: ScanReport, output: TextIO) -> None:
        output.write("CloudRip Scan Report\n")
        output.write(f"{'=' * 60}\n")
        output.write(f"Target: {report.target_domain}\n")
        output.write(f"Date: {report.scan_date}\n")
        output.write(f"Total checked: {report.total_checked}\n\n")

        output.write(f"[FOUND] Non-Cloudflare IPs ({len(report.found)}):\n")
        for r in report.found:
            output.write(f"  {r.domain}\n")
            output.write(f"    {ReportWriter._format_ips(r)}\n")

        output.write(f"\n[CLOUDFLARE] Behind Cloudflare ({len(report.cloudflare)}):\n")
        for r in report.cloudflare:
            output.write(f"  {r.domain}\n")
            output.write(f"    {ReportWriter._format_ips(r)}\n")

        output.write(f"\n[NOT FOUND] No DNS record ({len(report.not_found)}):\n")
        for r in report.not_found:
            output.write(f"  {r.domain}\n")

        if report.errors:
            output.write(f"\n[ERRORS] ({len(report.errors)}):\n")
            for r in report.errors:
                output.write(f"  {r.domain}: {r.error}\n")

    @staticmethod
    def _write_json(report: ScanReport, output: TextIO) -> None:
        json.dump(report.to_dict(), output, indent=2)
        output.write("\n")

    @staticmethod
    def _write_yaml(report: ScanReport, output: TextIO) -> None:
        data = report.to_dict()
        ReportWriter._dict_to_yaml(data, output)

    @staticmethod
    def _dict_to_yaml(data: dict, output: TextIO, indent: int = 0) -> None:
        """Simple YAML serializer without external dependencies."""
        prefix = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                output.write(f"{prefix}{key}:\n")
                ReportWriter._dict_to_yaml(value, output, indent + 1)
            elif isinstance(value, list):
                output.write(f"{prefix}{key}:\n")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for k, v in item.items():
                            if first:
                                output.write(f"{prefix}  - {k}: {v}\n")
                                first = False
                            else:
                                output.write(f"{prefix}    {k}: {v}\n")
                    else:
                        output.write(f"{prefix}  - {item}\n")
            else:
                output.write(f"{prefix}{key}: {value}\n")

    @staticmethod
    def _write_csv(report: ScanReport, output: TextIO) -> None:
        writer = csv.writer(output)
        writer.writerow(["domain", "ipv4", "ipv4_cloudflare", "ipv6", "ipv6_cloudflare", "status", "error"])

        for r in report.found + report.cloudflare + report.not_found + report.errors:
            writer.writerow([
                r.domain,
                r.ipv4 or "",
                r.ipv4_cloudflare,
                r.ipv6 or "",
                r.ipv6_cloudflare,
                r.status,
                r.error or "",
            ])


class CloudRip:
    """Main CloudRip scanner."""

    def __init__(
        self,
        domain: str,
        wordlists: list[str],
        threads: int = 10,
        output_file: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.NORMAL,
        verbose: bool = False,
        quiet: bool = False,
    ):
        self.domain = domain
        self.wordlists = [Path(w) for w in wordlists]
        self.threads = threads
        self.output_file = Path(output_file) if output_file else None
        self.output_format = output_format
        self.verbose = verbose
        self.quiet = quiet

        self.cf_ranges = CloudflareIPRanges()
        self.report = ScanReport(target_domain=domain)
        self.stop_requested = False

    def log(self, message: str, level: str = "info") -> None:
        """Print message to console based on verbosity settings."""
        if self.quiet:
            return

        if level == "verbose" and not self.verbose:
            return

        print(message)

    def display_banner(self) -> None:
        if self.quiet:
            return

        figlet_text = pyfiglet.Figlet(font="slant").renderText("CloudRip")
        print(f"{Colors.BLUE}{figlet_text}")
        print(f"{Colors.RED}CloudFlare Bypasser - Find Real IP Addresses Behind Cloudflare")
        print(f'{Colors.YELLOW}"Ripping through the clouds to expose the truth"')
        print(f"{Colors.WHITE}GitHub: {Colors.BLUE}https://github.com/lucky89144/CloudRip\n")

    def load_wordlists(self) -> list[str]:
        """Load and merge all wordlists."""
        subdomains: set[str] = set()

        for wordlist_path in self.wordlists:
            if not wordlist_path.exists():
                self.log(f"{Colors.RED}[ERROR] Wordlist not found: {wordlist_path}")
                continue

            with open(wordlist_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        subdomains.add(line.strip())

            self.log(f"{Colors.YELLOW}[INFO] Loaded wordlist: {wordlist_path}")

        if not subdomains:
            self.log(f"{Colors.RED}[ERROR] No subdomains loaded from any wordlist")
            sys.exit(1)

        return sorted(subdomains)

    def _resolve_record(self, domain: str, record_type: str) -> Optional[str]:
        """Resolve a single DNS record type."""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                return rdata.address
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout,
                dns.resolver.LifetimeTimeout):
            pass
        except Exception:
            pass
        return None

    def resolve_domain(self, subdomain: Optional[str] = None) -> ResolveResult:
        """Resolve a domain or subdomain for both A and AAAA records."""
        full_domain = f"{subdomain}.{self.domain}" if subdomain else self.domain

        result = ResolveResult(domain=full_domain)

        # Resolve IPv4 (A record)
        ipv4 = self._resolve_record(full_domain, "A")
        if ipv4:
            result.ipv4 = ipv4
            result.ipv4_cloudflare = self.cf_ranges.is_cloudflare_ip(ipv4)

        # Resolve IPv6 (AAAA record)
        ipv6 = self._resolve_record(full_domain, "AAAA")
        if ipv6:
            result.ipv6 = ipv6
            result.ipv6_cloudflare = self.cf_ranges.is_cloudflare_ip(ipv6)

        # Determine status
        if not result.ipv4 and not result.ipv6:
            result.status = "not_found"
            self.log(f"{Colors.RED}[NOT FOUND] {full_domain}", level="verbose")
        elif result.has_non_cf_ip:
            result.status = "found"
            self._log_found(result)
        else:
            result.status = "cloudflare"
            self._log_cloudflare(result)

        return result

    def _log_found(self, result: ResolveResult) -> None:
        """Log a found (non-CF) result."""
        parts = []
        if result.ipv4:
            tag = f"{Colors.YELLOW}[CF]" if result.ipv4_cloudflare else ""
            parts.append(f"v4:{result.ipv4}{tag}")
        if result.ipv6:
            tag = f"{Colors.YELLOW}[CF]" if result.ipv6_cloudflare else ""
            parts.append(f"v6:{result.ipv6}{tag}")

        ips_str = f"{Colors.WHITE} | ".join(parts)
        self.log(f"{Colors.GREEN}[FOUND] {result.domain} -> {ips_str}")

    def _log_cloudflare(self, result: ResolveResult) -> None:
        """Log a Cloudflare result."""
        parts = []
        if result.ipv4:
            parts.append(f"v4:{result.ipv4}")
        if result.ipv6:
            parts.append(f"v6:{result.ipv6}")

        ips_str = " | ".join(parts)
        self.log(f"{Colors.YELLOW}[CLOUDFLARE] {result.domain} -> {ips_str}")

    def add_result(self, result: ResolveResult) -> None:
        """Categorize and store a result."""
        if result.status == "found":
            self.report.found.append(result)
        elif result.status == "cloudflare":
            self.report.cloudflare.append(result)
        elif result.status == "not_found":
            self.report.not_found.append(result)
        else:
            self.report.errors.append(result)

    def save_report(self) -> None:
        """Save report to file if output path specified."""
        if not self.output_file:
            return

        try:
            with open(self.output_file, "w", encoding="utf-8") as f:
                ReportWriter.write(self.report, f, self.output_format)
            self.log(f"{Colors.GREEN}[INFO] Report saved to {self.output_file}")
        except OSError as e:
            self.log(f"{Colors.RED}[ERROR] Failed to save report: {e}")

    def handle_interrupt(self, signum: int, frame) -> None:
        """Handle Ctrl+C gracefully."""
        if self.stop_requested:
            print(f"{Colors.RED}\n[INFO] Force quitting...")
            sys.exit(0)

        print(f"{Colors.RED}\n[INFO] Ctrl+C detected. Quit? (y/n): ", end="")

        try:
            if input().strip().lower() == "y":
                self.stop_requested = True
            else:
                print(f"{Colors.YELLOW}[INFO] Resuming...")
        except EOFError:
            self.stop_requested = True

    def run(self) -> ScanReport:
        """Execute the scan."""
        signal.signal(signal.SIGINT, self.handle_interrupt)

        self.display_banner()

        # Load Cloudflare ranges
        self.log(f"{Colors.YELLOW}[INFO] Fetching Cloudflare IP ranges...")
        v4_api, v6_api = self.cf_ranges.load()
        v4_count, v6_count = self.cf_ranges.range_count

        if v4_api:
            self.log(f"{Colors.GREEN}[INFO] IPv4: {v4_count} ranges from API")
        else:
            self.log(f"{Colors.YELLOW}[WARNING] IPv4: using {v4_count} fallback ranges")

        if v6_api:
            self.log(f"{Colors.GREEN}[INFO] IPv6: {v6_count} ranges from API")
        else:
            self.log(f"{Colors.YELLOW}[WARNING] IPv6: using {v6_count} fallback ranges")

        # Check root domain first
        self.log(f"{Colors.YELLOW}[INFO] Checking root domain: {self.domain}")
        root_result = self.resolve_domain()
        self.add_result(root_result)
        self.report.total_checked += 1

        # Load wordlists
        subdomains = self.load_wordlists()
        self.log(f"{Colors.YELLOW}[INFO] {len(subdomains)} unique subdomains to check")
        self.log(f"{Colors.YELLOW}[INFO] Starting scan...\n")

        # Scan subdomains
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.resolve_domain, sub): sub
                for sub in subdomains
            }

            for future in as_completed(futures):
                if self.stop_requested:
                    self.log(f"{Colors.RED}[INFO] Scan interrupted.")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                result = future.result()
                self.add_result(result)
                self.report.total_checked += 1
                time.sleep(0.05)

        # Summary
        self.log(f"\n{Colors.WHITE}{'=' * 60}")
        self.log(f"{Colors.WHITE}Scan complete: {self.report.total_checked} checked")
        self.log(f"{Colors.GREEN}  Found (non-CF): {len(self.report.found)}")
        self.log(f"{Colors.YELLOW}  Cloudflare: {len(self.report.cloudflare)}")
        self.log(f"{Colors.RED}  Not found: {len(self.report.not_found)}")

        if self.report.errors:
            self.log(f"{Colors.YELLOW}  Errors: {len(self.report.errors)}")

        self.save_report()

        return self.report


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CloudRip v2 - CloudFlare Bypasser (IPv4 + IPv6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cloudrip.py example.com
  python cloudrip.py example.com -w wordlist1.txt -w wordlist2.txt
  python cloudrip.py example.com -o report.json -f json
  python cloudrip.py example.com -v  # verbose mode
  python cloudrip.py example.com -q  # quiet mode
        """,
    )

    parser.add_argument("domain", help="Target domain (e.g., example.com)")

    parser.add_argument(
        "-w", "--wordlist",
        action="append",
        dest="wordlists",
        default=[],
        help="Wordlist file(s). Can be specified multiple times.",
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Concurrent threads (default: 10)",
    )

    parser.add_argument(
        "-o", "--output",
        help="Output file for report",
    )

    parser.add_argument(
        "-f", "--format",
        choices=["normal", "json", "yaml", "csv"],
        default="normal",
        help="Output format (default: normal)",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show all results including not found",
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Minimal output (only found IPs)",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    wordlists = args.wordlists if args.wordlists else ["dom.txt"]

    scanner = CloudRip(
        domain=args.domain,
        wordlists=wordlists,
        threads=args.threads,
        output_file=args.output,
        output_format=OutputFormat(args.format),
        verbose=args.verbose,
        quiet=args.quiet,
    )

    scanner.run()


if __name__ == "__main__":
    main()
