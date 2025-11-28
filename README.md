# CloudRip

A tool that helps you find the real IP addresses hiding behind Cloudflare by checking subdomains. For penetration testing, security research, and learning how Cloudflare protection works.

## What it does

- **IPv4 & IPv6 support** - Resolves both A and AAAA records
- **Multiple IPs detection** - Finds ALL IPs behind a domain, not just the first one
- **Progress bar** - Real-time progress with live stats (found/cloudflare count)
- **Dynamic Cloudflare IP detection** - Fetches latest IP ranges from Cloudflare's API (with fallback)
- **Fast subdomain scanning** - Uses multiple threads to speed things up
- **Multiple wordlists** - Combine several wordlists in a single scan
- **Wordlist comments** - Use `#` to add comments in your wordlists
- **Multiple output formats** - Export to JSON, YAML, CSV, or plain text
- **Verbose & quiet modes** - Control output verbosity
- **Filters out Cloudflare IPs** - Only shows you the real server addresses
- **Bring your own wordlist** - Or use the built-in one (dom.txt)
- **Save your findings** - Export results to a file for later
- **Rate limiting** - Won't spam the target and get you blocked
- **Solid default wordlist** - Organized and comprehensive for better results

## Getting it running

You'll need Python 3. Create a virtual environment and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## How to use it

Basic scan:
```bash
python3 cloudrip.py example.com
```

With all the options:
```bash
python3 cloudrip.py example.com -w wordlist1.txt -w wordlist2.txt -t 20 -o report.json -f json
```

**Options:**

| Option | Description |
|--------|-------------|
| `<domain>` | The site you're testing (like example.com) |
| `-w, --wordlist` | Wordlist file(s). Can be specified multiple times (default: dom.txt) |
| `-t, --threads` | How many threads to run (default: 10) |
| `-o, --output` | Save results to a file |
| `-f, --format` | Output format: `normal`, `json`, `yaml`, `csv` (default: normal) |
| `-v, --verbose` | Show all results including "not found" entries |
| `-q, --quiet` | Minimal output - only show found IPs |

## Examples

**Basic scan:**
```bash
python3 cloudrip.py example.com
```

**Multiple wordlists with JSON output:**
```bash
python3 cloudrip.py example.com -w subs1.txt -w subs2.txt -o report.json -f json
```

**Fast scan with 50 threads:**
```bash
python3 cloudrip.py example.com -t 50 -o results.csv -f csv
```

**Verbose mode (see all attempts):**
```bash
python3 cloudrip.py example.com -v
```

**Quiet mode (only found IPs):**
```bash
python3 cloudrip.py example.com -q -o found.txt
```

## Output Formats

### Normal (default)
```
CloudRip Scan Report
============================================================
Target: example.com
Date: 2025-11-28T12:00:00+00:00
Total checked: 150

[FOUND] Non-Cloudflare IPs (3):
  mail.example.com
    v4:[192.168.1.1, 192.168.1.2, 192.168.1.3]
  ftp.example.com
    v4:[10.0.0.1] | v6:[2001:db8::1]

[CLOUDFLARE] Behind Cloudflare (5):
  www.example.com
    v4:[104.16.1.1 [CF], 172.67.1.1 [CF]] | v6:[2606:4700::1 [CF]]
```

### JSON
```json
{
  "target_domain": "example.com",
  "scan_date": "2025-11-28T12:00:00+00:00",
  "total_checked": 150,
  "summary": {
    "found": 3,
    "cloudflare": 5,
    "not_found": 142,
    "errors": 0
  },
  "results": { ... }
}
```

### CSV
```csv
domain,ipv4,ipv4_cloudflare,ipv6,ipv6_cloudflare,status,error
mail.example.com,192.168.1.1;192.168.1.2;192.168.1.3,,,,found,
www.example.com,104.16.1.1;172.67.1.1,104.16.1.1;172.67.1.1,2606:4700::1,2606:4700::1,cloudflare,
```

## Version History

### v2.1.0 (Current)

**New Features:**
- Full IPv6 support (AAAA record resolution)
- Multiple IPs detection - Resolves ALL IPs behind a domain (A/AAAA records can return multiple IPs)
- Real-time progress bar with live stats
- Dynamic Cloudflare IP range fetching from official API
- Multiple output formats: JSON, YAML, CSV, normal text
- Multiple wordlists support (combine with `-w file1.txt -w file2.txt`)
- Verbose mode (`-v`) to see all results including not found
- Quiet mode (`-q`) for minimal output
- Automatic root domain checking before subdomain scan
- Comprehensive scan summary with statistics
- Structured report with categorized results (found, cloudflare, not_found, errors)
- Wordlist comment support (lines starting with `#`)

**Technical Improvements:**
- Complete rewrite with object-oriented architecture
- Type hints throughout the codebase
- Dataclasses for structured data handling
- Better error handling (LifetimeTimeout, EOFError)
- Cleaner executor shutdown on interrupt
- Reduced rate limiting delay (0.1s → 0.05s)

### v2.0.0

**Wordlist Improvements:**
- Massive wordlist upgrade - Took dom.txt from 100 to 600+ subdomains
- Added API variants, cloud infrastructure, IoT endpoints
- Covers auth/security, payment gateways, analytics, CI/CD pipelines
- Way better geo coverage - cities and more countries
- Handles modern cloud-native and microservices setups
- Better database and service discovery hits

### v1.5.0
- Rate limiting so you don't get blocked
- Thread handling works better now
- Doesn't crash on DNS failures anymore
- Prettier output with colors

### v1.0.0
- First drop with the core stuff
- Multi-threaded subdomain scanning
- Filters out Cloudflare IPs
- Bring your own wordlist
- Save results to file
- Basic dom.txt with ~100 entries

## Contributors

Huge thanks to [@Dxsk](https://github.com/Dxsk) for the contribution to v2.1.0

## Contributing

Got ideas for improvements? Found a bug? Pull requests and issues are welcome! If it's better wordlists, new features, or bug fixes - all contributions help.

## Important Legal Stuff

**Only use CloudRip on systems you have permission to test.** This tool is for ethical security research, penetration testing with authorization, and educational purposes. Using it against websites without permission is illegal and not cool. You're responsible for how you use this tool.

## License

MIT License - use responsibly.
