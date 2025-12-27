# Advanced Reflected XSS Scanner

A powerful, multi-threaded, and context-aware Reflected Cross-Site Scripting (XSS) scanner written in Python. It supports crawling, WAF bypassing, and custom payload injection with detailed reporting.

## 🚀 Features

- **Multi-Mode Scanning**: Scan single URLs, lists of URLs, or crawl and scan targets recursively.
- **Smart Reflection Detection**: Detects reflected characters in the response body.
- **WAF Bypass Mode**: Tests payload characters individually to identify and bypass Web Application Firewalls (403 filtering).
- **Force Mode**: Strict verification that requires *all* injected characters to be reflected (reduces false positives).
- **Context Analysis**: Checks for HTML entities and hex encoding to avoid false positives.
- **Performance**: Multi-threaded architecture for fast scanning.
- **Crawler**: Built-in web crawler to extract links and parameters from target domains.
- **Proxy Support**: Supports HTTP/HTTPS proxies and proxy lists.

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/xss-scanner.git](https://github.com/YOUR_USERNAME/xss-scanner.git)
   cd xss-scanner
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt

## 🛠 Usage

**Basic Scan**
* Scan a single URL for Reflected XSS:
  ```bash
  python xss-scanner.py -u "[http://example.com/search.php?q=test](http://example.com/search.php?q=test)"
**Scan a List of URLs**
* Load URLs from a file and scan them:
  ```bash
  python xss-scanner.py -l urls.txt --threads 20
**Crawl and Scan**
* Crawl a target URL for links and scan discovered parameters:
  ```bash
  python xss-scanner.py -uC "[http://example.com](http://example.com)"
**WAF Bypass Mode**
* Test characters one-by-one to identify which specific characters are triggering the WAF:
  ```bash
  python xss-scanner.py -u "[http://example.com/search?q=test](http://example.com/search?q=test)" --bypass-waf
**Strict Mode (Force)**
* Only report a vulnerability if ALL custom characters are reflected (useful for confirming exploitability):
  ```bash
  python xss-scanner.py -u "[http://example.com/page?id=1](http://example.com/page?id=1)" --custom-chars "'<>" --force
  
## ⚙️ Arguments

| Argument | Description |
|--------|-------------|
| `-u, --url` | Single URL to scan (must have parameters). |
| `-l, --list` | File containing a list of URLs to scan. |
| `-uC, --url-crawl` | Single URL to crawl and then scan discovered links. |
| `-lC, --list-crawl` | File containing a list of URLs to crawl and scan. |
| `-o, --output` | File to save vulnerable URLs. |
| `-s, --silent` | Silent mode (only prints found vulnerabilities). |
| `-v, --verbose` | Verbose mode (shows progress even in silent mode). |
| `-t, --threads` | Number of threads to use (default: 10). |
| `--timeout` | Request timeout in seconds (default: 10). |
| `--proxy` | Single proxy (e.g., `http://127.0.0.1:8080`). |
| `--proxy-list` | File containing a list of proxies. |
| `-c, --custom-chars` | Custom payload characters to test (e.g., `"<>'"`). |
| `--bypass-waf` | Test characters individually to detect/bypass WAF blocks. |
| `--force` | Only report vulnerable if **ALL** injected characters are reflected. |

## 📝 Example Output
```bash
[INFO] Starting scan on 1 URLs...
[INFO] Testing param 'q' on: [http://example.com/search.php?q=hackedxss](http://example.com/search.php?q=hackedxss)...
[VULN] Potential XSS Found on param 'q': [http://example.com/search.php](http://example.com/search.php)... (Reflected: "><)
[+] Scan completed.
```

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
