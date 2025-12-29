#!/usr/bin/python3
import argparse
import sys
import asyncio
import aiohttp
import random
import re
import string
import ssl
import warnings
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# Suppress XML parsing warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
CANARY = "hackedxss"

# Default dangerous characters 
DEFAULT_PAYLOAD_CHARS = "\"><';)(&|\\{}[]"

# Extensions to IGNORE during crawl (Static assets)
IGNORED_EXTENSIONS = (
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', 
    '.webp', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', 
    '.pdf', '.zip', '.rar', '.tar', '.gz', '.xml', '.json'
)

# Global Sets for Deduplication
scanned_params = set() 
crawled_urls = set()
vulnerable_urls = []

class AsyncXSSScanner:
    def __init__(self, args):
        self.args = args
        self.proxies = self.load_proxies()
        self.sem = None 
        self.headers = {'User-Agent': USER_AGENT}

        if self.args.custom_chars:
            self.chars_to_test = self.args.custom_chars
        else:
            self.chars_to_test = DEFAULT_PAYLOAD_CHARS
            
    def load_proxies(self):
        proxy_list = []
        if self.args.proxy:
            proxy_list.append(self.format_proxy(self.args.proxy))
        
        if self.args.proxy_list:
            try:
                with open(self.args.proxy_list, 'r') as f:
                    for line in f:
                        if line.strip():
                            proxy_list.append(self.format_proxy(line.strip()))
            except Exception as e:
                self.print_msg(f"Error loading proxy list: {e}", type="error")
                sys.exit(1)
        return proxy_list

    def format_proxy(self, proxy_str):
        if "://" not in proxy_str:
            return f"http://{proxy_str}"
        return proxy_str

    def get_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    def print_msg(self, text, type="info"):
        clear_line = "\r\033[K"
        
        if type == "info":
            sys.stdout.write(f"{clear_line}[{Fore.BLUE}INFO{Style.RESET_ALL}] {text}\n")
        elif type == "vuln":
            sys.stdout.write(f"{clear_line}[{Fore.RED}VULN{Style.RESET_ALL}] {text}\n")
        elif type == "good":
            sys.stdout.write(f"{clear_line}[{Fore.GREEN}+{Style.RESET_ALL}] {text}\n")
        elif type == "error":
            sys.stdout.write(f"{clear_line}[{Fore.YELLOW}ERR{Style.RESET_ALL}] {text}\n")
        elif type == "crawl":
             sys.stdout.write(f"{clear_line}[{Fore.CYAN}CRAWL{Style.RESET_ALL}] {text}\n")
        elif type == "waf":
             sys.stdout.write(f"{clear_line}[{Fore.MAGENTA}WAF{Style.RESET_ALL}] {text}\n")
        elif type == "debug":
             sys.stdout.write(f"[{Fore.YELLOW}DEBUG{Style.RESET_ALL}] {text}\n")
        elif type == "plain":
             sys.stdout.write(f"{clear_line}{text}\n")
             
        sys.stdout.flush()

    def log(self, message, type="info"):
        if self.args.silent:
            if type == "vuln":
                sys.stdout.write(f"\r\033[K{message}\n")
                sys.stdout.flush()
            return

        self.print_msg(message, type)

    async def make_request(self, session, url):
        async with self.sem: 
            try:
                proxy = self.get_proxy()
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

                async with session.get(
                    url, 
                    proxy=proxy, 
                    timeout=aiohttp.ClientTimeout(total=self.args.timeout),
                    ssl=ssl_ctx,
                    allow_redirects=True
                ) as response:
                    content_bytes = await response.read()
                    return response.status, str(response.url), content_bytes
            except Exception as e:
                if not self.args.silent and self.args.verbose:
                    err_msg = str(e).split(':')[-1].strip() if ':' in str(e) else str(e)
                    self.log(f"Connection error on {url}: {err_msg}", type="error")
                return None, None, None

    def normalize_url(self, url):
        if not url.startswith('http://') and not url.startswith('https://'):
            return f'https://{url}'
        return url

    def get_base_domain_name(self, url):
        try:
            netloc = urlparse(url).netloc
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            if netloc.startswith('www.'):
                return netloc[4:]
            return netloc
        except:
            return ""

    async def crawl_and_extract(self, session, url, depth=2):
        if depth < 0:
            return []
        
        if url in crawled_urls:
            return []
        
        crawled_urls.add(url)
        self.log(f"Crawling (Depth {depth}): {url}", type="crawl")

        status, final_url, content_bytes = await self.make_request(session, url)
        if not content_bytes:
            return []

        try:
            content = content_bytes.decode('utf-8', errors='ignore')
        except:
            return []

        base_domain_root = self.get_base_domain_name(final_url)
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
        except Exception:
            return []
            
        extracted_raw_links = set()

        tags_attributes = {
            'a': 'href', 'link': 'href', 'area': 'href',
            'script': 'src', 'img': 'src', 'iframe': 'src',
            'embed': 'src', 'source': 'src', 'track': 'src',
            'object': 'data', 'base': 'href'
        }

        for tag_name, attr_name in tags_attributes.items():
            for tag in soup.find_all(tag_name):
                val = tag.get(attr_name)
                if val:
                    extracted_raw_links.add(val.strip())

        regex_links = re.findall(r'(?:href|src|url|action)\s*=\s*["\']([^"\']+)["\']', content)
        regex_abs = re.findall(r'(https?://[a-zA-Z0-9.-]+(?:/[^\s"\'<>]*)?)', content)
        
        extracted_raw_links.update(regex_links)
        extracted_raw_links.update(regex_abs)

        for form in soup.find_all('form'):
            action = form.get('action') or ''
            
            if not action:
                action_url = final_url
            else:
                action_url = urljoin(final_url, action)

            form_params = {}
            for inp in form.find_all(['input', 'textarea', 'select', 'button']):
                name = inp.get('name')
                if name:
                    form_params[name] = 'test'

            if form_params:
                try:
                    parsed_action = urlparse(action_url)
                    current_q = parse_qs(parsed_action.query)
                    current_q.update(form_params) 
                    
                    new_query = urlencode(current_q, doseq=True)
                    constructed_url = urlunparse((
                        parsed_action.scheme, parsed_action.netloc, parsed_action.path,
                        parsed_action.params, new_query, parsed_action.fragment
                    ))
                    extracted_raw_links.add(constructed_url)
                except:
                    pass

        scan_targets = set()     
        next_crawl_targets = set() 

        for raw_link in extracted_raw_links:
            if not raw_link or raw_link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                continue

            try:
                full_url = urljoin(final_url, raw_link)
                parsed = urlparse(full_url)
                
                link_domain_root = self.get_base_domain_name(full_url)
                if link_domain_root != base_domain_root:
                    continue

                path_lower = parsed.path.lower()
                if path_lower.endswith(IGNORED_EXTENSIONS):
                    continue

                if parsed.query:
                    q_params = parse_qs(parsed.query)
                    sorted_q = urlencode(q_params, doseq=True)
                    unique_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, sorted_q, parsed.fragment
                    ))
                    scan_targets.add(unique_url)
                
                if depth > 0:
                    crawl_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
                    if crawl_url not in crawled_urls:
                        next_crawl_targets.add(full_url) 

            except:
                continue

        if self.args.output_crawl and scan_targets:
            try:
                with open(self.args.output_crawl, 'a') as f:
                    for link in scan_targets:
                        f.write(link + '\n')
            except Exception as e:
                pass

        if scan_targets:
            self.log(f"Found {len(scan_targets)} parameter URLs on {url}", type="info")

        results = list(scan_targets)
        
        if depth > 0 and next_crawl_targets:
            limited_targets = list(next_crawl_targets)[:20] 
            tasks = [self.crawl_and_extract(session, target, depth - 1) for target in limited_targets]
            sub_results = await asyncio.gather(*tasks)
            for sub_res in sub_results:
                results.extend(sub_res)

        return results

    async def check_xss(self, session, url):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not query_params:
            return

        path_identifier = f"{parsed.netloc}{parsed.path}"
        
        for param_name in query_params:
            dedupe_key = f"{path_identifier}:{param_name}"
            
            if dedupe_key in scanned_params:
                continue
            scanned_params.add(dedupe_key)
            
            delimiter = "".join(random.choices(string.ascii_lowercase, k=6))
            
            payload_body = f"{delimiter}{self.chars_to_test}{delimiter}"
            full_payload = f"{CANARY}{payload_body}"
            
            params_copy = query_params.copy()
            params_copy[param_name] = [full_payload]
            
            new_query = urlencode(params_copy, doseq=True)
            target_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            self.log(f"Testing param '{param_name}' on: {target_url}", type="info")
            if self.args.debug:
                self.print_msg(f"Target URL: {target_url}", type="debug")
            
            status, _, content = await self.make_request(session, target_url)
            
            if content is None:
                continue

            canary_bytes = CANARY.encode()
            
            if canary_bytes in content:
                reflected_chars = []
                start_marker_str = f"{CANARY}{delimiter}"
                start_marker = start_marker_str.encode()
                delimiter_bytes = delimiter.encode()
                
                start_indices = [m.start() for m in re.finditer(re.escape(start_marker), content)]
                
                for i, start_idx in enumerate(start_indices):
                    payload_start = start_idx + len(start_marker)
                    window_len = len(self.chars_to_test) * 10 + 100
                    search_window = content[payload_start : payload_start + window_len]
                    
                    end_idx = search_window.find(delimiter_bytes)
                    
                    if end_idx != -1:
                        reflected_segment = search_window[:end_idx]
                        
                        if not reflected_segment or canary_bytes in reflected_segment:
                            continue
                        
                        has_encoded_tags = False
                        if re.search(rb'(%3C|%3c|%3E|%3e|%22|&lt;|&gt;|&quot;)', reflected_segment):
                            has_encoded_tags = True

                        for char in self.chars_to_test:
                            char_bytes = char.encode()
                            
                            if char_bytes in reflected_segment:
                                found_valid_char = False
                                for m in re.finditer(re.escape(char_bytes), reflected_segment):
                                    char_idx = m.start()
                                    
                                    # --- Odd/Even Backslash Check ---
                                    # Count consecutive backslashes immediately BEFORE this character
                                    bs_count = 0
                                    curr = char_idx - 1
                                    while curr >= 0 and reflected_segment[curr] == 92: # 92 is ASCII for \
                                        bs_count += 1
                                        curr -= 1
                                    
                                    # If Odd: The last backslash escapes our character -> Ignored
                                    # If Even: The backslashes escaped themselves (e.g. \\) -> Valid
                                    if bs_count % 2 == 1:
                                        continue

                                    # 2. Forward Check for the Backslash character ITSELF
                                    # If we found a '\' (and it wasn't escaped by a previous \ per above check),
                                    # we need to see if it is escaping the NEXT character.
                                    if char == '\\':
                                        if char_idx + 1 < len(reflected_segment):
                                            next_char_code = reflected_segment[char_idx + 1]
                                            # If followed by " or ' or \ it is likely serving as an escape char
                                            if next_char_code in [34, 39, 92]:
                                                continue

                                    # 3. HTML Entity Checks
                                    if char == '&':
                                        sub = reflected_segment[char_idx:]
                                        if re.match(rb'&([a-zA-Z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});', sub): 
                                            continue 
                                    
                                    if char == ';':
                                        pre = reflected_segment[:char_idx+1]
                                        if re.search(rb'&([a-zA-Z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});$', pre): 
                                            continue

                                    # 4. URL Encoding check
                                    if char == '%':
                                        sub = reflected_segment[char_idx:]
                                        if re.match(rb'%[0-9a-fA-F]{2}', sub): 
                                            continue

                                    if has_encoded_tags:
                                        if char in ["'", "(", ")", ";"]:
                                            continue

                                    found_valid_char = True
                                    break
                                
                                if found_valid_char:
                                    if char not in reflected_chars:
                                        reflected_chars.append(char)
                    
                if reflected_chars:
                    reflected_str = "".join(reflected_chars)
                    if self.args.force and set(reflected_chars) != set(self.chars_to_test):
                         pass
                    else:
                        self.report_vuln(target_url, param_name, f"Reflected chars: {reflected_str}")
                else:
                    self.log(f"Canary reflected but chars filtered/encoded on {param_name}", type="info")

    def report_vuln(self, url, param, note):
        if self.args.silent:
            msg = f"{url} | {note}"
        else:
            msg = f"Potential XSS Found on param '{param}': {url} ({note})"
            
        self.log(msg, type="vuln")
        vulnerable_urls.append(url)
        
        if self.args.output:
            with open(self.args.output, 'a') as f:
                f.write(f"{url}\n")
        if self.args.output_context:
            with open(self.args.output_context, 'a') as f:
                f.write(f"{url} | {note}\n")

    async def run(self):
        self.sem = asyncio.Semaphore(self.args.concurrency)
        urls_to_scan = []

        connector = aiohttp.TCPConnector(
            limit=self.args.concurrency + 10, 
            ttl_dns_cache=300,
            ssl=False
        )
        
        async with aiohttp.ClientSession(connector=connector, headers=self.headers) as session:
            self.session = session 

            if self.args.url:
                urls_to_scan.append(self.normalize_url(self.args.url))

            if self.args.list:
                try:
                    with open(self.args.list, 'r') as f:
                        urls_to_scan.extend([self.normalize_url(line.strip()) for line in f if line.strip()])
                except FileNotFoundError:
                    self.print_msg("URL list file not found!", type="error")
                    return
            
            crawl_targets = []
            if self.args.url_crawl:
                crawl_targets.append(self.normalize_url(self.args.url_crawl))
            
            if self.args.list_crawl:
                try:
                    with open(self.args.list_crawl, 'r') as f:
                         crawl_targets.extend([self.normalize_url(line.strip()) for line in f if line.strip()])
                except FileNotFoundError:
                    self.print_msg("Crawl list file not found!", type="error")

            if crawl_targets:
                self.log(f"Starting Crawl on {len(crawl_targets)} targets...", type="good")
                crawl_tasks = [self.crawl_and_extract(session, target, depth=2) for target in crawl_targets]
                crawl_results = await asyncio.gather(*crawl_tasks)
                for res in crawl_results:
                    urls_to_scan.extend(res)

            unique_urls_to_scan = list(set(urls_to_scan))
            
            if not unique_urls_to_scan:
                self.print_msg("No URLs to scan. Crawl found no parameters or no URLs provided.", type="error")
                return

            self.log(f"Starting scan on {len(unique_urls_to_scan)} unique URLs...", type="good")
            
            scan_tasks = []
            for url in unique_urls_to_scan:
                scan_tasks.append(self.check_xss(session, url))
            
            if scan_tasks:
                for future in asyncio.as_completed(scan_tasks):
                    await future

        if (not self.args.silent) or (self.args.silent and self.args.verbose):
            sys.stdout.write("\n")
            self.log("Scan completed.", type="good")

def parse_arguments():
    parser = argparse.ArgumentParser(description='RefleXSS - Advanced Reflected XSS Scanner (Async)')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to scan (must have params)')
    group.add_argument('-l', '--list', help='File containing list of URLs to scan')
    group.add_argument('-uC', '--url-crawl', help='Single URL to crawl and scan')
    group.add_argument('-lC', '--list-crawl', help='File containing list of URLs to crawl and scan')

    parser.add_argument('-o', '--output', help='File to save vulnerable URLs')
    parser.add_argument('-oc', '--output-context', help='File to save vulnerable URLs WITH reflected characters')
    parser.add_argument('-oC', '--output-crawl', help='File to save crawled URLs (Query Strings)')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent mode (only vulns)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode (Show progress even in silent mode)')
    parser.add_argument('--debug', action='store_true', help='Enable DEEP DEBUG mode to see raw response bytes')
    parser.add_argument('--proxy', help='Single proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxy-list', help='File containing list of proxies')
    parser.add_argument('--concurrency', type=int, default=25, help='Max concurrent requests (default 25)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout in seconds (default 5)')
    parser.add_argument('-c', '--custom-chars', help='Custom payload characters (overrides default). E.g: -c "<>\"\'"')
    parser.add_argument('--bypass-waf', action='store_true', help='Test characters one by one to detect WAF blocks (403)')
    parser.add_argument('--force', action='store_true', help='Force mode: Only report vulnerable if ALL injected characters are reflected.')

    return parser.parse_args()

if __name__ == "__main__":
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

        args = parse_arguments()
        
        if not args.silent:
            print(Fore.MAGENTA + r"""
    ____       ______   __   _  _____ _____
   / __ \___  / __/ /__ \ \_/ // ___// ___/
  / /_/ / _ \/ /_/ / _ \ \/ /  \__ \ \__ \ 
 / _, _/  __/ __/ /  __/ / /  ___/ /___/ / 
/_/ |_|\___/_/ /_/\___/_/ \_//____//____/  
                                           
            """ + Style.RESET_ALL)
            print(f"[{Fore.GREEN}+{Style.RESET_ALL}] RefleXSS Async Engine started...")
            if args.debug:
                 print(f"[{Fore.YELLOW}DEBUG{Style.RESET_ALL}] DEBUG MODE ENABLED - Raw bytes will be analyzed.")

        scanner = AsyncXSSScanner(args)
        asyncio.run(scanner.run())

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down please wait...{Style.RESET_ALL}")
        sys.exit(0)
