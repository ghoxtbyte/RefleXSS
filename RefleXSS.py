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
    '.pdf', '.zip', '.rar', '.tar', '.gz', '.xml'
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
             sys.stdout.write(f"{clear_line}[{Fore.YELLOW}DEBUG{Style.RESET_ALL}] {text}\n")
        elif type == "plain":
             sys.stdout.write(f"{clear_line}{text}\n")
             
        sys.stdout.flush()

    def log(self, message, type="info"):
        # Always print debug messages if debug flag is on
        if type == "debug":
            if self.args.debug:
                self.print_msg(message, type)
            return

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
                    text = await response.text(errors='ignore')
                    return response.status, str(response.url), text
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

        status, final_url, content = await self.make_request(session, url)
        if not content:
            return []

        base_domain_root = self.get_base_domain_name(final_url)
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
        except Exception:
            return []
            
        extracted_raw_links = set()

        # 1. Standard Tags
        tags_attributes = {
            'a': 'href', 'link': 'href', 'area': 'href',
            'script': 'src', 'img': 'src', 'iframe': 'src',
            'embed': 'src', 'source': 'src', 'track': 'src',
            'form': 'action', 'object': 'data', 'base': 'href'
        }

        for tag_name, attr_name in tags_attributes.items():
            for tag in soup.find_all(tag_name):
                val = tag.get(attr_name)
                if val:
                    extracted_raw_links.add(val.strip())

        # 2. Regex Extraction
        regex_links = re.findall(r'(?:href|src|url|action)\s*=\s*["\']([^"\']+)["\']', content)
        regex_abs = re.findall(r'(https?://[a-zA-Z0-9.-]+(?:/[^\s"\'<>]*)?)', content)
        
        extracted_raw_links.update(regex_links)
        extracted_raw_links.update(regex_abs)

        # 3. Form Input Extraction
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

        # 3.1 Catch-all inputs (Orphans/No Form)
        orphan_params = {}
        for inp in soup.find_all(['input', 'textarea', 'select', 'button']):
            name = inp.get('name')
            if name:
                orphan_params[name] = 'test'
        
        if orphan_params:
            try:
                parsed_final = urlparse(final_url)
                current_q = parse_qs(parsed_final.query)
                current_q.update(orphan_params)
                
                new_query = urlencode(current_q, doseq=True)
                constructed_url = urlunparse((
                    parsed_final.scheme, parsed_final.netloc, parsed_final.path,
                    parsed_final.params, new_query, parsed_final.fragment
                ))
                extracted_raw_links.add(constructed_url)
            except:
                pass

        # --- PHASE 2: PROCESSING & FILTERING ---
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
            
            # --- MODE 1: WAF BYPASS ---
            if self.args.bypass_waf:
                self.log(f"WAF Bypass Mode: Testing param '{param_name}' on: {url}", type="info")
                
                for char in self.chars_to_test:
                    payload_body = f"{delimiter}{char}{delimiter}"
                    full_payload = f"{CANARY}{payload_body}"
                    
                    params_copy = query_params.copy()
                    params_copy[param_name] = [full_payload]
                    new_query = urlencode(params_copy, doseq=True)
                    target_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

                    status, _, content = await self.make_request(session, target_url)
                    
                    if content:
                        if status == 403:
                            self.log(f"WAF 403 Forbidden detected for char '{char}'", type="waf")
                        else:
                            start_marker = f"{CANARY}{delimiter}"
                            end_marker = delimiter
                            start_idx = content.find(start_marker)
                            if start_idx != -1:
                                payload_start = start_idx + len(start_marker)
                                search_window = content[payload_start : payload_start + 50]
                                end_idx = search_window.find(end_marker)
                                if end_idx != -1:
                                    reflected_data = search_window[:end_idx]
                                    
                                    # Reuse validation logic
                                    if self.validate_reflection(char, reflected_data, param_name):
                                         self.report_vuln(target_url, param_name, f"Reflected: {char}")

            # --- MODE 2: FAST BATCH ---
            else:
                payload_body = f"{delimiter}{self.chars_to_test}{delimiter}"
                full_payload = f"{CANARY}{payload_body}"
                
                params_copy = query_params.copy()
                params_copy[param_name] = [full_payload]
                
                new_query = urlencode(params_copy, doseq=True)
                target_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                self.log(f"Testing param '{param_name}'", type="info")
                self.log(f"Payload URL: {target_url}", type="debug")
                
                status, _, content = await self.make_request(session, target_url)
                
                if content and CANARY in content:
                    reflected_chars = []
                    start_marker = f"{CANARY}{delimiter}"
                    
                    start_indices = [m.start() for m in re.finditer(re.escape(start_marker), content)]
                    
                    if not start_indices:
                         self.log(f"Canary '{CANARY}' found, but full start marker '{start_marker}' missing.", type="debug")

                    for start_idx in start_indices:
                        payload_start = start_idx + len(start_marker)
                        window_len = len(self.chars_to_test) * 10 + 100
                        search_window = content[payload_start : payload_start + window_len]
                        
                        end_idx = search_window.find(delimiter)
                        if end_idx != -1:
                            reflected_segment = search_window[:end_idx]
                            self.log(f"Reflected Segment found: {reflected_segment}", type="debug")

                            if not reflected_segment or CANARY in reflected_segment:
                                continue

                            for char in self.chars_to_test:
                                if char in reflected_segment:
                                    if self.validate_reflection(char, reflected_segment, param_name):
                                        if char not in reflected_chars:
                                            reflected_chars.append(char)
                        else:
                            self.log(f"End delimiter '{delimiter}' not found after start marker.", type="debug")
                        
                    if reflected_chars:
                        reflected_str = "".join(reflected_chars)
                        if self.args.force:
                            if set(reflected_chars) == set(self.chars_to_test):
                                self.report_vuln(target_url, param_name, f"Reflected chars (FORCE): {reflected_str}")
                            else:
                                self.log(f"Partial reflection ignored by --force ({len(reflected_chars)}/{len(self.chars_to_test)})", type="info")
                        else:
                            self.report_vuln(target_url, param_name, f"Reflected chars: {reflected_str}")
                    else:
                        self.log(f"Canary reflected but chars filtered/encoded on {param_name}", type="info")
                else:
                    self.log(f"Canary '{CANARY}' NOT found in response.", type="debug")

    def validate_reflection(self, char, reflected_text, param_name):
        """
        Validates if a character is truly reflected and not escaped/encoded.
        """
        is_valid = False
        
        # Iterate over all occurrences of the character in the reflection
        for m in re.finditer(re.escape(char), reflected_text):
            idx = m.start()
            self.log(f"Checking char '{char}' at index {idx} in segment...", type="debug")
            
            # 1. Backslash Lookbehind (Odd/Even Logic)
            # Checks if the character is preceded by an odd number of backslashes
            bs_count = 0
            check_pos = idx - 1
            while check_pos >= 0 and reflected_text[check_pos] == '\\':
                bs_count += 1
                check_pos -= 1
            
            self.log(f" -> Preceding backslashes count: {bs_count}", type="debug")

            if bs_count % 2 != 0:
                self.log(f" -> Char '{char}' is escaped by preceding backslash(es). Ignored.", type="debug")
                continue
                
            # 2. Backslash Escape Check (Corrected Logic)
            # If we found a '\' (and it passed the lookbehind check above),
            # we must ensure it is NOT acting as an escape character for the NEXT character.
            # Example: In \", the \ is escaping the ". It is NOT a valid injected backslash.
            if char == '\\':
                if idx + 1 < len(reflected_text):
                    next_char = reflected_text[idx + 1]
                    # If the backslash is followed by a quote or another backslash, 
                    # it is highly likely an escape artifact provided by the server.
                    if next_char in ['"', "'", '\\']:
                        self.log(f" -> Char '\\' is escaping the following '{next_char}'. Ignored.", type="debug")
                        continue

            # 3. HTML Entity Start check (e.g. &quot;)
            if char == '&':
                sub = reflected_text[idx:]
                if re.match(r'&([a-zA-Z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});', sub): 
                    self.log(f" -> Char '&' is start of HTML entity. Ignored.", type="debug")
                    continue 
            
            # 4. HTML Entity End check
            if char == ';':
                pre = reflected_text[:idx+1]
                if re.search(r'&([a-zA-Z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});$', pre): 
                    self.log(f" -> Char ';' is end of HTML entity. Ignored.", type="debug")
                    continue

            # 5. URL Encoding check
            if char == '%':
                sub = reflected_text[idx:]
                if re.match(r'%[0-9a-fA-F]{2}', sub): 
                    self.log(f" -> Char '%' is start of URL encoding. Ignored.", type="debug")
                    continue

            # If passed all checks
            self.log(f" -> Char '{char}' appears VALID (Not escaped/encoded).", type="debug")
            is_valid = True
            break # Found at least one valid occurrence
        
        return is_valid

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
                    return

            if crawl_targets:
                self.log(f"Starting Deep Crawl on {len(crawl_targets)} targets (Depth: 2)...", type="info")
                
                crawl_tasks = [self.crawl_and_extract(session, url, depth=2) for url in crawl_targets]
                crawl_results = []
                total_crawl = len(crawl_tasks)
                completed_crawl = 0

                for future in asyncio.as_completed(crawl_tasks):
                    res = await future
                    crawl_results.append(res)
                    completed_crawl += 1
                    
                    show_progress = (not self.args.silent) or (self.args.silent and self.args.verbose)
                    
                    if show_progress and total_crawl > 0:
                        percentage = (completed_crawl / total_crawl) * 100
                        sys.stdout.write(f"\r[{Fore.CYAN}CRAWL PROGRESS{Style.RESET_ALL}] {percentage:.1f}% Completed ({completed_crawl}/{total_crawl})\033[K")
                        sys.stdout.flush()

                if (not self.args.silent) or (self.args.silent and self.args.verbose):
                     sys.stdout.write("\n")
                
                for links in crawl_results:
                    urls_to_scan.extend(links)

            unique_urls_to_scan = list(set(urls_to_scan))
            self.log(f"Starting scan on {len(unique_urls_to_scan)} URLs...", type="good")
            
            if self.args.bypass_waf:
                self.log("Running in WAF Bypass mode", type="good")

            scan_tasks = []
            for url in unique_urls_to_scan:
                scan_tasks.append(self.check_xss(session, url))
            
            if scan_tasks:
                total = len(scan_tasks)
                completed = 0
                for future in asyncio.as_completed(scan_tasks):
                    await future
                    completed += 1
                    
                    show_progress = (not self.args.silent) or (self.args.silent and self.args.verbose)
                    
                    if show_progress and total > 0:
                        percentage = (completed / total) * 100
                        sys.stdout.write(f"\r[{Fore.CYAN}SCAN PROGRESS{Style.RESET_ALL}] {percentage:.1f}% Completed\033[K")
                        sys.stdout.flush()

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
    parser.add_argument('--debug', action='store_true', help='Debug mode (Show payloads, raw logic, and reasons for false positives)')
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
                 print(f"[{Fore.YELLOW}DEBUG{Style.RESET_ALL}] Debug Mode Enabled. Expect verbose output.")

        scanner = AsyncXSSScanner(args)
        asyncio.run(scanner.run())

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Shutting down please wait...{Style.RESET_ALL}")
        sys.exit(0)
