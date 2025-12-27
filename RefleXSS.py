#!/bin/python3
import argparse
import requests
import sys
import urllib3
import threading
import random
import time
import re
import string
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize Colorama
init(autoreset=True)

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
CANARY = "hackedxss"

# Default dangerous characters
DEFAULT_PAYLOAD_CHARS = "\"><';)(&|\\"

# Global Sets for Deduplication
scanned_params = set() 
crawled_urls = set()
vulnerable_urls = []

class XSSScanner:
    def __init__(self, args):
        self.args = args
        self.proxies = self.load_proxies()
        self.lock = threading.Lock()
        
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
            return {"http": f"http://{proxy_str}", "https": f"http://{proxy_str}"}
        scheme = proxy_str.split("://")[0]
        return {"http": proxy_str, "https": proxy_str}

    def get_proxy(self):
        if not self.proxies:
            return None
        return random.choice(self.proxies)

    
    def print_msg(self, text, type="info"):
        """
        Prints a message cleanly by clearing the current line (removing progress bar artifacts),
        printing the message, and forcing a newline. The progress bar will redraw on the next loop.
        """
        # \r moves to start of line, \033[K clears the line
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
        elif type == "plain":
             sys.stdout.write(f"{clear_line}{text}\n")
             
        sys.stdout.flush()

    def log(self, message, type="info"):
        # Silent mode logic:
        # If silent is ON, we only print VULN.
        if self.args.silent:
            if type == "vuln":
                
                sys.stdout.write(f"\r\033[K{message}\n")
                sys.stdout.flush()
            return

        self.print_msg(message, type)

    def make_request(self, url):
        try:
            proxy = self.get_proxy()
            headers = {'User-Agent': USER_AGENT}
            response = requests.get(
                url, 
                headers=headers, 
                proxies=proxy, 
                timeout=self.args.timeout,
                verify=False,
                allow_redirects=True
            )
            return response
        except requests.exceptions.RequestException as e:
            if not self.args.silent:
                # Cleaner error message
                err_msg = str(e).split(':')[-1].strip() if ':' in str(e) else str(e)
                self.log(f"Connection error on {url}: {err_msg}", type="error")
            return None

    def normalize_url(self, url):
        if not url.startswith('http://') and not url.startswith('https://'):
            return f'https://{url}'
        return url

    # --- NEW HELPER FOR DOMAIN COMPARISON ---
    def get_base_domain_name(self, url):
        netloc = urlparse(url).netloc
        # Remove port if exists
        if ':' in netloc:
            netloc = netloc.split(':')[0]
        # Remove www prefix for looser matching
        if netloc.startswith('www.'):
            return netloc[4:]
        return netloc

    def extract_links(self, url):
        # Deduplication check for the page being crawled
        if url in crawled_urls:
            return []
        
        self.log(f"Crawling: {url}", type="crawl")
        crawled_urls.add(url)
        
        if self.args.output_crawl:
            with open(self.args.output_crawl, 'a') as f:
                f.write(url + '\n')

        response = self.make_request(url)
        if not response:
            return []

        final_url = response.url
        
        base_domain_root = self.get_base_domain_name(final_url)

        soup = BeautifulSoup(response.text, 'html.parser')
        links = set()
        
        for tag in soup.find_all('a', href=True):
            href = tag['href'].strip() 
            
            
            if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue

            # Join relative URLs with the final URL from response
            full_url = urljoin(final_url, href)
            parsed = urlparse(full_url)
            
            
            link_domain_root = self.get_base_domain_name(full_url)
            
            # 1. Check if it belongs to the same domain (Root Domain Comparison)
            if link_domain_root == base_domain_root:
                # 2. Check if it has a Query String (GET params)
                if parsed.query:
                    # 3. Deduplication logic:
                    q_params = parse_qs(parsed.query)
                    sorted_q = urlencode(q_params, doseq=True)
                    
                    # Rebuild URL with sorted params for unique check
                    unique_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, sorted_q, parsed.fragment
                    ))
                    
                    links.add(unique_url)
        
        found_count = len(links)
        if found_count > 0:
            self.log(f"Found {found_count} URLs with parameters on {url}", type="info")
            
        return list(links)

    def check_xss(self, url):
        parsed = urlparse(url)
        # keep_blank_values=True ensures parameters like ?id= are NOT ignored
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not query_params:
            return

        path_identifier = f"{parsed.netloc}{parsed.path}"
        
        for param_name in query_params:
            dedupe_key = f"{path_identifier}:{param_name}"
            
            with self.lock:
                if dedupe_key in scanned_params:
                    continue
                scanned_params.add(dedupe_key)
            
            # Generate a random delimiter (Bumper) to isolate our payload from surrounding HTML
            delimiter = "".join(random.choices(string.ascii_lowercase, k=6))
            
            # --- MODE 1: WAF BYPASS (One by one) ---
            if self.args.bypass_waf:
                self.log(f"WAF Bypass Mode: Testing param '{param_name}' on: {url}", type="info")
                
                for char in self.chars_to_test:
                    # Payload: CANARY + delimiter + char + delimiter
                    payload_body = f"{delimiter}{char}{delimiter}"
                    full_payload = f"{CANARY}{payload_body}"
                    
                    params_copy = query_params.copy()
                    params_copy[param_name] = [full_payload]
                    
                    new_query = urlencode(params_copy, doseq=True)
                    target_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))

                    response = self.make_request(target_url)
                    
                    if response:
                        if response.status_code == 403:
                            self.log(f"WAF 403 Forbidden detected for char '{char}' on {param_name}", type="waf")
                        else:
                            content = response.text
                            start_marker = f"{CANARY}{delimiter}"
                            end_marker = delimiter
                            
                            start_idx = content.find(start_marker)
                            if start_idx != -1:
                                payload_start = start_idx + len(start_marker)
                                search_window = content[payload_start : payload_start + 50]
                                end_idx = search_window.find(end_marker)
                                
                                if end_idx != -1:
                                    reflected_data = search_window[:end_idx]
                                    if char in reflected_data:
                                        self.report_vuln(target_url, param_name, f"Reflected: {char}")

            # --- MODE 2: FAST BATCH (All at once) ---
            else:
                # Payload: CANARY + delimiter + ALL_CHARS + delimiter
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
                
                response = self.make_request(target_url)
                
                if response and CANARY in response.text:
                    reflected_chars = []
                    content = response.text
                    
                    # 1. Find the Start Marker
                    start_marker = f"{CANARY}{delimiter}"
                    start_indices = [m.start() for m in re.finditer(re.escape(start_marker), content)]
                    
                    for start_idx in start_indices:
                        payload_start = start_idx + len(start_marker)
                        
                        # 2. Look for the End Marker
                        window_len = len(self.chars_to_test) * 10 + 50
                        search_window = content[payload_start : payload_start + window_len]
                        
                        end_idx = search_window.find(delimiter)
                        
                        if end_idx != -1:
                            reflected_segment = search_window[:end_idx]
                            
                            # Regex for Entity Checking
                            entity_pattern_start = re.compile(r'&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});', re.IGNORECASE)

                            for char in self.chars_to_test:
                                if char in reflected_segment:
                                    char_idx = reflected_segment.find(char)
                                    
                                    # --- CONTEXT CHECKS ---
                                    if char == '&':
                                        sub = reflected_segment[char_idx:]
                                        if entity_pattern_start.match(sub):
                                            continue 
                                            
                                    if char == ';':
                                        pre = reflected_segment[:char_idx+1]
                                        if re.search(r'&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});$', pre):
                                            continue

                                    if char == '%':
                                        sub = reflected_segment[char_idx:]
                                        if re.match(r'%[0-9a-fA-F]{2}', sub):
                                            continue

                                    if char not in reflected_chars:
                                        reflected_chars.append(char)
                        
                    if reflected_chars:
                        reflected_str = "".join(reflected_chars)
                        
                        # --- Force Mode Logic ---
                        if self.args.force:
                            # Check if ALL chars (custom or default) are present in reflection
                            if set(reflected_chars) == set(self.chars_to_test):
                                self.report_vuln(target_url, param_name, f"Reflected chars (FORCE): {reflected_str}")
                            else:
                                # In force mode, we do NOT report partial reflections
                                self.log(f"Partial reflection ignored by --force on {param_name} ({len(reflected_chars)}/{len(self.chars_to_test)} chars)", type="info")
                        else:
                            # Standard behavior: Report if ANY char is reflected
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

    def run(self):
        urls_to_scan = []

        if self.args.url:
            urls_to_scan.append(self.normalize_url(self.args.url))

        if self.args.list:
            try:
                with open(self.args.list, 'r') as f:
                    urls_to_scan.extend([self.normalize_url(line.strip()) for line in f if line.strip()])
            except FileNotFoundError:
                self.print_msg("URL list file not found!", type="error")
                return

        if self.args.url_crawl:
            start_url = self.normalize_url(self.args.url_crawl)
            links = self.extract_links(start_url)
            urls_to_scan.extend(links)

        if self.args.list_crawl:
            try:
                 with open(self.args.list_crawl, 'r') as f:
                    targets = [self.normalize_url(line.strip()) for line in f if line.strip()]
                    self.log(f"Crawling {len(targets)} targets...", type="info")
                    with ThreadPoolExecutor(max_workers=5) as crawler_pool:
                        future_to_url = {crawler_pool.submit(self.extract_links, url): url for url in targets}
                        for future in as_completed(future_to_url):
                            links = future.result()
                            urls_to_scan.extend(links)
            except FileNotFoundError:
                self.print_msg("Crawl list file not found!", type="error")
                return

        unique_urls_to_scan = list(set(urls_to_scan))
        self.log(f"Starting scan on {len(unique_urls_to_scan)} URLs...", type="good")
        if self.args.bypass_waf:
            self.log("Running in WAF Bypass mode (Slower, High Accuracy)", type="good")

        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            futures = [executor.submit(self.check_xss, url) for url in unique_urls_to_scan]
            
            total = len(futures)
            completed = 0
            for f in as_completed(futures):
                completed += 1
                
                # Progress Logic:
                # Show if (Silent is OFF) OR (Silent is ON AND Verbose is ON)
                show_progress = (not self.args.silent) or (self.args.silent and self.args.verbose)
                
                if show_progress and total > 0:
                    percentage = (completed / total) * 100
                    
                    sys.stdout.write(f"\r[{Fore.CYAN}PROGRESS{Style.RESET_ALL}] {percentage:.1f}% Completed\033[K")
                    sys.stdout.flush()
        
        if (not self.args.silent) or (self.args.silent and self.args.verbose):
            # Move to a new line after progress bar is done
            sys.stdout.write("\n")
            self.log("Scan completed.", type="good")

def parse_arguments():
    
    parser = argparse.ArgumentParser(description='RefleXSS - Advanced Reflected XSS Scanner')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to scan (must have params)')
    group.add_argument('-l', '--list', help='File containing list of URLs to scan')
    group.add_argument('-uC', '--url-crawl', help='Single URL to crawl and scan')
    group.add_argument('-lC', '--list-crawl', help='File containing list of URLs to crawl and scan')

    parser.add_argument('-o', '--output', help='File to save vulnerable URLs')
    parser.add_argument('-oC', '--output-crawl', help='File to save crawled URLs')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent mode (only vulns)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode (Show progress even in silent mode)')
    parser.add_argument('--proxy', help='Single proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxy-list', help='File containing list of proxies')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default 10)')
    
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default 10)')
    
    parser.add_argument('-c', '--custom-chars', help='Custom payload characters (overrides default). E.g: -c "<>\"\'"')
    parser.add_argument('--bypass-waf', action='store_true', help='Test characters one by one to detect WAF blocks (403)')
    
    
    parser.add_argument('--force', action='store_true', help='Force mode: Only report vulnerable if ALL injected characters are reflected.')

    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    if not args.silent:
        
        print(Fore.MAGENTA + r"""
    ____       ______   __   _  _____ _____
   / __ \___  / __/ /__ \ \_/ // ___// ___/
  / /_/ / _ \/ /_/ / _ \ \/ /  \__ \ \__ \ 
 / _, _/  __/ __/ /  __/ / /  ___/ /___/ / 
/_/ |_|\___/_/ /_/\___/_/ \_//____//____/  
                                           
        """ + Style.RESET_ALL)
        print(f"[{Fore.GREEN}+{Style.RESET_ALL}] RefleXSS Engine started...")
        if args.custom_chars:
             print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Using Custom Chars: {args.custom_chars}")
        if args.force:
             print(f"[{Fore.BLUE}INFO{Style.RESET_ALL}] Force Mode Enabled: Requiring strict reflection of ALL characters.")

    scanner = XSSScanner(args)
    scanner.run()
