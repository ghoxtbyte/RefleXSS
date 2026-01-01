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
import os
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# Suppress XML parsing warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
# Suppress MarkupResemblesLocatorWarning 
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

# Configuration
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
CANARY = "hackedxss"

# Default dangerous characters 
DEFAULT_PAYLOAD_CHARS = "\"><';)(&|{}[]`$|:\\"

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

class AsyncNullContext:
    """Helper context manager that does nothing (used when semaphores aren't needed)."""
    async def __aenter__(self):
        return None
    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

class AsyncXSSScanner:
    def __init__(self, args):
        self.args = args
        self.proxies = self.load_proxies()
        self.sem = None 
        # Initialize default headers
        self.headers = {'User-Agent': USER_AGENT}
        
        # Parse Custom Headers from CLI argument if present
        if self.args.custom_headers:
            self.parse_custom_headers(self.args.custom_headers)

        if self.args.custom_chars:
            self.chars_to_test = self.args.custom_chars
        else:
            self.chars_to_test = DEFAULT_PAYLOAD_CHARS
            
    def parse_custom_headers(self, header_str):
        """Parses custom headers string (Key:Value;;Key2:Value2) and updates self.headers."""
        try:
            # Support multiple headers separated by ;; or just one
            headers_list = header_str.split(';;')
            for h in headers_list:
                if ':' in h:
                    key, value = h.split(':', 1)
                    self.headers[key.strip()] = value.strip()
                    if self.args.debug:
                        self.print_msg(f"Custom Header Set: {key.strip()} = {value.strip()}", type="debug")
        except Exception as e:
            self.print_msg(f"Error parsing custom headers: {e}", type="error")

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

    def get_post_filename(self, filename):
        """Generates the filename for POST results."""
        if not filename:
            return None
        base, ext = os.path.splitext(filename)
        return f"{base}_reflexss_post{ext}"

    def parse_raw_request(self, file_path):
        """
        Parses a raw HTTP request from a file.
        Returns: (method, url, headers_dict, body)
        """
        try:
            self.log(f"Reading raw request file: {file_path}", type="debug")
            with open(file_path, 'r') as f:
                content = f.read()
            
            lines = content.splitlines()
            if not lines:
                return None, None, None, None

            # 1. Request Line (GET /path HTTP/1.1)
            req_line = lines[0].split()
            if len(req_line) < 2:
                return None, None, None, None
            
            method = req_line[0].upper()
            path = req_line[1]
            self.log(f"Raw Request Line Parsed: {method} {path}", type="debug")
            
            # 2. Headers
            headers = {}
            body = ""
            i = 1
            while i < len(lines):
                line = lines[i]
                if line == "" or line == "\r":
                    # End of headers, start of body
                    body = "\n".join(lines[i+1:])
                    break
                
                if ':' in line:
                    key, val = line.split(':', 1)
                    headers[key.strip()] = val.strip()
                i += 1
            
            self.log(f"Raw Headers Found: {len(headers)}", type="debug")

            # 3. Construct URL
            # Prefer Host header, fallback to args or localhost
            host = headers.get('Host', headers.get('host'))
            if not host:
                self.log("Host header missing in raw request. Assuming 127.0.0.1", type="error")
                host = "127.0.0.1"
            
            # --- SCHEME HANDLING ---
            # Default to http. The probe will decide if we should upgrade.
            # We do NOT force https based on HTTP/2 anymore to avoid connection errors if SSL fails.
            scheme = "http" 
            if ":443" in host:
                scheme = "https"

            full_url = f"{scheme}://{host}{path}"
            
            # Normalize URL
            full_url = self.normalize_url(full_url)
            self.log(f"Reconstructed Base URL from Raw: {full_url}", type="debug")
            
            return method, full_url, headers, body

        except Exception as e:
            self.print_msg(f"Error parsing raw request file: {e}", type="error")
            return None, None, None, None

    async def make_request(self, session, url, method="GET", data=None, check_only=False):
        """
        Handles requests with MANUAL REDIRECT logic to preserve headers (Authorization, etc.)
        """
        # Select appropriate context manager
        if check_only:
            ctx = AsyncNullContext()
        else:
            ctx = self.sem

        async with ctx: 
            try:
                proxy = self.get_proxy()
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
                # Attempt to set permissive ciphers to avoid handshake errors
                try:
                    ssl_ctx.set_ciphers('DEFAULT')
                except:
                    pass

                # Prepare kwargs
                # IMPORTANT: allow_redirects=False so we can handle them manually
                req_kwargs = {
                    'proxy': proxy,
                    'timeout': aiohttp.ClientTimeout(total=self.args.timeout),
                    'ssl': ssl_ctx,
                    'allow_redirects': False 
                }

                # Use self.headers which now includes custom headers
                req_headers = self.headers.copy()

                if method == "POST":
                    if 'Content-Type' not in req_headers and 'content-type' not in req_headers:
                        req_headers['Content-Type'] = 'application/x-www-form-urlencoded'

                # Manual Redirect Loop
                current_url = url
                redirect_count = 0
                max_redirects = 5

                while redirect_count < max_redirects:
                    if self.args.debug and not check_only:
                        self.log(f"[{method}] {current_url} (Redirects: {redirect_count})", type="debug")

                    if method == "POST" and redirect_count == 0:
                        # Only send data on the first POST request usually, 
                        # but if 307/308 preserve method, we might need to re-send.
                        # For now, simplistic approach:
                        response = await session.post(current_url, data=data, headers=req_headers, **req_kwargs)
                    elif method == "HEAD":
                        response = await session.head(current_url, headers=req_headers, **req_kwargs)
                    else:
                        response = await session.get(current_url, headers=req_headers, **req_kwargs)

                    async with response:
                        if response.status in [301, 302, 303, 307, 308]:
                            redirect_location = response.headers.get('Location')
                            if not redirect_location:
                                return response.status, str(response.url), await response.text(errors='ignore')
                            
                            # Calculate new URL
                            current_url = urljoin(current_url, redirect_location)
                            redirect_count += 1
                            
                            # 303 always changes to GET
                            if response.status == 303:
                                method = "GET"
                                data = None
                            
                            # If we are just checking connectivity (HEAD/Probe), we can stop at the first redirect usually,
                            # BUT to find the real final URL, we should follow.
                            continue
                        else:
                            # Not a redirect, return result
                            text = await response.text(errors='ignore')
                            if self.args.debug and not check_only:
                                 self.log(f"Response: {response.status} [{current_url}]", type="debug")
                            return response.status, str(current_url), text
                
                # If Max redirects reached
                return 310, str(current_url), ""

            except Exception as e:
                # Show error if verbose OR debug is enabled
                if (not self.args.silent and self.args.verbose) or self.args.debug:
                    # Print the specific error class to help debugging
                    err_msg = f"{e.__class__.__name__}: {str(e)}"
                    if not check_only:
                        self.log(f"Connection error on {url} ({method}): {err_msg}", type="error")
                return None, None, None

    async def detect_protocols(self, session, raw_target):
        """
        Smartly detects if the target supports HTTP, HTTPS, or BOTH.
        """
        valid_urls = []
        target = raw_target.strip()
        if not target:
            return []

        if "://" in target:
            parsed = urlparse(target)
            host_part = parsed.netloc
            path_part = parsed.path
            query_part = parsed.query
        else:
            if "/" in target:
                parts = target.split("/", 1)
                host_part = parts[0]
                path_part = "/" + parts[1]
                query_part = ""
            else:
                host_part = target
                path_part = ""
                query_part = ""

        # Construct candidates
        candidates = [
            f"http://{host_part}{path_part}",
            f"https://{host_part}{path_part}"
        ]
        
        if query_part:
            candidates = [f"{c}?{query_part}" for c in candidates]

        if self.args.debug:
            self.log(f"Probing protocols for: {host_part}", type="debug")

        for url in candidates:
            # Try HEAD first (fast)
            status, real_url, _ = await self.make_request(session, url, method="HEAD", check_only=True)
            
            if status is not None:
                if self.args.debug:
                    self.log(f"Probe Successful: {url} -> {real_url} (Status: {status})", type="debug")
                valid_urls.append(real_url)
            else:
                # If HEAD failed, try GET
                status, real_url, _ = await self.make_request(session, url, method="GET", check_only=True)
                if status is not None:
                     if self.args.debug:
                        self.log(f"Probe Successful (GET fallback): {url} -> {real_url}", type="debug")
                     valid_urls.append(real_url)
                else:
                     if self.args.debug:
                        self.log(f"Probe Failed: {url}", type="debug")

        return list(set(valid_urls))

    def normalize_url(self, url):
        # This is now a basic formatter. 
        # The intelligent protocol detection happens in detect_protocols
        if not url.startswith('http://') and not url.startswith('https://'):
            return f'http://{url}' # Default to http for parsing, will be upgraded by probe
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
        
        if self.args.debug:
            self.log(f"Crawl Response: {status} | URL: {final_url} | Content-Length: {len(content) if content else 0}", type="debug")

        if not content:
            if self.args.debug:
                self.log(f"Empty content for {url}", type="debug")
            return []

        base_domain_root = self.get_base_domain_name(final_url)
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
        except Exception as e:
            if self.args.debug:
                self.log(f"Soup parsing error: {e}", type="debug")
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
        
        if self.args.debug:
            self.log(f"Total raw links extracted: {len(extracted_raw_links)}", type="debug")

        for raw_link in extracted_raw_links:
            if not raw_link or raw_link.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                continue

            try:
                full_url = urljoin(final_url, raw_link)
                parsed = urlparse(full_url)
                
                link_domain_root = self.get_base_domain_name(full_url)
                if link_domain_root != base_domain_root:
                    # if self.args.debug: self.log(f"Ignored external domain: {full_url}", type="debug")
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

        # Save Crawled GET URLs (Only if not in post-only mode)
        if self.args.output_crawl and scan_targets and not self.args.post_only:
            try:
                with open(self.args.output_crawl, 'a') as f:
                    for link in scan_targets:
                        f.write(link + '\n')
            except Exception as e:
                pass
        
        # Save Crawled POST URLs (Only if not in get-only mode)
        # Formatted output for POST crawl file
        if self.args.output_crawl and scan_targets and not self.args.get_only:
             post_crawl_file = self.get_post_filename(self.args.output_crawl)
             try:
                with open(post_crawl_file, 'a') as f:
                    for link in scan_targets:
                        try:
                            # Parse the URL to separate Base and Query
                            parsed_link = urlparse(link)
                            base_link = urlunparse((parsed_link.scheme, parsed_link.netloc, parsed_link.path, '', '', ''))
                            body_link = parsed_link.query
                            
                            # Write in POST format
                            f.write(f"{base_link} | POST_BODY: {body_link}\n")
                        except:
                            # Fallback if parsing fails
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

    async def check_xss(self, session, url, method="GET", post_data=None):
        """
        Generic check function handling both GET and POST based on 'method'.
        If method is POST, 'post_data' (string like 'a=1&b=2') is required.
        """
        parsed = urlparse(url)
        
        if method == "POST":
            if not post_data:
                return
            query_params = parse_qs(post_data, keep_blank_values=True)
        else:
            query_params = parse_qs(parsed.query, keep_blank_values=True)
        
        if not query_params:
            return

        # Unique identifier for deduplication (Method + URL + Path)
        path_identifier = f"{method}:{parsed.netloc}{parsed.path}"
        
        for param_name in query_params:
            dedupe_key = f"{path_identifier}:{param_name}"
            
            if dedupe_key in scanned_params:
                continue
            scanned_params.add(dedupe_key)
            
            delimiter = "".join(random.choices(string.ascii_lowercase, k=6))
            
            # --- MODE 1: WAF BYPASS ---
            if self.args.waf_bypass:
                self.log(f"WAF Bypass Mode [{method}]: Testing param '{param_name}' on: {url}", type="info")
                
                for char in self.chars_to_test:
                    payload_body = f"{delimiter}{char}{delimiter}"
                    full_payload = f"{CANARY}{payload_body}"
                    
                    params_copy = query_params.copy()
                    params_copy[param_name] = [full_payload]
                    new_query_or_body = urlencode(params_copy, doseq=True)

                    if method == "POST":
                        target_url = url
                        req_data = new_query_or_body
                    else:
                        target_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query_or_body, parsed.fragment))
                        req_data = None

                    status, _, content = await self.make_request(session, target_url, method=method, data=req_data)
                    
                    if content:
                        if status == 403:
                            self.log(f"WAF 403 Forbidden detected for char '{char}' ({method})", type="waf")
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
                                         self.report_vuln(target_url, param_name, f"Reflected [{method}]: {char}", method=method)

            # --- MODE 2: FAST BATCH ---
            else:
                payload_body = f"{delimiter}{self.chars_to_test}{delimiter}"
                full_payload = f"{CANARY}{payload_body}"
                
                params_copy = query_params.copy()
                params_copy[param_name] = [full_payload]
                
                new_query_or_body = urlencode(params_copy, doseq=True)
                
                if method == "POST":
                    target_url = url
                    req_data = new_query_or_body
                else:
                    target_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query_or_body, parsed.fragment
                    ))
                    req_data = None
                
                self.log(f"Testing param '{param_name}' [{method}]", type="info")
                self.log(f"Payload ({method}): {target_url} DATA: {req_data if req_data else 'Query'}", type="debug")
                
                status, _, content = await self.make_request(session, target_url, method=method, data=req_data)
                
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
                                self.report_vuln(target_url, param_name, f"Reflected chars (FORCE) [{method}]: {reflected_str}", method=method)
                            else:
                                self.log(f"Partial reflection ignored by --force ({len(reflected_chars)}/{len(self.chars_to_test)})", type="info")
                        else:
                            self.report_vuln(target_url, param_name, f"Reflected chars [{method}]: {reflected_str}", method=method)
                    else:
                        self.log(f"Canary reflected but chars filtered/encoded on {param_name} [{method}]", type="info")
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
            # If char is '\' and reflected as '\\', bs_count will be 1 (for the first slash) and 0 (for the second).
            bs_count = 0
            check_pos = idx - 1
            while check_pos >= 0 and reflected_text[check_pos] == '\\':
                bs_count += 1
                check_pos -= 1
            
            self.log(f" -> Preceding backslashes count: {bs_count}", type="debug")

            if bs_count % 2 != 0:
                self.log(f" -> Char '{char}' is escaped by preceding backslash(es). Ignored.", type="debug")
                continue
                
            # 2. Backslash Escape Check (Logic for injected backslash acting as escaper)
            # If we injected '\' and it appears as '\' (raw), we must ensure it's not simply the server
            # adding a slash to escape a following quote.
            if char == '\\':
                if idx + 1 < len(reflected_text):
                    next_char = reflected_text[idx + 1]
                    # If the backslash is followed by a quote or another backslash, 
                    # it is likely an escape artifact provided by the server, NOT our payload.
                    # Exception: If we injected '\' and next char is NOT one of these, it's a valid reflection.
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

    def report_vuln(self, url, param, note, method="GET"):
        if self.args.silent:
            # Included Param and Method in silent output
            msg = f"{url} | Param: {param} | {note} | Method: {method}"
        else:
            msg = f"Potential XSS Found on param '{param}': {url} ({note}) [{method}]"
            
        self.log(msg, type="vuln")
        vulnerable_urls.append(url)
        
        # Determine files based on method
        output_file = self.args.output
        output_context_file = self.args.output_context
        
        if method == "POST":
            output_file = self.get_post_filename(output_file)
            output_context_file = self.get_post_filename(output_context_file)

        if output_file:
            with open(output_file, 'a') as f:
                # Explicitly writing the parameter name instead of [POST_DATA: See Context]
                if method == "POST":
                     f.write(f"{url} | PostParam: {param}\n")
                else:
                     f.write(f"{url} | Param: {param}\n")
        
        if output_context_file:
            with open(output_context_file, 'a') as f:
                # Included Param in context output
                f.write(f"{url} | Param: {param} | {note} | Method: {method}\n")

    async def run(self):
        self.sem = asyncio.Semaphore(self.args.concurrency)
        urls_to_scan = []
        raw_scan_tasks = [] # To hold specific tasks from -r (Raw Request)
        
        connector = aiohttp.TCPConnector(
            limit=self.args.concurrency + 10, 
            ttl_dns_cache=300,
            ssl=False
        )
        
        async with aiohttp.ClientSession(connector=connector, headers=self.headers) as session:
            self.session = session 

            # --- INPUT PROCESSING WITH SMART PROTOCOL DETECTION ---
            raw_scan_inputs = []
            raw_crawl_inputs = []

            # 1. Standard URL
            if self.args.url:
                raw_scan_inputs.append(self.args.url)

            # 2. List of URLs
            if self.args.list:
                try:
                    with open(self.args.list, 'r') as f:
                        raw_scan_inputs.extend([line.strip() for line in f if line.strip()])
                except FileNotFoundError:
                    self.print_msg("URL list file not found!", type="error")
                    return
            
            # 3. Standard Crawl URL
            if self.args.url_crawl:
                raw_crawl_inputs.append(self.args.url_crawl)
            
            # 4. List Crawl
            if self.args.list_crawl:
                try:
                     with open(self.args.list_crawl, 'r') as f:
                        raw_crawl_inputs.extend([line.strip() for line in f if line.strip()])
                except FileNotFoundError:
                    self.print_msg("Crawl list file not found!", type="error")
                    return

            # --- PROCESS RAW TARGETS (Probe HTTP/HTTPS) ---
            # We must detect if they are HTTP, HTTPS, or BOTH
            
            crawl_targets = []
            
            if raw_scan_inputs:
                self.log(f"Probing protocols for {len(raw_scan_inputs)} scan targets...", type="info")
                processed_scan_urls = []
                for raw_in in raw_scan_inputs:
                    valid_urls = await self.detect_protocols(session, raw_in)
                    processed_scan_urls.extend(valid_urls)
                urls_to_scan.extend(processed_scan_urls)

            if raw_crawl_inputs:
                self.log(f"Probing protocols for {len(raw_crawl_inputs)} crawl targets...", type="info")
                processed_crawl_urls = []
                for raw_in in raw_crawl_inputs:
                    valid_urls = await self.detect_protocols(session, raw_in)
                    processed_crawl_urls.extend(valid_urls)
                crawl_targets.extend(processed_crawl_urls)

            # 5. Raw Request Crawl (-rC)
            if self.args.raw_crawl:
                self.log(f"Parsing raw HTTP file for crawling: {self.args.raw_crawl}", type="info")
                r_method, r_url, r_headers, r_body = self.parse_raw_request(self.args.raw_crawl)
                
                if r_url:
                    # Filter headers
                    if r_headers:
                        skip_headers = ['content-length', 'content-type', 'accept-encoding', 'host', 'connection', 'upgrade-insecure-requests']
                        cleaned_headers = {k: v for k, v in r_headers.items() if k.lower() not in skip_headers}
                        self.headers.update(cleaned_headers)
                        if self.args.custom_headers:
                             self.parse_custom_headers(self.args.custom_headers)
                    
                    # PROBE PROTOCOLS for Raw Request
                    detected = await self.detect_protocols(session, r_url)
                    if detected:
                        self.log(f"Raw Request Crawl Targets: {detected}", type="good")
                        crawl_targets.extend(detected)
                    else:
                        self.log("Could not establish connection to Raw Request target (checked both HTTP/HTTPS).", type="error")

                else:
                    self.print_msg("Failed to parse raw request for crawling.", type="error")
                    return

            # --- EXECUTE CRAWLING ---
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

            # --- EXECUTE SCANNING ---
            unique_urls_to_scan = list(set(urls_to_scan))
            
            # 6. Raw Request Scan (-r)
            if self.args.raw_request:
                self.log(f"Parsing raw HTTP file for scanning: {self.args.raw_request}", type="info")
                r_method, r_url, r_headers, r_body = self.parse_raw_request(self.args.raw_request)
                
                if r_url:
                    # PROBE PROTOCOLS for Raw Request Scan
                    # Since Raw Request might rely on specific host headers, we use the detected URL 
                    # but we keep the body/headers logic.
                    
                    valid_raw_targets = await self.detect_protocols(session, r_url)
                    
                    if valid_raw_targets:
                        # Update headers
                        if r_headers:
                            skip_headers = ['content-length', 'content-type', 'host', 'connection']
                            cleaned_headers = {k: v for k, v in r_headers.items() if k.lower() not in skip_headers}
                            self.headers.update(cleaned_headers)
                            if self.args.custom_headers:
                                self.parse_custom_headers(self.args.custom_headers)
                        
                        for valid_r_url in valid_raw_targets:
                            self.log(f"Raw Request Scanning Target: {valid_r_url}", type="good")
                            
                            # Logic for Raw Request Scanning (Duplicated for each valid protocol)
                            if r_method == "POST":
                                if not self.args.get_only:
                                     raw_scan_tasks.append(self.check_xss(session, valid_r_url, method="POST", post_data=r_body))
                                
                                if (self.args.full_check or self.args.get_only) and r_body:
                                     try:
                                         parsed_r = urlparse(valid_r_url)
                                         new_query = r_body if not parsed_r.query else f"{parsed_r.query}&{r_body}"
                                         new_url = urlunparse((parsed_r.scheme, parsed_r.netloc, parsed_r.path, parsed_r.params, new_query, parsed_r.fragment))
                                         raw_scan_tasks.append(self.check_xss(session, new_url, method="GET"))
                                     except:
                                         pass

                            elif r_method == "GET":
                                if not self.args.post_only:
                                    raw_scan_tasks.append(self.check_xss(session, valid_r_url, method="GET"))
                                
                                parsed_r = urlparse(valid_r_url)
                                if (self.args.full_check or self.args.post_only) and parsed_r.query:
                                    base_r_url = urlunparse((parsed_r.scheme, parsed_r.netloc, parsed_r.path, parsed_r.params, '', parsed_r.fragment))
                                    raw_scan_tasks.append(self.check_xss(session, base_r_url, method="POST", post_data=parsed_r.query))
                    else:
                        self.log("Could not establish connection to Raw Request target (checked both HTTP/HTTPS).", type="error")

                else:
                    self.print_msg("Failed to parse raw request for scanning.", type="error")

            
            self.log(f"Starting scan on {len(unique_urls_to_scan) + len(raw_scan_tasks)} targets...", type="good")
            
            if self.args.waf_bypass:
                self.log("Running in WAF Bypass mode", type="good")

            # --- PREPARE TASKS ---
            scan_tasks = []
            
            # Add Raw Tasks first
            scan_tasks.extend(raw_scan_tasks)

            for url in unique_urls_to_scan:
                parsed = urlparse(url)

                # 1. Standard GET check (Existing logic)
                # Skip if we are in POST-ONLY mode
                if not self.args.post_only and parsed.query:
                    scan_tasks.append(self.check_xss(session, url, method="GET"))
                    
                # 2. Check if we need to scan this as POST
                should_scan_post = False
                
                if self.args.post_only:
                    should_scan_post = True
                elif self.args.full_check and not self.args.get_only:
                    should_scan_post = True
                elif (url in crawled_urls) and not self.args.get_only:
                     # This covers the requirement: "In crawling section, all inputs checked as GET should also be checked as POST!"
                     should_scan_post = True
                
                if should_scan_post and parsed.query:
                     # Strip query from URL for the POST request
                     base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, '', parsed.fragment))
                     # Use the query string as the POST body
                     scan_tasks.append(self.check_xss(session, base_url, method="POST", post_data=parsed.query))

                # 3. Explicit POST Mode (--post with --data)
                if self.args.post and self.args.data and url == self.normalize_url(self.args.url) and not self.args.get_only:
                     scan_tasks.append(self.check_xss(session, url, method="POST", post_data=self.args.data))

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
    
    group.add_argument('-r', '--raw-request', help='File containing a raw HTTP request to scan.')
    group.add_argument('-rC', '--raw-crawl', help='File containing a raw HTTP request to crawl and scan.')

    parser.add_argument('-o', '--output', help='File to save vulnerable URLs')
    parser.add_argument('-oc', '--output-context', help='File to save vulnerable URLs WITH reflected characters')
    parser.add_argument('-oC', '--output-crawl', help='File to save crawled URLs (Query Strings)')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent mode (only vulns)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode (Show progress even in silent mode)')
    parser.add_argument('--debug', action='store_true', help='Debug mode (Show payloads, raw logic, and reasons for false positives)')
    parser.add_argument('--proxy', help='Single proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--proxy-list', help='File containing list of proxies')
    parser.add_argument('--concurrency', type=int, default=25, help='Max concurrent requests (default 25)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default 5)')
    parser.add_argument('-c', '--custom-chars', help='Custom payload characters (overrides default). E.g: -c "<>\"\'"')
    parser.add_argument('--waf-bypass', action='store_true', help='Test characters one by one to detect WAF blocks (403)')
    parser.add_argument('--force', action='store_true', help='Force mode: Only report vulnerable if ALL injected characters are reflected.')
    
    parser.add_argument('--custom-headers', help='Custom headers (e.g., "Cookie: auth=1;;Referer: google.com")')

    parser.add_argument('--post', action='store_true', help='Enable POST request scanning mode.')
    parser.add_argument('--data', help='POST data string (e.g., "param1=value&param2=test"). Required if --post is used.')
    parser.add_argument('--full-check', action='store_true', help='Check GET parameters as POST parameters as well.')

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--get-only', action='store_true', help='Only scan and crawl GET parameters.')
    mode_group.add_argument('--post-only', action='store_true', help='Only scan and crawl POST parameters.')

    args = parser.parse_args()

    # Validation for POST arguments
    if args.post and not args.data:
        parser.error("--post requires --data to be specified.")

    return args

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
