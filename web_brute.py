#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import requests
import colorama
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from tqdm import tqdm
import json
from typing import Dict, Optional, Iterator
import aiohttp
import itertools
import string
import re
import asyncio
import signal
from datetime import datetime

colorama.init()  # For Windows ANSI color support

GREEN = "\033[92m"
RESET = "\033[0m"

class WordlistGenerator:
    def __init__(self):
        self.charsets = {
            'a': string.ascii_lowercase,
            'A': string.ascii_uppercase,
            'd': string.digits,
            's': string.punctuation
        }
    
    def parse_pattern(self, pattern: str) -> Iterator[str]:
        """Parse patterns like: [a]{3} for 3 lowercase letters"""
        if not pattern or len(pattern) < 4:  # Minimum pattern: [x]{1}
            raise ValueError("Invalid pattern format")
            
        match = re.match(r'\[([aAds]+)\]\{(\d+)\}', pattern)
        if not match:
            raise ValueError("Pattern must be in format: [chars]{length}")
            
        chars, length = match.groups()
        charset = ''.join(self.charsets[c] for c in chars)
        return (''.join(p) for p in itertools.product(charset, repeat=int(length)))

def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="Optimized multithreaded brute-forcer for website routes/files, streaming large wordlists."
    )
    
    # Create mutually exclusive group for wordlist source
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument("-w", "--wordlist", help="Path to wordlist file")
    source_group.add_argument("-p", "--pattern", help="Pattern for wordlist generation (e.g. [a]{3})")
    
    parser.add_argument(
        "-u", "--url", required=True,
        help="Base URL, e.g., http://alert.htb/index.php?page="
    )
    parser.add_argument(
        "--prefix", default="",
        help="String to prepend to each wordlist entry."
    )
    parser.add_argument(
        "--suffix", default="",
        help="String to append to each wordlist entry."
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=5,
        help="Number of threads (default: 5)."
    )
    parser.add_argument("-m", "--method", default="GET", 
                        choices=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"],
                        help="HTTP method to use")
    parser.add_argument("-d", "--data", help="Request body data (JSON format)")
    parser.add_argument("-H", "--headers", help="Path to headers file (JSON format)")
    parser.add_argument("--brute-headers", action="store_true", 
                        help="Enable header bruteforcing")
    parser.add_argument("--data-pattern", help="Pattern for data bruteforcing (e.g. {'user':'[a]{3}'})")
    parser.add_argument("--data-wordlist", help="Wordlist file for data bruteforcing")

    # -----------------------------
    # FILTERS: Include / Exclude
    # -----------------------------
    parser.add_argument("--include-status", nargs="*", type=int, default=[],
        help="Only accept these status codes (ignore others).")
    parser.add_argument("--exclude-status", nargs="*", type=int, default=[],
        help="Reject these status codes.")
    parser.add_argument("--include-size", nargs="*", type=int, default=[],
        help="Only accept these content lengths.")
    parser.add_argument("--exclude-size", nargs="*", type=int, default=[],
        help="Reject these content lengths.")
    parser.add_argument("--include-contains", nargs="*", default=[],
        help="Response body must contain *one* of these substrings.")
    parser.add_argument("--exclude-contains", nargs="*", default=[],
        help="Response body is rejected if it contains any of these substrings.")

    parser.add_argument("-v", "--verbose", action="store_true",
        help="Verbose mode (debug logs).")

    return parser.parse_args(args)

def passes_filter(value, include_list, exclude_list):
    """
    Generic check for a single 'value' against 'include_list' and 'exclude_list'.
    - If 'value' is in 'exclude_list', we fail immediately.
    - If 'include_list' is not empty and 'value' is not in 'include_list', we fail.
    - Otherwise, we pass.
    """
    # Exclude check
    if value in exclude_list:
        return False
    # Include check (only if includes are specified)
    if include_list and (value not in include_list):
        return False
    return True

def passes_body_filter(body, include_list, exclude_list):
    """
    Similar logic for substrings in the response body.
    - 'exclude_list': if any substring is found, fail.
    - 'include_list': must find *at least one* substring from the list (if provided).
      (If you prefer 'must contain ALL', adjust logic.)
    """
    # Exclude if body contains any substring in exclude_list
    for sub in exclude_list:
        if sub in body:
            return False

    # If we have an include_list, we pass only if body contains at least one of them
    if include_list:
        # If none of them is in body => fail
        if not any(sub in body for sub in include_list):
            return False

    return True

def check_url(url, filters, verbose=False):
    """
    Send GET request to 'url'. Return (is_valid, status_code, content_length, reason).
      - is_valid: bool
      - reason: short string describing why it was accepted/rejected
    """
    try:
        r = requests.get(url, timeout=5)
        status_code = r.status_code
        content_len = len(r.content)
        body_text   = r.text  # string

        # 1) Check status filter
        if not passes_filter(status_code, filters["inc_status"], filters["exc_status"]):
            return False, status_code, content_len, f"Rejected by status_code={status_code}"

        # 2) Check size filter
        if not passes_filter(content_len, filters["inc_size"], filters["exc_size"]):
            return False, status_code, content_len, f"Rejected by size={content_len}"

        # 3) Check body substring filter
        if not passes_body_filter(body_text, filters["inc_contains"], filters["exc_contains"]):
            return False, status_code, content_len, "Rejected by substring filter"

        # If all checks pass, it's valid
        return True, status_code, content_len, "OK"

    except requests.exceptions.RequestException as e:
        if verbose:
            print(f"[!] Request error for {url}: {e}")
        return False, 0, 0, f"Exception: {e}"

def worker(url, filters, verbose=False):
    """
    Worker for each line. Returns dict with result info.
    """
    is_valid, code, size, reason = check_url(url, filters, verbose)
    return {
        "url": url,
        "is_valid": is_valid,
        "status_code": code,
        "content_length": size,
        "reason": reason
    }

async def make_request(session, url: str, method: str = "GET", 
                      data: Optional[Dict] = None, 
                      headers: Optional[Dict] = None,
                      timeout: int = 10) -> dict:
    try:
        async with session.request(method=method, url=url, 
                                 json=data, headers=headers,
                                 timeout=timeout) as response:
            content = await response.read()
            return {
                "url": url,
                "status": response.status,
                "length": len(content),
                "timestamp": datetime.now().isoformat()
            }
    except asyncio.TimeoutError:
        print(f"[TIMEOUT] {url}")
        return None
    except Exception as e:
        print(f"[ERROR] {url}: {str(e)}")
        return None

def generate_data_payloads(pattern: str, generator: WordlistGenerator) -> Iterator[Dict]:
    """Generate data payloads from pattern or literal values."""
    try:
        template = json.loads(pattern)
        # We’ll try for each key. If it’s a pattern "[a]{1}", generate permutations.
        # Else, yield the literal value once.
        keys = list(template.keys())
        # Build up all possible permutations of pattern/literal
        # but keep it simple by iterating on each key:
        records = [template]  # Start with one “base” record
        new_records = []

        for key in keys:
            val = template[key]
            if isinstance(val, str) and val.startswith('[') and val.endswith(']'):
                # Real pattern, expand
                words = generator.parse_pattern(val)
                for wrd in words:
                    for rec in records:
                        new_rec = dict(rec)
                        new_rec[key] = wrd
                        new_records.append(new_rec)
                records = new_records
                new_records = []
            else:
                # Literal value, keep it as-is
                # i.e., we just leave it in `records` unchanged
                pass

        for r in records:
            yield r
    except json.JSONDecodeError:
        print("[!] Invalid JSON pattern for data")
        return

async def main(args=None):
    if args is None:
        args = parse_args()
    else:
        args = parse_args(args)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    print(f"[*] Starting web brute force against {args.url}")
    print(f"[*] Method: {args.method}")
    print(f"[*] Threads: {args.threads}")
    
    generator = WordlistGenerator()
    
    # Generate URL paths
    if args.pattern:
        paths = list(generator.parse_pattern(args.pattern))
    elif args.wordlist:
        with open(args.wordlist) as f:
            paths = [line.strip() for line in f]
    
    # Generate data payloads
    data_payloads = [None]  # Default no data
    if args.data_pattern:
        data_payloads = list(generate_data_payloads(args.data_pattern, generator))
    elif args.data_wordlist:
        with open(args.data_wordlist) as f:
            data_payloads = [json.loads(line.strip()) for line in f]
    
    if args.verbose:
        print(f"[*] Generated {len(paths)} paths to test")
    
    async with aiohttp.ClientSession() as session:
        tasks = []
        with tqdm(total=len(paths), desc="Progress", disable=not args.verbose) as pbar:
            for path in paths:
                for data in data_payloads:
                    # Update URL construction with prefix/suffix
                    url = f"{args.url}/{args.prefix}{path}{args.suffix}"
                    task = asyncio.create_task(make_request(session, url, 
                                                          method=args.method, data=data))
                    tasks.append(task)
                    if args.verbose:
                        print(f"[+] Testing: {url} with data: {data}")
                    
            results = await asyncio.gather(*tasks)
            for result in results:
                if result:
                    pbar.update(1)
                    if args.verbose:
                        print(f"[+] Found: {result['url']} "
                              f"(Status: {result['status']}, "
                              f"Length: {result['length']})")
    return results  # Add return for test validation

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)

