#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
import requests
import colorama
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from tqdm import tqdm

colorama.init()  # For Windows ANSI color support

GREEN = "\033[92m"
RESET = "\033[0m"

def parse_args():
    parser = argparse.ArgumentParser(
        description="Optimized multithreaded brute-forcer for website routes/files, streaming large wordlists."
    )
    parser.add_argument(
        "-u", "--url", required=True,
        help="Base URL, e.g., http://alert.htb/index.php?page="
    )
    parser.add_argument(
        "-w", "--wordlist", required=True,
        help="Path to the (large) wordlist file."
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

    return parser.parse_args()

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

def main():
    args = parse_args()

    # Build filters dict
    filters = {
        "inc_status": set(args.include_status),
        "exc_status": set(args.exclude_status),
        "inc_size": set(args.include_size),
        "exc_size": set(args.exclude_size),
        "inc_contains": args.include_contains,
        "exc_contains": args.exclude_contains
    }

    if not os.path.isfile(args.wordlist):
        print(f"[!] Wordlist not found: {args.wordlist}")
        sys.exit(1)

    # We'll do a quick pass to count lines so we can show a proper total in tqdm.
    print("[*] Counting lines in wordlist (one-time pass).")
    try:
        total_lines = 0
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fcount:
            for _ in fcount:
                total_lines += 1
    except KeyboardInterrupt:
        print("\n[!] User interrupted during counting. Exiting.")
        sys.exit(1)

    if args.verbose:
        print(f"[+] Found {total_lines} lines in {args.wordlist}.")
        print(f"[+] Using {args.threads} threads.")
        print("[+] Filters:")
        print(f"    - include status: {filters['inc_status']} | exclude status: {filters['exc_status']}")
        print(f"    - include size:   {filters['inc_size']}  | exclude size:   {filters['exc_size']}")
        print(f"    - include substr: {filters['inc_contains']} | exclude substr: {filters['exc_contains']}")
        print()

    print(f"[*] Starting brute force against: {args.url}")
    valid_results = []

    # Producer-Consumer approach:
    # We'll open the file again and stream lines, never queuing
    # more futures than 'args.threads' at once.
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor, \
             open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f, \
             tqdm(total=total_lines, desc="Processing", unit="URL") as pbar:

            futures = []
            for line in f:
                w = line.strip()
                if not w:
                    pbar.update(1)
                    continue

                brute_url = f"{args.url}{args.prefix}{w}{args.suffix}"

                # If we already have 'threads' futures in flight, wait for at least one to finish
                while len(futures) >= args.threads:
                    done, not_done = wait(futures, return_when=FIRST_COMPLETED)
                    for d in done:
                        res = d.result()
                        pbar.update(1)
                        futures.remove(d)  # remove from the main list

                        if res["is_valid"]:
                            print(f"{GREEN}[+] {res['url']} => {res['status_code']} (size: {res['content_length']}){RESET}")
                            valid_results.append(res)

                # Submit a new job
                futures.append(executor.submit(worker, brute_url, filters, args.verbose))

            # After reading all lines, wait for leftover futures
            while futures:
                done, not_done = wait(futures, return_when=FIRST_COMPLETED)
                for d in done:
                    res = d.result()
                    pbar.update(1)
                    futures.remove(d)

                    if res["is_valid"]:
                        print(f"{GREEN}[+] {res['url']} => {res['status_code']} (size: {res['content_length']}){RESET}")
                        valid_results.append(res)

    except KeyboardInterrupt:
        print("\n[!] User interrupted. Stopping.")
        sys.exit(1)

    # Print summary
    print("\n=== Summary of Valid Results ===\n")
    if not valid_results:
        print("No valid routes found or everything got filtered out.")
    else:
        for entry in valid_results:
            print(f"[+] {entry['url']} => {entry['status_code']} (size: {entry['content_length']})")

    print("\nDone.")

if __name__ == "__main__":
    main()

