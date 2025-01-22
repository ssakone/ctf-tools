# ctf-tools

## Web Path Brute-Forcer

A fast, async web path discovery tool for web application testing and CTF challenges.

### Features
- Asynchronous HTTP requests for high performance
- Multiple wordlist sources:
  - File-based wordlists
  - Pattern-based generation (e.g. `[a]{3}` for 3-letter combinations)
- Customizable HTTP options:
  - Multiple HTTP methods (GET, POST, PUT, etc.)
  - Custom headers
  - Request body data
  - Header bruteforcing
- Advanced filtering:
  - Status code filtering
  - Response size filtering
  - Response content filtering
- Progress bar and colorized output

### Installation

```bash
git clone https://github.com/yourusername/ctf-tools.git
cd ctf-tools
pip install -r requirements.txt

# Using wordlist file
python web_brute.py -w /path/to/wordlist.txt -u http://target.com/

# Using pattern generation
python web_brute.py -p "[a]{3}" -u http://target.com/
# POST request with body
python web_brute.py -w wordlist.txt -u http://target.com/ -m POST -d '{"key": "value"}'

# Custom headers from file
python web_brute.py -w wordlist.txt -u http://target.com/ -H headers.json

# Filter by status codes
python web_brute.py -w wordlist.txt -u http://target.com/ --include-status 200 301

# Filter by response size
python web_brute.py -w wordlist.txt -u http://target.com/ --exclude-size 0

---

-w, --wordlist     Path to wordlist file
-p, --pattern      Pattern for wordlist generation
-u, --url          Target URL
-m, --method       HTTP method (GET, POST, PUT, etc.)
-d, --data         Request body data (JSON)
-H, --headers      Headers file path
-t, --threads      Number of threads (default: 5)
--prefix           Prefix to add to each word
--suffix           Suffix to add to each word
--include-status   Only show responses with these status codes
--exclude-status   Hide responses with these status codes
--include-size     Only show responses with these sizes
--exclude-size     Hide responses with these sizes
-v, --verbose      Verbose output

Pattern Syntax
[a] - lowercase letters
[A] - uppercase letters
[d] - digits
[s] - special characters
{n} - length
Examples:

[a]{3} - aaa to zzz
[ad]{2} - aa to z9
[aA]{1} - a to Z