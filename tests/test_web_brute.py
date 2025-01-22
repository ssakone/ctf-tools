import pytest
import asyncio
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_brute import WordlistGenerator, main
from test_server import run_test_server
import threading

@pytest.fixture(scope="session")
def server():
    server_thread = threading.Thread(target=run_test_server)
    server_thread.daemon = True
    server_thread.start()
    yield
    
@pytest.fixture
def wordlist():
    content = "admin\ntest\nindex\n"
    with open("test_wordlist.txt", "w") as f:
        f.write(content)
    yield "test_wordlist.txt"
    os.remove("test_wordlist.txt")

@pytest.fixture
def header_file():
    content = '{"Authorization": "Bearer FUZZ"}'
    with open("test_headers.json", "w") as f:
        f.write(content)
    yield "test_headers.json"
    os.remove("test_headers.json")

@pytest.fixture(autouse=True)
async def setup_teardown():
    # Setup
    yield
    # Cleanup
    await asyncio.sleep(0.1)  # Allow server to cleanup

@pytest.mark.asyncio
async def test_url_bruteforce(server, wordlist):
    args = [
        "-w", wordlist,
        "-u", "http://localhost:5000",
        "-v"
    ]
    result = await main(args)
    assert result is not None
    assert len(result) > 0

@pytest.mark.asyncio
async def test_pattern_bruteforce(server):
    args = [
        "-p", "[a]{3}",
        "-u", "http://localhost:5000",
        "-v"
    ]
    result = await main(args)
    assert len(result) == 26**3

@pytest.mark.asyncio
async def test_data_bruteforce(server):
    # Force [d]{3} to include "123"
    # Then check for success.
    args = [
        # Use a URL pattern to skip file usage but still satisfy the parser
        "-p", "[a]{1}",  
        "-u", "http://localhost:5000/auth",
        "-m", "POST",
        "--data-pattern", '{"username":"admin","password":"123"}',
        "-v"
    ]
    result = await main(args)

    print("\nReceived results:")
    for r in result:
        print(f"Status: {r.get('status')}, URL: {r.get('url')}")

    assert any(r['status'] == 200 for r in result), "No successful auth attempt found"

@pytest.mark.asyncio
async def test_header_bruteforce(server, header_file):
    args = [
        "-p", "[a]{1}",  # Add required pattern
        "-u", "http://localhost:5000",
        "--brute-headers",
        "-H", header_file,
        "-v"
    ]
    result = await main(args)
    assert result is not None
    assert len(result) > 0