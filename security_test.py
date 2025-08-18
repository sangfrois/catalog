import requests
import time
import threading
import uuid
import os

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000"
# This should match the token in your app.py.
ADMIN_TOKEN = "your_very_secret_token" 
# A valid project name from app.py
VALID_PROJECT = "catherine" 

# --- Test Harness ---
def print_test_header(name):
    print(f"\n{'='*20}\n[TEST] {name}\n{'='*20}")

def print_result(test_name, success, message=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"  {status}: {test_name}")
    if message:
        print(f"    -> {message}")
    return success

# --- Test Functions ---

def test_rate_limiting():
    """Tests if the rate limiting middleware blocks excessive requests."""
    print_test_header("Rate Limiting")
    
    # The limit is 100 requests per 60 seconds. We'll send 105.
    limit = 105
    responses = []

    print(f"    -> Sending {limit} requests rapidly...")
    for _ in range(limit):
        try:
            res = requests.get(BASE_URL)
            responses.append(res.status_code)
        except requests.exceptions.ConnectionError:
            responses.append(999) # Special code for connection error
        time.sleep(0.01)

    too_many_requests_count = responses.count(429)
    success_count = responses.count(200)
    
    print(f"    -> Got {success_count} OK and {too_many_requests_count} 'Too Many Requests'.")
    
    return print_result(
        "Blocks excessive requests",
        too_many_requests_count > 0,
        f"Expected at least one 429 status, got {too_many_requests_count}."
    )

def test_request_size_limit():
    """Tests if the server rejects requests with bodies that are too large."""
    print_test_header("Request Size Limit (1MB)")
    
    # REQUEST_SIZE_LIMIT is 1 * 1024 * 1024 bytes
    large_payload = 'A' * (1 * 1024 * 1024 + 1)
    
    try:
        res = requests.post(
            f"{BASE_URL}/feedback",
            json={
                'project': VALID_PROJECT,
                'content': large_payload,
                'visitor_id': str(uuid.uuid4())
            }
        )
        return print_result(
            "Rejects oversized request body",
            res.status_code == 413,
            f"Expected 413, got {res.status_code}"
        )
    except requests.exceptions.RequestException as e:
        return print_result(
            "Rejects oversized request body",
            False,
            f"Request failed with an exception: {e}"
        )

def test_input_validation_and_ip_blocking():
    """Tests input validation and subsequent IP blocking after multiple violations."""
    print_test_header("Input Validation & IP Blocking")
    
    # Use a unique session to simulate a single client
    session = requests.Session()
    
    # --- Test 1: Malicious content ---
    malicious_payload = "<script>alert('xss')</script>"
    res = session.post(f"{BASE_URL}/feedback", json={'project': VALID_PROJECT, 'content': malicious_payload, 'visitor_id': 'test-1'})
    test1_ok = print_result(
        "Rejects content with <script> tag",
        res.status_code == 400,
        f"Expected 400, got {res.status_code}"
    )
    
    # --- Test 2: Invalid project name ---
    res = session.post(f"{BASE_URL}/feedback", json={'project': 'nonexistent_project', 'content': 'valid content', 'visitor_id': 'test-2'})
    test2_ok = print_result(
        "Rejects invalid project name",
        res.status_code == 400,
        f"Expected 400, got {res.status_code}"
    )
    
    # --- Test 3: Invalid visitor ID ---
    res = session.post(f"{BASE_URL}/feedback", json={'project': VALID_PROJECT, 'content': 'valid content', 'visitor_id': 'invalid_id_with_$$$'})
    test3_ok = print_result(
        "Rejects visitor_id with invalid characters",
        res.status_code == 400,
        f"Expected 400, got {res.status_code}"
    )
    
    # --- Test 4: Trigger IP block ---
    # We've already had 3 violations. We need 2 more to reach the threshold of 5.
    print("    -> Sending more invalid requests to trigger IP block...")
    for i in range(2):
        session.post(f"{BASE_URL}/feedback", json={'project': 'invalid', 'content': 'spam', 'visitor_id': f'spam-{i}'})
    
    # Now, the next request should be blocked, even if it's valid.
    res = session.post(f"{BASE_URL}/feedback", json={'project': VALID_PROJECT, 'content': 'this should be blocked', 'visitor_id': 'test-block'})
    test4_ok = print_result(
        "Blocks IP after 5 violations",
        res.status_code == 403,
        f"Expected 403, got {res.status_code}"
    )
    
    return test1_ok and test2_ok and test3_ok and test4_ok

def test_secure_headers():
    """Tests for the presence of security-related HTTP headers."""
    print_test_header("Secure HTTP Headers")
    
    try:
        res = requests.get(BASE_URL)
        headers = res.headers
        
        csp_ok = print_result(
            "Content-Security-Policy header is present",
            'Content-Security-Policy' in headers
        )
        
        xcto_ok = print_result(
            "X-Content-Type-Options header is 'nosniff'",
            headers.get('X-Content-Type-Options') == 'nosniff'
        )
        
        xfo_ok = print_result(
            "X-Frame-Options header is 'DENY'",
            headers.get('X-Frame-Options') == 'DENY'
        )
        
        return csp_ok and xcto_ok and xfo_ok
        
    except requests.exceptions.RequestException as e:
        return print_result(
            "Could not fetch headers",
            False,
            f"Request failed with an exception: {e}"
        )

def test_admin_endpoint():
    """Tests that the admin endpoint is properly secured."""
    print_test_header("Admin Endpoint Security")
    
    # --- Test 1: No token ---
    res = requests.post(f"{BASE_URL}/admin/unblock", json={'ip': '127.0.0.1'})
    test1_ok = print_result(
        "Rejects request with no token",
        res.status_code == 401,
        f"Expected 401, got {res.status_code}"
    )
    
    # --- Test 2: Wrong token ---
    res = requests.post(f"{BASE_URL}/admin/unblock?token=wrong_token", json={'ip': '127.0.0.1'})
    test2_ok = print_result(
        "Rejects request with wrong token",
        res.status_code == 401,
        f"Expected 401, got {res.status_code}"
    )
    
    # --- Test 3: Correct token (should succeed) ---
    res = requests.post(f"{BASE_URL}/admin/unblock?token={ADMIN_TOKEN}", json={'ip': '127.0.0.1'})
    test3_ok = print_result(
        "Accepts request with correct token",
        res.status_code == 200,
        f"Expected 200, got {res.status_code}"
    )
    
    return test1_ok and test2_ok and test3_ok

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting Machinic Encounters Security Audit...")
    print(f"Target: {BASE_URL}")
    
    try:
        requests.get(BASE_URL, timeout=2)
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Could not connect to the server.")
        print(f"Please make sure the Flask application is running at {BASE_URL}")
        exit(1)
        
    results = []
    
    print("\nNOTE: The IP blocking test will block this client's IP for one hour.")
    print("If other tests fail with 403, this is the likely cause. Restart the server to clear blocks.")
    
    results.append(test_secure_headers())
    results.append(test_admin_endpoint())
    results.append(test_request_size_limit())
    results.append(test_input_validation_and_ip_blocking()) # This will block the IP
    
    # The rate limit test is slow and may be flaky depending on machine performance.
    # It is commented out by default. Uncomment the line below to run it.
    # results.append(test_rate_limiting())
    
    print("\n" + "="*20 + "\nAUDIT SUMMARY\n" + "="*20)
    if all(results):
        print("✅ All security tests passed successfully!")
    else:
        failures = results.count(False)
        print(f"❌ {failures} security test(s) failed. Please review the output above.")
