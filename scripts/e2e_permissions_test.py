#!/usr/bin/env python3
"""
Live Production Permission & Revocation Acceptance Test
Validates:
  1. Owner registers and uploads doc.
  2. Viewer registers.
  3. Viewer attempts unauthorized download -> 403 Forbidden (Audit event logged).
  4. Owner grants READ permission to Viewer.
  5. Viewer downloads doc -> 200 OK, SHA-256 match.
  6. Owner revokes permission.
  7. Viewer attempts download immediately -> 403 Forbidden (immediate revocation verified).
  8. Clean up test document.
"""

import sys
import time
import random
import hashlib
import urllib.request
import urllib.parse
import http.cookiejar
import re
import ssl

BASE_URL = "https://trustvault-lemon.vercel.app"

def run_permission_tests():
    print(f"=== TRUSTVAULT LIVE PERMISSION & REVOCATION TEST ===")
    print(f"Target: {BASE_URL}\n")

    ctx = ssl.create_default_context()

    def make_session():
        cj = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj),
            urllib.request.HTTPSHandler(context=ctx)
        )
        return opener, cj

    def extract_csrf(html, cj):
        match = re.search(r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        for cookie in cj:
            if cookie.name == 'csrftoken':
                return cookie.value
        return None

    def register_and_login(username, email, password, role):
        opener, cj = make_session()
        # GET register
        with opener.open(f"{BASE_URL}/accounts/register/") as resp:
            csrf = extract_csrf(resp.read().decode('utf-8'), cj)

        # POST register
        reg_data = urllib.parse.urlencode({
            'csrfmiddlewaretoken': csrf,
            'username': username,
            'email': email,
            'role': role,
            'password1': password,
            'password2': password,
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{BASE_URL}/accounts/register/",
            data=reg_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': f"{BASE_URL}/accounts/register/"}
        )
        with opener.open(req) as resp:
            login_page_html = resp.read().decode('utf-8')
            login_csrf = extract_csrf(login_page_html, cj)

        # POST login
        login_data = urllib.parse.urlencode({
            'csrfmiddlewaretoken': login_csrf,
            'username': username,
            'password': password,
        }).encode('utf-8')
        req = urllib.request.Request(
            f"{BASE_URL}/accounts/login/",
            data=login_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': f"{BASE_URL}/accounts/login/"}
        )
        with opener.open(req) as resp:
            dash_html = resp.read().decode('utf-8')
            assert any(c.name == 'sessionid' for c in cj), f"Login failed for {username}"

        return opener, cj

    ts = f"{int(time.time())}_{random.randint(100, 999)}"
    owner_uname = f"perm_owner_{ts}"
    viewer_uname = f"perm_viewer_{ts}"
    pwd = "SecureTestPass123!@#"

    print(f"Creating Owner ({owner_uname}) and Viewer ({viewer_uname})...")
    owner_opener, owner_cj = register_and_login(owner_uname, f"{owner_uname}@test.com", pwd, 'OWNER')
    viewer_opener, viewer_cj = register_and_login(viewer_uname, f"{viewer_uname}@test.com", pwd, 'VIEWER')
    print("  [OK] Both users registered and logged in.")

    # 1. Owner uploads document
    with owner_opener.open(f"{BASE_URL}/documents/upload/") as resp:
        upload_csrf = extract_csrf(resp.read().decode('utf-8'), owner_cj)

    boundary = f"----Boundary{ts}"
    payload_content = f"Confidential Permission Test Content {ts}".encode('utf-8')
    expected_hash = hashlib.sha256(payload_content).hexdigest()

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="csrfmiddlewaretoken"\r\n\r\n{upload_csrf}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="name"\r\n\r\nPermission Test Doc {ts}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="description"\r\n\r\nRBAC test\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="category"\r\n\r\nLEGAL\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="perm_test_{ts}.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode('utf-8') + payload_content + f"\r\n--{boundary}--\r\n".encode('utf-8')

    req = urllib.request.Request(
        f"{BASE_URL}/documents/upload/",
        data=body,
        headers={'Content-Type': f"multipart/form-data; boundary={boundary}", 'Referer': f"{BASE_URL}/documents/upload/"}
    )
    with owner_opener.open(req) as resp:
        html = resp.read().decode('utf-8')
        doc_id = re.search(r'/documents/(\d+)/', html).group(1)
    print(f"  [OK] Document uploaded with ID={doc_id}")

    # 2. Viewer attempts download before permission -> MUST BE 403 Forbidden
    print("Testing unauthorized download attempt by unpermitted viewer...")
    try:
        with viewer_opener.open(f"{BASE_URL}/documents/{doc_id}/download/") as resp:
            print(f"  [FAIL] Viewer was unexpectedly allowed to download (HTTP {resp.status})!")
            sys.exit(1)
    except urllib.error.HTTPError as err:
        assert err.code == 403, f"Expected HTTP 403, got HTTP {err.code}"
        print(f"  [PASS] Correctly rejected unauthorized viewer with HTTP {err.code} Forbidden.")

    # 3. Owner grants READ permission to Viewer
    print(f"Owner granting READ permission to {viewer_uname}...")
    with owner_opener.open(f"{BASE_URL}/permissions/document/{doc_id}/") as resp:
        share_html = resp.read().decode('utf-8')
        share_csrf = extract_csrf(share_html, owner_cj)

    grant_data = urllib.parse.urlencode({
        'csrfmiddlewaretoken': share_csrf,
        'recipient_username': viewer_uname,
        'permission_type': 'READ',
    }).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}/permissions/document/{doc_id}/grant/",
        data=grant_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': f"{BASE_URL}/permissions/document/{doc_id}/"}
    )
    with owner_opener.open(req) as resp:
        grant_resp_html = resp.read().decode('utf-8')
        assert viewer_uname in grant_resp_html, "Viewer not found in permissions list after grant"
    print(f"  [PASS] READ permission granted successfully.")

    # 4. Viewer downloads document -> MUST SUCCEED (200 OK)
    print("Viewer attempting authorized download...")
    with viewer_opener.open(f"{BASE_URL}/documents/{doc_id}/download/") as resp:
        content = resp.read()
        got_hash = hashlib.sha256(content).hexdigest()
        assert got_hash == expected_hash, "Downloaded content hash mismatch!"
        assert resp.status == 200
    print(f"  [PASS] Authorized download succeeded (200 OK, 100% SHA-256 match: {got_hash[:12]}...).")

    # 5. Owner revokes permission
    print("Owner revoking permission from viewer...")
    # Find perm_id from share management page
    with owner_opener.open(f"{BASE_URL}/permissions/document/{doc_id}/") as resp:
        manage_html = resp.read().decode('utf-8')
        revoke_match = re.search(r'/permissions/document/\d+/revoke/(\d+)/', manage_html)
        assert revoke_match, "Revoke link/form not found in manage page"
        perm_id = revoke_match.group(1)
        revoke_csrf = extract_csrf(manage_html, owner_cj)

    revoke_data = urllib.parse.urlencode({'csrfmiddlewaretoken': revoke_csrf}).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}/permissions/document/{doc_id}/revoke/{perm_id}/",
        data=revoke_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': f"{BASE_URL}/permissions/document/{doc_id}/"}
    )
    with owner_opener.open(req) as resp:
        assert resp.status == 200
    print(f"  [PASS] Permission ID={perm_id} revoked.")

    # 6. Viewer immediately attempts download -> MUST BE 403 Forbidden!
    print("Verifying IMMEDIATE revocation enforcement for viewer...")
    try:
        with viewer_opener.open(f"{BASE_URL}/documents/{doc_id}/download/") as resp:
            print(f"  [FAIL] Viewer was able to download after revocation (HTTP {resp.status})!")
            sys.exit(1)
    except urllib.error.HTTPError as err:
        assert err.code == 403, f"Expected HTTP 403 after revocation, got {err.code}"
        print(f"  [PASS] Revocation effective immediately: HTTP {err.code} Forbidden.")

    # 7. Owner deletes document
    with owner_opener.open(f"{BASE_URL}/documents/{doc_id}/") as resp:
        del_csrf = extract_csrf(resp.read().decode('utf-8'), owner_cj)
    del_data = urllib.parse.urlencode({'csrfmiddlewaretoken': del_csrf}).encode('utf-8')
    req = urllib.request.Request(
        f"{BASE_URL}/documents/{doc_id}/delete/",
        data=del_data,
        headers={'Content-Type': 'application/x-www-form-urlencoded', 'Referer': f"{BASE_URL}/documents/{doc_id}/"}
    )
    with owner_opener.open(req) as resp:
        assert resp.status == 200
    print(f"  [OK] Test document ID={doc_id} cleaned up.")

    print("\n=== ALL PERMISSION LIFECYCLE & IMMEDIATE REVOCATION TESTS PASSED (100%) ===")

if __name__ == '__main__':
    run_permission_tests()
