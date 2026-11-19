# Security Guide: Detecting and Mitigating OWASP API1:2023 Broken Object Level Authorization (BOLA) in Multi-Tenant REST APIs

## 1. Authoritative References and Numbered Public Sources
[1] OWASP API Security Top 10 (2023 Edition) - API1:2023 Broken Object Level Authorization:
    https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
[2] OWASP Top 10 API Security Risks Project Overview:
    https://owasp.org/www-project-api-security/
[3] NIST Special Publication 800-162: Guide to Attribute Based Access Control (ABAC) Definition and Considerations:
    https://csrc.nist.gov/pubs/sp/800/162/final
[4] RFC 9110: HTTP Semantics (Client Error Status Codes 401, 403, 404):
    https://datatracker.ietf.org/doc/html/rfc9110#section-15.5
[5] RFC 6749: The OAuth 2.0 Authorization Framework:
    https://datatracker.ietf.org/doc/html/rfc6749

---

## 2. BOLA Mechanics and Why RBAC Fails in Multi-Tenant Architectures

### 2.1 Understanding Broken Object Level Authorization (API1:2023)
Broken Object Level Authorization (BOLA), historically catalogued under Insecure Direct Object References (IDOR), consistently ranks as the number one vulnerability in the OWASP API Security Top 10. Modern REST APIs frequently expose identifiers directly in request URLs (such as `GET /api/v1/documents/{document_id}`), query parameters, or payload bodies. BOLA occurs when an API endpoint receives an object identifier from a client and retrieves or manipulates the corresponding backend entity without validating whether the authenticated actor possesses legitimate authorization to interact with that specific instance.

### 2.2 Why Role-Based Access Control (RBAC) Fails to Mitigate BOLA
A common architectural misconception is that functional Role-Based Access Control (RBAC) protects against cross-tenant or horizontal privilege escalation. RBAC evaluates whether an authenticated subject holds permission to execute a specific class of operation on an endpoint (e.g., verifying that a user has the role `analyst` or permission `documents:read`).

However, RBAC operates purely on action permissions and lacks resource-level contextual awareness:
- User Alice (Tenant Alpha) possesses the valid role `analyst`.
- User Bob (Tenant Beta) possesses the valid role `analyst`.
- When Alice issues a request to `GET /api/v1/documents/doc-beta-999`, the RBAC authorization gateway verifies that Alice is authenticated and holds the `analyst` role. The gateway permits the request because `analyst` is authorized to invoke the endpoint.
- If the endpoint implementation queries `SELECT * FROM documents WHERE id = 'doc-beta-999'` without enforcing tenant or owner scoping, Bob's sensitive data is leaked to Alice across the tenant boundary.

### 2.3 Attribute-Based Access Control (ABAC) as the Resolution
Mitigating BOLA requires transitioning from coarse-grained RBAC to fine-grained Attribute-Based Access Control (ABAC, NIST SP 800-162). Under ABAC, the Policy Enforcement Point (PEP) evaluates subject attributes (e.g., authenticated `tenant_id`, user ID), object attributes (e.g., resource `tenant_id`, owner, access control list), action attributes (`read`, `update`), and environmental attributes before granting access.

---

## 3. Multi-Tenant Endpoint Test Plan and Inspection Checklist

### 3.1 Endpoint Test Matrix
The following test plan defines verification criteria for multi-tenant REST endpoints exposing object IDs:

| Test ID | Scenario | Injected Vector | Expected HTTP Status | Security Assertion |
| :--- | :--- | :--- | :--- | :--- |
| **TC-BOLA-01** | Authorized Intra-Tenant Read | `GET /records/rec-101` (User A, Tenant Alpha) | `200 OK` | Valid request within authenticated tenant boundary succeeds. |
| **TC-BOLA-02** | Horizontal BOLA / IDOR Tampering | `GET /records/rec-202` (User A, Tenant Alpha accessing Tenant Beta record) | `403 Forbidden` or `404 Not Found` | Cross-tenant access blocked. No payload leaked. |
| **TC-BOLA-03** | Tenant Header Spoofing | `GET /records/rec-202` with header `X-Tenant-ID: tenant-beta` | `403 Forbidden` | Server ignores client-supplied tenant headers and validates strictly against token claims. |
| **TC-BOLA-04** | Horizontal BOLA Mutation | `PUT /records/rec-202` with payload `{ "data": "tampered" }` | `403 Forbidden` | State mutation across tenants rejected. |
| **TC-BOLA-05** | Unauthenticated Access | `GET /records/rec-101` with no auth bearer token | `401 Unauthorized` | Baseline unauthenticated invocation rejected per RFC 9110. |

### 3.2 Security Inspection Checklist for API Architects
1. **Source of Truth for Tenant Context:** Never read `tenant_id` or `user_id` from query strings, request path parameters, or client headers. The tenant identifier must be extracted exclusively from validated cryptographic session tokens (e.g., signed JWT claims verified at the server).
2. **Database Query Scoping:** Ensure database access layers consistently enforce tenant scoping at the SQL/ORM level (e.g., `WHERE record_id = :id AND tenant_id = :session_tenant_id`). Do not rely on application-level filtering post-fetch.
3. **Defense in Depth with ABAC:** Implement a Policy Enforcement Point (PEP) within domain service boundaries to validate object ownership attributes prior to serialization.
4. **Opaque Identifiers:** While not a replacement for authorization, use cryptographically random, high-entropy identifiers (such as UUIDv4) to prevent sequential enumeration attacks.
5. **Standardized Error Handling:** Return `403 Forbidden` or `404 Not Found` consistently to prevent side-channel object existence enumeration.

---

## 4. Synthetic Scenario and Verification Test Script

### 4.1 Synthetic Scenario Definition
To illustrate the difference between vulnerable RBAC-only routing and secure ABAC enforcement without relying on private infrastructure, we define a synthetic multi-tenant scenario:
- **Tenant Alpha:** Houses record `rec-101` (owned by user Alice, role `analyst`).
- **Tenant Beta:** Houses record `rec-202` (owned by user Bob, role `analyst`).
- **Vulnerable Handler (`vulnerable_get_record`):** Confirms the user has the `analyst` role, then fetches `rec-202` directly. Result: Alice successfully reads Bob's confidential record across tenant boundaries (BOLA leak).
- **Secure ABAC Handler (`secure_abac_get_record`):** Evaluates whether the requested resource's `tenant_id` matches the authenticated subject's `tenant_id`. Result: Cross-tenant access is rejected with `403 Forbidden`.

### 4.2 Standard-Library Python Test Script (`test_bola_abac.py`)
Below is the self-contained, standard-library Python test script (59 lines, under the 80-line limit):

```python
"""Synthetic test harness demonstrating BOLA (OWASP API1:2023) vs ABAC."""
import unittest

# Synthetic in-memory repository: {record_id: {"tenant_id": str, "owner": str, "payload": str}}
DB = {
    "rec-101": {"tenant_id": "tenant-alpha", "owner": "alice", "data": "financial-report-q1"},
    "rec-202": {"tenant_id": "tenant-beta", "owner": "bob", "data": "confidential-roadmap-2026"},
}

def vulnerable_get_record(subject, record_id):
    """Vulnerable endpoint: RBAC checks authenticated role, but omits object-level check."""
    if not subject.get("role"):
        return 401, {"error": "Unauthenticated"}
    record = DB.get(record_id)
    if not record:
        return 404, {"error": "Not Found"}
    # Flaw: Object returned directly without validating subject["tenant_id"] == record["tenant_id"]
    return 200, record

def secure_abac_get_record(subject, record_id):
    """Secure endpoint: Enforces Attribute-Based Access Control (Tenant & Ownership validation)."""
    if not subject.get("role"):
        return 401, {"error": "Unauthenticated"}
    record = DB.get(record_id)
    if not record:
        return 404, {"error": "Not Found"}
    # ABAC policy enforcement: Tenant isolation check
    if record["tenant_id"] != subject.get("tenant_id"):
        return 403, {"error": "Forbidden: Cross-tenant access prohibited"}
    return 200, record

class TestBolaMitigation(unittest.TestCase):
    def setUp(self):
        self.user_alpha = {"user": "alice", "tenant_id": "tenant-alpha", "role": "analyst"}
        self.user_beta = {"user": "bob", "tenant_id": "tenant-beta", "role": "analyst"}

    def test_01_authorized_tenant_access_succeeds(self):
        status, body = secure_abac_get_record(self.user_alpha, "rec-101")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"], "financial-report-q1")

    def test_02_vulnerable_endpoint_allows_bola_cross_tenant_leak(self):
        # Alice requests Bob's record in tenant-beta. RBAC check passes, leaking data!
        status, body = vulnerable_get_record(self.user_alpha, "rec-202")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"], "confidential-roadmap-2026")

    def test_03_secure_abac_blocks_cross_tenant_access(self):
        # Secure handler detects tenant mismatch and returns 403 Forbidden.
        status, body = secure_abac_get_record(self.user_alpha, "rec-202")
        self.assertEqual(status, 403)
        self.assertIn("Cross-tenant access prohibited", body["error"])

    def test_04_unauthenticated_request_blocked(self):
        status, body = secure_abac_get_record({}, "rec-101")
        self.assertEqual(status, 401)

if __name__ == "__main__":
    unittest.main()
```

---

## 5. Local Execution Verification and Complete Terminal Output

The test script was executed locally against Python 3. The test results verify both the vulnerability reproduction (test 02 demonstrating cross-tenant data exposure under pure RBAC) and the ABAC mitigation enforcement (test 03 enforcing strict tenant isolation).

### Terminal Command:
`python3 test_bola_abac.py -v`

### Unedited Terminal Output:
```text
test_01_authorized_tenant_access_succeeds (__main__.TestBolaMitigation.test_01_authorized_tenant_access_succeeds) ... ok
test_02_vulnerable_endpoint_allows_bola_cross_tenant_leak (__main__.TestBolaMitigation.test_02_vulnerable_endpoint_allows_bola_cross_tenant_leak) ... ok
test_03_secure_abac_blocks_cross_tenant_access (__main__.TestBolaMitigation.test_03_secure_abac_blocks_cross_tenant_access) ... ok
test_04_unauthenticated_request_blocked (__main__.TestBolaMitigation.test_04_unauthenticated_request_blocked) ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.001s

OK
```
