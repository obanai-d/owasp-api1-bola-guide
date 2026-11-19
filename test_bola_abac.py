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
