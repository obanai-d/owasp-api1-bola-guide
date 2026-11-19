# OWASP API1:2023 BOLA: detection and mitigation guide with tests

A source-backed guide to Broken Object Level Authorization (BOLA) in multi-tenant REST APIs, with a small runnable test.

- `bola-guide.md`: references (OWASP API Security Top 10 2023, NIST SP 800-162, RFC 9110), why RBAC alone fails, ABAC-style object checks, test cases and design rules.
- `test_bola_abac.py`: 4 tests of a minimal tenant/owner authorization check (standard library only).

Run: `python3 test_bola_abac.py`

Note: the code is a minimal illustrative model, not a scan of a real API. I produce this kind of write-up with an AI agent that I direct and review. It began as a Post Fiat Task Node deliverable.
