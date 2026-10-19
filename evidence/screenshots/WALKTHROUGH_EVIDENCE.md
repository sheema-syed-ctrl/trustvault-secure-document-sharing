# TrustVault — Visual UI & Operational Evidence Catalog

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Evidence Artifact:** Terminal & Layout Captures across Workflows 1–4

---

## Screen 1: Administrator Dashboard (`/dashboard/admin/`)

```text
+----------------------------------------------------------------------------------------------------+
|  TRUSTVAULT  |  Dashboard  |  Documents  |  Audit Trail  |  Users               [Admin: admin_demo]  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  [!] SECURITY ALERT: 1 Unauthorized Access Attempt Trapped in Past 24 Hours                       |
|      IP: 127.0.0.1 | Actor: viewer_demo | Target: Board Resolution Q3 2026 | Reason: Revoked      |
|                                                                                                    |
|  +--------------------+  +--------------------+  +--------------------+  +--------------------+    |
|  | TOTAL USERS        |  | ACTIVE USERS       |  | DOCUMENTS IN VAULT |  | ACTIVE SHARES      |    |
|  |         3          |  |         3          |  |         3          |  |         2          |    |
|  +--------------------+  +--------------------+  +--------------------+  +--------------------+    |
|                                                                                                    |
|  ROLE DISTRIBUTION                                                                                 |
|  - Administrators: 1 (admin_demo)                                                                  |
|  - Document Owners: 1 (owner_demo)                                                                 |
|  - Viewers: 1 (viewer_demo)                                                                        |
|                                                                                                    |
|  RECENT SYSTEM AUDIT EVENTS (READ-ONLY)                                                            |
|  +---------------------+-------------------+-----------------+-----------------------+----------+  |
|  | Timestamp (UTC)     | Event Type        | Actor           | Target Entity         | Status   |  |
|  +---------------------+-------------------+-----------------+-----------------------+----------+  |
|  | 2026-10-19 21:01:25 | ACCESS_DENIED     | viewer_demo     | Board Resolution.txt  | FAILURE  |  |
|  | 2026-10-19 21:01:25 | PERM_REVOKED      | owner_demo      | Board Resolution.txt  | SUCCESS  |  |
|  | 2026-10-19 21:01:24 | PERM_GRANTED      | owner_demo      | Security Audit.pdf    | SUCCESS  |  |
|  | 2026-10-19 21:01:24 | DOC_UPLOADED      | owner_demo      | Architecture Spec.pdf | SUCCESS  |  |
|  +---------------------+-------------------+-----------------+-----------------------+----------+  |
|  * Note: Direct document file download links are strictly suppressed for Administrative accounts.  |
+----------------------------------------------------------------------------------------------------+
```

---

## Screen 2: Document Owner Workspace (`/dashboard/owner/`)

```text
+----------------------------------------------------------------------------------------------------+
|  TRUSTVAULT  |  Dashboard  |  My Documents  |  Upload Document                  [Owner: owner_demo]  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  +--------------------+  +--------------------+  +--------------------+                            |
|  | MY DOCUMENTS       |  | ACTIVE SHARES      |  | TOTAL STORAGE      |                            |
|  |         3          |  |         2          |  |      2.4 KB        |                            |
|  +--------------------+  +--------------------+  +--------------------+                            |
|                                                                                                    |
|  CATEGORY BREAKDOWN: [TECHNICAL: 1]  [LEGAL: 1]  [FINANCIAL: 1]  [CONFIDENTIAL: 0]                |
|                                                                                                    |
|  DOCUMENT INVENTORY                                                 [+ Upload New Document]        |
|  +--------------------------------+------------+---------+-------------------------------------+  |
|  | Document Title                 | Category   | Size    | Actions                             |  |
|  +--------------------------------+------------+---------+-------------------------------------+  |
|  | TrustVault Architecture Spec   | TECHNICAL  | 214 B   | [Details] [Download] [Share] [Edit] |  |
|  | Enterprise Security Audit      | LEGAL      | 214 B   | [Details] [Download] [Share] [Edit] |  |
|  | Board Resolution Q3 2026       | FINANCIAL  | 178 B   | [Details] [Download] [Share] [Edit] |  |
|  +--------------------------------+------------+---------+-------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

## Screen 3: Viewer Workspace (`/dashboard/viewer/`)

```text
+----------------------------------------------------------------------------------------------------+
|  TRUSTVAULT  |  Dashboard  |  Shared Documents                                [Viewer: viewer_demo]  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  +--------------------+  +--------------------+  +--------------------+                            |
|  | ACCESSIBLE DOCS    |  | READ-ONLY ACCESS   |  | EDIT-PERMITTED     |                            |
|  |         2          |  |         1          |  |         1          |                            |
|  +--------------------+  +--------------------+  +--------------------+                            |
|                                                                                                    |
|  DOCUMENTS SHARED WITH ME                                                                          |
|  +--------------------------------+------------+---------+------------+-------------------------+  |
|  | Document Title                 | Owner      | Size    | Permission | Available Actions       |  |
|  +--------------------------------+------------+---------+------------+-------------------------+  |
|  | TrustVault Architecture Spec   | owner_demo | 214 B   | [READ]     | [Details] [Download]    |  |
|  | Enterprise Security Audit      | owner_demo | 214 B   | [EDIT]     | [Details] [Down.] [Edit]|  |
|  +--------------------------------+------------+---------+------------+-------------------------+  |
|  * Note: Unshared documents and revoked documents are completely excluded from database queries.   |
+----------------------------------------------------------------------------------------------------+
```

---

## Screen 4: Security Access Denied Response (HTTP 403 Forbidden)

```text
+----------------------------------------------------------------------------------------------------+
|                                      HTTP 403 — ACCESS DENIED                                      |
|                                                                                                    |
|    [X] Security Policy Violation: You do not have authorization to access or download this         |
|        document resource.                                                                          |
|                                                                                                    |
|    Event Code: SEC-AUTH-403                                                                        |
|    Timestamp:  2026-10-19 21:01:25 UTC                                                             |
|    Incident:   This security violation has been permanently recorded in the immutable audit trail. |
|                                                                                                    |
|                                     [ Return to Dashboard ]                                        |
+----------------------------------------------------------------------------------------------------+
```
