# TrustVault — 5-Minute Evaluation & Demonstration Walkthrough

**Project:** TrustVault — Secure Document Sharing with a Real Audit Trail
**Challenge:** Snovasys Fresher Hiring Challenge 2026
**Target Duration:** 5 Minutes (0:00 - 5:00)
**Evaluator Personas:** 3 Distinct Roles (`admin_demo`, `owner_demo`, `viewer_demo`)

---

## Pre-Demonstration Setup (10 Seconds)

Ensure the test database and synthetic demo data are fresh:
```bash
python manage.py migrate
python manage.py seed_demo_data --clean
python manage.py runserver
```
> [!TIP]
> Note the dynamically generated passwords displayed in your terminal output from the `seed_demo_data` command (or preset them via `$env:DEMO_ADMIN_PASSWORD="YourPassword!"`, etc.).

Open your browser at `http://127.0.0.1:8000/`.

---

## Workflow 1: Administrator Governance & Security Monitoring (Minute 0:00 - 1:15)

**Objective:** Demonstrate platform health, user administration, security alarms, and administrative privacy boundaries.

### Step 1.1: Sign In as Administrator
1. Navigate to `http://127.0.0.1:8000/accounts/login/`.
2. Enter credentials:
   - **Username:** `admin_demo`
   - **Password:** `<Password displayed in terminal upon running seed_demo_data>`
3. Click **Sign In**.

### Step 1.2: Inspect the Admin Control Panel (`/dashboard/`)
- **Key Observation 1 (Metrics Overview):** Observe top KPI tiles showing:
  - Total Users: `3` (1 Admin, 1 Owner, 1 Viewer)
  - Registered Documents: `3`
  - Active Shares: `2`
  - Security Denials: `1+`
- **Key Observation 2 (Security Denials Alert):** Notice the amber security alert banner displaying recent unauthorized access attempts (`SECURITY_ACCESS_DENIED`) triggered by unassigned viewers attempting downloads.
- **Key Observation 3 (Zero Document Eavesdropping):** Notice that while the administrator can see document counts, category metrics, and operational health, **no document download links or content inspection buttons are rendered**. Administrators manage the platform without violating document privacy.

### Step 1.3: Inspect the Global Audit Trail (`/audit/`)
1. Click **Audit Trail** in the navigation header.
2. Filter by Event Type: Select `SECURITY_ACCESS_DENIED`.
3. Click **Filter**.
4. Observe the immutable audit event log displaying:
   - Timestamp (ISO 8601 UTC)
   - Actor: `viewer_demo`
   - Event: `SECURITY_ACCESS_DENIED`
   - Target Document: `Board Resolution & Executive Compensation Q3 2026`
   - Status: `FAILURE`
   - IP Address & User Agent: Captured safely without sensitive credential exposure.

---

## Workflow 2: Document Ingestion, Categorization & Private Storage (Minute 1:15 - 2:30)

**Objective:** Demonstrate Document Owner capabilities, binary magic-byte verification, and storage segregation.

### Step 2.1: Switch to Document Owner
1. Click **Sign Out** (top right). Confirm redirection to login.
2. Sign in as:
   - **Username:** `owner_demo`
   - **Password:** `<Password displayed in terminal upon running seed_demo_data>`

### Step 2.2: Inspect Owner Workspace (`/dashboard/`)
- Notice the owner-tailored dashboard:
  - Metric cards: Owned Documents (`3`), Total Active Shares (`2`), Storage Usage (~2.4 KB).
  - Category breakdown chart (`TECHNICAL`, `LEGAL`, `FINANCIAL`).
  - Document Inventory table showing ownership actions: Details, Download, Manage Access, Edit Metadata.

### Step 2.3: Upload a New Confidential Document
1. Click **Upload Document** (`/documents/upload/`).
2. Fill out the upload form:
   - **Document Name:** `Q4 2026 Board Strategy Paper`
   - **Description:** `Classified board proceedings and strategic M&A acquisitions.`
   - **Category:** `CONFIDENTIAL`
   - **File:** Choose a local `.pdf` or `.txt` file (or use sample).
3. Click **Upload to Secure Vault**.
4. Observe redirection to the Document Detail view (`/documents/<id>/`).
5. **Security Verification:**
   - Inspect the file properties: Notice the generated `SHA-256 Hash` and verified `MIME Type`.
   - Verify that the physical file is written to `protected_media/<uuid>.bin`, completely isolated from public URL paths.

---

## Workflow 3: Granular Permission Delegation & Viewer Access (Minute 2:30 - 3:45)

**Objective:** Demonstrate object-level permission granting and role-enforced capabilities.

### Step 3.1: Delegate READ Access to Viewer
1. From the Document Detail view, click **Share & Manage Access** (`/permissions/document/<id>/`).
2. Under "Grant Access to New Recipient":
   - **Recipient:** Select `viewer_demo (Viewer)`.
   - **Permission Type:** Select `READ (View & Download Only)`.
3. Click **Grant Access**.
4. Notice the confirmation alert and table update displaying `viewer_demo` with `READ` badge.

### Step 3.2: Verify Viewer Experience
1. Click **Sign Out** and sign in as:
   - **Username:** `viewer_demo`
   - **Password:** `<Password displayed in terminal upon running seed_demo_data>`
2. Notice the Viewer Workspace (`/dashboard/`):
   - Only documents explicitly shared with `viewer_demo` appear.
   - Documents are cleanly partitioned into:
     - **Read-Only Access:** Details and Download buttons are active.
     - **Edit-Permitted Access:** Edit Metadata button is also available.
     - Delete and Share buttons are completely absent.
3. Click **Download** on `TrustVault Architecture & Threat Model Specification`.
4. Observe that the file streams smoothly via authenticated controller with filename `trustvault_spec.pdf`.

---

## Workflow 4: Immediate Access Revocation & Denial Alarms (Minute 3:45 - 5:00)

**Objective:** Prove zero-lag permission revocation, instant access cutoff, and tamper-resistant audit logging.

### Step 4.1: Revoke Access as Document Owner
1. Sign out of `viewer_demo` and sign back in as `owner_demo`.
2. Navigate to `TrustVault Architecture & Threat Model Specification` -> **Manage Access**.
3. Under Active Collaborators, locate `viewer_demo` (READ).
4. Click **Revoke Access** and confirm the prompt.
5. Notice the flash alert: `Access revoked successfully for viewer_demo`.

### Step 4.2: Prove Instant Access Cutoff (Zero-Lag Enforcement)
1. Sign out and sign back in as `viewer_demo`.
2. Inspect Viewer Dashboard: `TrustVault Architecture & Threat Model Specification` has vanished from the accessible table.
3. **Penetration Test (Direct URL Bypass):**
   - Attempt to directly access the document URL: `http://127.0.0.1:8000/documents/2/` (or previously noted ID).
   - **Result:** Immediate `HTTP 403 Forbidden` error template is rendered.
   - Attempt direct download URL: `http://127.0.0.1:8000/documents/2/download/`.
   - **Result:** Immediate `HTTP 403 Forbidden` rejection.

### Step 4.3: Verify Administrative Audit Evidence
1. Sign out of `viewer_demo` and sign in as `admin_demo`.
2. Navigate to `/audit/`.
3. Notice that:
   - `PERMISSION_REVOKED` was logged by `owner_demo` against `viewer_demo`.
   - Subsequent unauthorized access attempts by `viewer_demo` were immediately trapped and logged as `SECURITY_ACCESS_DENIED`.
4. **Conclusion:** End-to-end zero-trust lifecycle fully demonstrated within 5 minutes.
