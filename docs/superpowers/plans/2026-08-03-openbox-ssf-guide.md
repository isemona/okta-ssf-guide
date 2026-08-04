# OpenBox SSF Integration Guide Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Write a complete Markdown developer guide for OpenBox's engineering team to build an SSF Transmitter and send Security Event Tokens to Okta.

**Architecture:** Single `README.md` in the `isemona/okta-ssf-guide` GitHub repo. Flow-first: quick-start at top, full reference sections below. Python code examples throughout (cryptography + PyJWT + requests).

**Tech Stack:** Markdown, Python (`cryptography`, `PyJWT`, `requests`), Mermaid (sequence diagram), curl (API examples)

## Global Constraints

- Audience: OpenBox engineers — expert-level Python/TS, familiar with JWTs, DIDs, REST. No JWT/HTTP basics.
- Use only current non-deprecated APIs: SSF Receiver API (`/api/v1/security-events-providers`, `/security/api/v1/security-events`). Not the Risk Provider API (deprecated 2025).
- `aud` must always show with trailing slash: `https://your-org.okta.com/`
- `iss` must exactly match the issuer registered in the provider object
- `jti` must be unique per SET — document silent drop behavior explicitly
- Python package dependencies: `cryptography`, `PyJWT`, `requests`
- Working directory: `/Users/semona.igama/okta-ssf-guide/`
- Commit and push to `isemona/okta-ssf-guide` after each task

---

### Task 1: README skeleton + Overview section

**Files:**
- Create: `README.md`

**Interfaces:**
- Produces: `README.md` with title, intro blurb, TOC, and Overview section including the Mermaid sequence diagram

- [ ] **Step 1: Check spec coverage for Overview**

  Requirements from spec:
  - What SSF is and why it matters for AI agent security
  - OpenBox as transmitter, Okta as receiver
  - What it enables: agent risk signals → Okta risk engine → adaptive policies
  - Mermaid sequence diagram (exact diagram from design spec)

- [ ] **Step 2: Create README.md**

  ```markdown
  # OpenBox → Okta: Shared Signals Framework Integration

  > Build an SSF Transmitter that sends risk signals from OpenBox directly into Okta's risk engine. Okta is ready to receive — you just need to build the transmitter.

  ## Table of Contents

  - [Overview](#overview)
  - [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [Step 1: Keys \& Endpoints](#step-1-keys--endpoints)
  - [Step 2: Register with Okta](#step-2-register-with-okta)
  - [Step 3: Event Reference](#step-3-event-reference)
  - [Step 4: Sending SETs](#step-4-sending-sets)
  - [Step 5: Verifying in Okta](#step-5-verifying-in-okta)
  - [Production Hardening](#production-hardening)
  - [References](#references)

  ---

  ## Overview

  When OpenBox detects risky AI agent behavior, it can push that signal directly into Okta's risk engine via the [Shared Signals Framework (SSF)](https://sharedsignals.guide). Okta evaluates the signal and triggers adaptive policies — session revocation, step-up auth, or Universal Logout — automatically.

  **OpenBox is the transmitter. Okta is the receiver. No changes are needed on Okta's end.**

  ```mermaid
  sequenceDiagram
      participant OB as OpenBox (Transmitter)
      participant JWKS as OpenBox JWKS Endpoint
      participant Okta as Okta (Receiver)
      participant Log as Okta System Log
      participant Risk as Okta Risk Engine

      Note over OB: Setup (one-time)
      OB->>JWKS: Host RSA public key at /.well-known/jwks.json
      OB->>Okta: POST /api/v1/security-events-providers<br/>(well-known URL or issuer + jwks_uri)
      Okta-->>OB: 200 OK { providerId }
      Okta->>JWKS: Fetch public key for verification

      Note over OB: Runtime — per signal
      OB->>OB: Detect risky agent behavior
      OB->>OB: Build SET JWT (iss, jti, iat, aud, event payload)
      OB->>OB: Sign SET with RSA private key (RS256)
      OB->>Okta: POST /security/api/v1/security-events<br/>(raw signed JWT)
      Okta->>JWKS: Verify JWT signature
      Okta-->>OB: 202 Accepted
      Okta->>Log: security.events.provider.receive_event
      Okta->>Risk: Evaluate risk signal
      Risk->>Log: user.risk.detect
      Risk->>Okta: Trigger policy (session revocation / step-up auth)
  ```

  Signals are [Security Event Tokens (SETs)](https://datatracker.ietf.org/doc/html/rfc8417) — JWTs signed with your RSA private key and delivered over HTTPS. Okta supports three event types from OpenBox: [user risk change](#user-risk-change), [session revoked](#caep-session-revoked), and [credential change](#caep-credential-change).
  ```

- [ ] **Step 3: Verify**

  - Mermaid block is syntactically valid (matches diagram from design spec exactly)
  - All 9 TOC anchors resolve to section headers in later tasks
  - No JWT or HTTP fundamentals explained

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add README skeleton and Overview section"
  git push
  ```

---

### Task 2: Prerequisites section

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 1 (append after Overview)
- Produces: Prerequisites section with 4 requirements

- [ ] **Step 1: Check spec coverage for Prerequisites**

  Requirements from spec:
  - Okta org with ITP enabled
  - Okta API token with security events provider permissions
  - Publicly accessible HTTPS host for JWKS
  - Optional host for `.well-known/ssf-configuration`

- [ ] **Step 2: Append Prerequisites section to README.md**

  ```markdown
  ---

  ## Prerequisites

  - **Okta org with Identity Threat Protection (ITP) enabled** — SSF receiver functionality requires ITP. Confirm under Security > Identity Threat Protection in the Okta Admin Console.
  - **Okta API token** with permission to manage security events providers. Generate one under Security > API > Tokens.
  - **Publicly accessible HTTPS host** for your JWKS endpoint (e.g., `https://your.openbox.instance/.well-known/jwks.json`). Okta fetches this during registration and to verify every incoming SET.
  - *(Optional but recommended)* **HTTPS host for `.well-known/ssf-configuration`** — enables SSF-compliant auto-discovery. Required for the SSF-compliant registration variant in Step 2.
  ```

- [ ] **Step 3: Verify**

  All 4 spec requirements present. No extra setup steps invented.

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Prerequisites section"
  git push
  ```

---

### Task 3: Quick Start section

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 2
- Produces: Complete 5-step Quick Start with working Python code, curl commands, and verification step

- [ ] **Step 1: Check spec coverage for Quick Start**

  Requirements from spec:
  - Generate RSA-2048 keypair + host JWKS
  - Optional `.well-known/ssf-configuration`
  - Register: `POST /api/v1/security-events-providers`
  - Build + sign a `user-risk-change` SET
  - Send: `POST /security/api/v1/security-events`
  - Verify in Okta System Log

- [ ] **Step 2: Append Quick Start section to README.md**

  ```markdown
  ---

  ## Quick Start

  Get a working transmitter in ~10 minutes.

  ### 1. Generate a keypair and build your JWKS

  Install dependencies:

  ```bash
  pip install cryptography PyJWT requests
  ```

  Run this script to generate an RSA-2048 keypair and print your JWKS:

  ```python
  # generate_keys.py
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives import serialization
  from cryptography.hazmat.backends import default_backend
  import base64, hashlib, json

  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend()
  )

  with open("private_key.pem", "wb") as f:
      f.write(private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.PKCS8,
          encryption_algorithm=serialization.NoEncryption()
      ))

  pub = private_key.public_key().public_numbers()

  def to_b64url(n: int) -> str:
      return base64.urlsafe_b64encode(
          n.to_bytes((n.bit_length() + 7) // 8, "big")
      ).rstrip(b"=").decode()

  n_b64 = to_b64url(pub.n)
  kid = hashlib.sha256(n_b64.encode()).hexdigest()[:16]

  jwks = {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256",
                    "kid": kid, "n": n_b64, "e": to_b64url(pub.e)}]}
  print(json.dumps(jwks, indent=2))
  # Copy the kid value — you'll need it when building SETs
  print(f"\nkid: {kid}")
  ```

  Host the printed JWKS JSON at `https://your.openbox.instance/.well-known/jwks.json` with `Content-Type: application/json`.

  ### 2. Register with Okta

  ```bash
  curl -X POST https://your-org.okta.com/api/v1/security-events-providers \
    -H "Authorization: SSWS <your-api-token>" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "OpenBox",
      "type": "SecurityEventsProvider",
      "settings": {
        "wellKnownUrl": "https://your.openbox.instance/.well-known/ssf-configuration"
      }
    }'
  ```

  Save the `id` field from the response — that's your `providerId`.

  ### 3. Build and sign a SET

  ```python
  # send_risk_change.py
  import jwt, uuid, time

  with open("private_key.pem", "rb") as f:
      private_key_pem = f.read()

  KID = "<kid from generate_keys.py>"
  ISSUER = "https://your.openbox.instance/"   # must match registered issuer exactly
  OKTA_ORG = "https://your-org.okta.com/"    # trailing slash required

  now = int(time.time())
  payload = {
      "iss": ISSUER,
      "jti": uuid.uuid4().hex,   # must be unique per SET — duplicates are silently dropped
      "iat": now,
      "aud": OKTA_ORG,
      "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
          "subject": {"user": {"format": "email", "email": "user@example.com"}},
          "event_timestamp": now,
          "previous_level": "low",
          "current_level": "high",
      }
  }

  token = jwt.encode(payload, private_key_pem, algorithm="RS256",
                     headers={"kid": KID, "typ": "secevent+jwt"})
  ```

  ### 4. Send the SET

  ```python
  import requests

  resp = requests.post(
      f"{OKTA_ORG}security/api/v1/security-events",
      data=token,
      headers={
          "Authorization": "SSWS <your-api-token>",
          "Content-Type": "application/secevent+jwt",
      }
  )
  print(resp.status_code)  # 202 = success
  ```

  ### 5. Verify in Okta System Log

  In the Okta Admin Console go to **Reports > System Log** and search for:

  - `security.events.provider.receive_event` — Okta received the SET
  - `user.risk.detect` — risk signal was processed by the risk engine
  ```

- [ ] **Step 3: Verify**

  - All 6 spec steps covered (well-known is referenced in Step 1, covered fully in Step 1 reference)
  - Python code is syntactically valid
  - `jti` uniqueness gotcha noted inline with `uuid.uuid4().hex`
  - `aud` has trailing slash in `OKTA_ORG`
  - `iss` comment says "must match registered issuer exactly"

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Quick Start section"
  git push
  ```

---

### Task 4: Step 1 reference — Keys & Endpoints

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 3
- Produces: Full reference for keypair generation, JWKS structure, and `.well-known/ssf-configuration`

- [ ] **Step 1: Check spec coverage**

  Requirements from spec:
  - RSA-2048, RS256 algorithm, SHA-256 kid
  - JWKS JSON structure (exact fields)
  - Optional `.well-known/ssf-configuration` with `issuer` + `jwks_uri`

- [ ] **Step 2: Append Step 1 reference section to README.md**

  ```markdown
  ---

  ## Step 1: Keys & Endpoints

  ### Keypair requirements

  | Parameter | Value |
  |-----------|-------|
  | Key type | RSA |
  | Key size | 2048 bits |
  | Algorithm | RS256 |
  | Key use | sig |
  | Key ID (`kid`) | SHA-256 of base64url-encoded modulus (first 16 hex chars) |

  The [Quick Start script](#1-generate-a-keypair-and-build-your-jwks) generates a compliant keypair. For production, generate keys in your secrets manager — never write the private key to disk unencrypted.

  ### JWKS endpoint

  Host the following JSON at a publicly accessible HTTPS URL (e.g. `https://your.openbox.instance/.well-known/jwks.json`) with `Content-Type: application/json`:

  ```json
  {
    "keys": [
      {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "<your-key-id>",
        "n": "<base64url-encoded-modulus>",
        "e": "AQAB"
      }
    ]
  }
  ```

  Okta fetches this URL during provider registration and on every incoming SET to verify the JWT signature. It must be publicly reachable without authentication.

  ### `.well-known/ssf-configuration` (optional)

  For SSF-compliant auto-discovery, host the following at `https://your.openbox.instance/.well-known/ssf-configuration`:

  ```json
  {
    "issuer": "https://your.openbox.instance/",
    "jwks_uri": "https://your.openbox.instance/.well-known/jwks.json"
  }
  ```

  If you host this, provide only `wellKnownUrl` during registration. If you skip it, provide `issuer` + `jwksUrl` directly (see [Step 2](#step-2-register-with-okta)).
  ```

- [ ] **Step 3: Verify**

  - JWKS JSON structure matches the format from the Okta developer guide
  - `.well-known` JSON fields match SSF spec (`issuer`, `jwks_uri`)
  - Table includes all 5 keypair parameters from spec

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Step 1 Keys and Endpoints reference section"
  git push
  ```

---

### Task 5: Step 2 reference — Register with Okta

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 4
- Produces: Full registration reference with both request variants, response schema, lifecycle endpoints, and link to Okta developer guide

- [ ] **Step 1: Check spec coverage**

  Requirements from spec:
  - SSF-compliant variant (well-known URL)
  - Non-SSF-compliant variant (issuer + JWKS URI)
  - Save `providerId`
  - Lifecycle endpoints: list, retrieve, update, deactivate, delete
  - Link to Okta developer guide

- [ ] **Step 2: Append Step 2 reference section to README.md**

  ```markdown
  ---

  ## Step 2: Register with Okta

  Register OpenBox as a security events provider so Okta knows your issuer and can verify SETs signed with your key.

  ### SSF-compliant (recommended)

  Use if you host `.well-known/ssf-configuration`:

  ```bash
  curl -X POST https://your-org.okta.com/api/v1/security-events-providers \
    -H "Authorization: SSWS <your-api-token>" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "OpenBox",
      "type": "SecurityEventsProvider",
      "settings": {
        "wellKnownUrl": "https://your.openbox.instance/.well-known/ssf-configuration"
      }
    }'
  ```

  ### Non-SSF-compliant

  Use if you're hosting JWKS directly without a well-known config:

  ```bash
  curl -X POST https://your-org.okta.com/api/v1/security-events-providers \
    -H "Authorization: SSWS <your-api-token>" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "OpenBox",
      "type": "SecurityEventsProvider",
      "settings": {
        "issuer": "https://your.openbox.instance/",
        "jwksUrl": "https://your.openbox.instance/.well-known/jwks.json"
      }
    }'
  ```

  ### Response

  ```json
  {
    "id": "sse0a4tsrkqfyFxBJ0g7",
    "name": "OpenBox",
    "type": "SecurityEventsProvider",
    "status": "ACTIVE",
    "settings": {
      "issuer": "https://your.openbox.instance/",
      "jwksUrl": "https://your.openbox.instance/.well-known/jwks.json"
    }
  }
  ```

  Save the `id` as your `providerId`.

  ### Lifecycle endpoints

  | Action | Request |
  |--------|---------|
  | List all providers | `GET /api/v1/security-events-providers` |
  | Retrieve | `GET /api/v1/security-events-providers/{providerId}` |
  | Update | `PUT /api/v1/security-events-providers/{providerId}` |
  | Deactivate | `POST /api/v1/security-events-providers/{providerId}/lifecycle/deactivate` |
  | Delete | `DELETE /api/v1/security-events-providers/{providerId}` |

  Full request/response schemas: [Configure an SSF receiver and publish a SET — Okta Developer](https://developer.okta.com/docs/guides/configure-ssf-receiver/main)
  ```

- [ ] **Step 3: Verify**

  - Both registration variants present with correct field names (`wellKnownUrl` vs `issuer`+`jwksUrl`)
  - Response example shows `id` prominently
  - All 5 lifecycle endpoints in table
  - Okta developer guide link is correct URL

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Step 2 Register with Okta reference section"
  git push
  ```

---

### Task 6: Step 3 reference — Event Reference

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 5
- Produces: Event reference covering all 3 event types with complete, valid SET payload JSON for each

- [ ] **Step 1: Check spec coverage**

  Requirements from spec:
  - Shared JWT header (all event types use the same header)
  - `user-risk-change`: iss, jti, iat, aud, subject (email format), event_timestamp, previous_level, current_level; risk levels low/medium/high
  - CAEP Session Revoked: subject (email format), reason_admin, event_timestamp
  - CAEP Credential Change: full table of credential_type + change_type combos (8 rows)

- [ ] **Step 2: Append Step 3 reference section to README.md**

  ```markdown
  ---

  ## Step 3: Event Reference

  All SETs share the same JWT header:

  ```json
  {
    "kid": "<your-key-id>",
    "typ": "secevent+jwt",
    "alg": "RS256"
  }
  ```

  ### user-risk-change

  OpenBox's primary signal. Send this when a user's risk level changes due to AI agent behavior.

  ```json
  {
    "iss": "https://your.openbox.instance/",
    "jti": "24c63fb56e5a2d77a6b512616ca9fa24",
    "iat": 1750980770,
    "aud": "https://your-org.okta.com/",
    "https://schemas.okta.com/secevent/okta/event-type/user-risk-change": {
      "subject": {
        "user": { "format": "email", "email": "user@example.com" }
      },
      "event_timestamp": 1750980770,
      "previous_level": "low",
      "current_level": "high"
    }
  }
  ```

  **Risk levels:** `low` | `medium` | `high`

  ### CAEP Session Revoked

  Send this when an active session should be terminated immediately.

  Use `format: "email"` if OpenBox identifies users by email (simplest). Use `format: "iss_sub"` if you have the Okta user ID (`sub`) available — replace `"iss"` with your Okta org URL and `"sub"` with the Okta user ID.

  ```json
  {
    "iss": "https://your.openbox.instance/",
    "jti": "9d3a8f2b1c4e567890abcdef12345678",
    "iat": 1750980770,
    "aud": "https://your-org.okta.com/",
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "subject": {
        "format": "email",
        "email": "user@example.com"
      },
      "reason_admin": { "en": "Risky agent activity detected by OpenBox" },
      "event_timestamp": 1750980770
    }
  }
  ```

  ### CAEP Credential Change

  Send this when a credential has been created, updated, revoked, or deleted.

  ```json
  {
    "iss": "https://your.openbox.instance/",
    "jti": "abc123def456789012345678abcdef01",
    "iat": 1750980770,
    "aud": "https://your-org.okta.com/",
    "https://schemas.openid.net/secevent/caep/event-type/credential-change": {
      "subject": {
        "format": "email",
        "email": "user@example.com"
      },
      "credential_type": "password",
      "change_type": "revoke",
      "event_timestamp": 1750980770
    }
  }
  ```

  **Supported `credential_type` + `change_type` combinations:**

  | `credential_type` | `change_type` | Triggered by |
  |---|---|---|
  | `fido2-roaming` | `create` | MFA factor activate |
  | `x509` | `delete` | MFA factor deactivate |
  | `ALL_FACTORS` | `revoke` | MFA factor reset all |
  | `OKTA_VERIFY_PUSH` | `update` | MFA factor suspend/unsuspend |
  | `phone-sms` | `update` | MFA factor update |
  | `DUO_SECURITY` | `update` | MFA factor update |
  | `password` | `revoke` | Password reset |
  | `password` | `update` | Password update |
  ```

- [ ] **Step 3: Verify**

  - All 3 event types present
  - `user-risk-change` uses `schemas.okta.com` namespace (Okta-specific)
  - CAEP events use `schemas.openid.net` namespace (standard CAEP)
  - All `jti` values in examples are unique (no repeats across tasks)
  - `aud` has trailing slash in all 3 examples
  - Credential change table has all 8 rows from spec

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Step 3 Event Reference section"
  git push
  ```

---

### Task 7: Step 4 reference — Sending SETs

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 6
- Produces: Sending SETs reference with endpoint, response codes table, silent failure gotchas, and Python helper

- [ ] **Step 1: Check spec coverage**

  Requirements from spec:
  - `POST /security/api/v1/security-events`
  - HTTP 202 = success
  - Silent failures: duplicate `jti`, unknown email, `iss` mismatch

- [ ] **Step 2: Append Step 4 reference section to README.md**

  ```markdown
  ---

  ## Step 4: Sending SETs

  ```bash
  POST /security/api/v1/security-events
  ```

  **Request:**

  ```bash
  curl -X POST https://your-org.okta.com/security/api/v1/security-events \
    -H "Authorization: SSWS <your-api-token>" \
    -H "Content-Type: application/secevent+jwt" \
    --data-raw "<signed-jwt>"
  ```

  **Response codes:**

  | Code | Meaning |
  |------|---------|
  | `202 Accepted` | SET received and queued for processing |
  | `400 Bad Request` | Malformed JWT or invalid claims |
  | `401 Unauthorized` | Invalid or missing API token |
  | `403 Forbidden` | Provider not registered or inactive |

  ### Silent failures

  Okta returns `202` in these cases but silently drops the SET without processing it:

  | Condition | What to do |
  |-----------|------------|
  | Duplicate `jti` | Generate a fresh `uuid.uuid4().hex` per SET — never reuse |
  | Unknown user email | `email` must match an active user in the Okta org |
  | `iss` mismatch | `iss` in the JWT must exactly match the `issuer` in your registered provider object |

  ### Python helper

  ```python
  import requests

  def send_set(token: str, okta_org: str, api_token: str) -> None:
      resp = requests.post(
          f"{okta_org.rstrip('/')}/security/api/v1/security-events",
          data=token,
          headers={
              "Authorization": f"SSWS {api_token}",
              "Content-Type": "application/secevent+jwt",
          }
      )
      resp.raise_for_status()  # raises on 4xx/5xx; 202 does not raise
  ```
  ```

- [ ] **Step 3: Verify**

  - All 3 silent failure conditions documented with actionable remediation
  - Response code table is complete (202, 400, 401, 403)
  - `raise_for_status()` correctly does not raise on 202

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Step 4 Sending SETs reference section"
  git push
  ```

---

### Task 8: Step 5 reference — Verifying in Okta

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 7
- Produces: Verification section with System Log event types and Entity Risk Policy setup steps

- [ ] **Step 1: Check spec coverage**

  Requirements from spec:
  - `security.events.provider.receive_event` and `user.risk.detect`
  - How to trigger a downstream risk policy

- [ ] **Step 2: Append Step 5 reference section to README.md**

  ```markdown
  ---

  ## Step 5: Verifying in Okta

  ### System Log

  After sending a SET, verify receipt in the Okta Admin Console under **Reports > System Log**.

  | Event | What it means |
  |-------|---------------|
  | `security.events.provider.receive_event` | Okta received and accepted the SET |
  | `user.risk.detect` | Risk signal was processed by the risk engine |

  Search by event type or filter by the target user's email to narrow results.

  ### Triggering a downstream policy

  Risk signals alone don't take action — you need an **Entity Risk Policy** in Okta to act on them.

  1. Go to **Security > Identity Threat Protection > Entity Risk Policy**
  2. Create or edit a policy rule
  3. Set the condition to trigger on risk level (e.g., when level reaches `high`)
  4. Choose an action: **Terminate all active sessions**, **Require re-authentication**, or **Universal Logout**

  Once configured, a `user-risk-change` SET with `current_level: "high"` will automatically trigger the policy for that user.

  See [Identity Threat Protection — Okta Help](https://help.okta.com/oie/en-us/content/topics/itp/shared-signals.htm) for full policy configuration docs.
  ```

- [ ] **Step 3: Verify**

  - Both System Log event types documented
  - Policy setup steps are 4 concrete numbered steps
  - Link to Okta ITP docs is correct

- [ ] **Step 4: Commit**

  ```bash
  git add README.md
  git commit -m "docs: add Step 5 Verifying in Okta reference section"
  git push
  ```

---

### Task 9: Production Hardening + References + link verification

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: `README.md` from Task 8
- Produces: Completed guide with Production Hardening section, References section, and all links verified

- [ ] **Step 1: Check spec coverage for Production Hardening**

  Requirements from spec:
  - Private key in secrets management (not on disk)
  - Key rotation strategy
  - `jti` uniqueness (UUID v4)
  - Retry logic for non-202 responses
  - Rate limiting considerations

- [ ] **Step 2: Append Production Hardening + References sections to README.md**

  ```markdown
  ---

  ## Production Hardening

  ### Private key management

  Never write the private key to disk unencrypted. Load it from your secrets manager at startup:

  ```python
  import os
  PRIVATE_KEY_PEM = os.environ["OPENBOX_OKTA_SSF_PRIVATE_KEY"].encode()
  KID = os.environ["OPENBOX_OKTA_SSF_KID"]
  ```

  ### Key rotation

  1. Generate a new keypair
  2. Add the new public key to your JWKS response (keep the old key — Okta may have cached it)
  3. Update your provider registration: `PUT /api/v1/security-events-providers/{providerId}`
  4. Start signing new SETs with the new key and `kid`
  5. After a few minutes, remove the old key from your JWKS response

  ### jti uniqueness

  Every SET must have a unique `jti`. Duplicates are silently dropped with no error. Always use `uuid.uuid4().hex` — never sequential IDs or timestamps alone.

  ### Retry logic

  On non-202 responses, retry with exponential backoff. Generate a new `jti` per attempt — never reuse:

  ```python
  import uuid, time, requests

  def send_with_retry(
      build_token_fn,   # callable(jti: str) -> str
      okta_org: str,
      api_token: str,
      max_attempts: int = 3
  ) -> None:
      for attempt in range(max_attempts):
          token = build_token_fn(jti=uuid.uuid4().hex)
          resp = requests.post(
              f"{okta_org.rstrip('/')}/security/api/v1/security-events",
              data=token,
              headers={
                  "Authorization": f"SSWS {api_token}",
                  "Content-Type": "application/secevent+jwt",
              }
          )
          if resp.status_code == 202:
              return
          if attempt < max_attempts - 1:
              time.sleep(2 ** attempt)
      resp.raise_for_status()
  ```

  ### Rate limiting

  Okta applies standard API rate limits to the security events endpoint. Monitor the `X-Rate-Limit-Remaining` response header and back off when it approaches zero. See [Okta API rate limits](https://developer.okta.com/docs/reference/rate-limits/) for current thresholds.

  ---

  ## References

  - [Configure an SSF receiver and publish a SET — Okta Developer](https://developer.okta.com/docs/guides/configure-ssf-receiver/main)
  - [SSF Transmitter SET payload structures — Okta Developer](https://developer.okta.com/docs/reference/ssf-transmitter-sets)
  - [Shared Signals — Okta Help Center](https://help.okta.com/oie/en-us/content/topics/itp/shared-signals.htm)
  - [Guide to Shared Signals](https://sharedsignals.guide)
  - [RFC 8417 — Security Event Token (SET)](https://datatracker.ietf.org/doc/html/rfc8417)
  ```

- [ ] **Step 3: Verify all reference links**

  ```bash
  for url in \
    "https://developer.okta.com/docs/guides/configure-ssf-receiver/main" \
    "https://developer.okta.com/docs/reference/ssf-transmitter-sets" \
    "https://help.okta.com/oie/en-us/content/topics/itp/shared-signals.htm" \
    "https://sharedsignals.guide" \
    "https://datatracker.ietf.org/doc/html/rfc8417" \
    "https://developer.okta.com/docs/reference/rate-limits/"; do
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    echo "$status  $url"
  done
  ```

  Expected: all return `200`, `301`, or `302`.

- [ ] **Step 4: Final commit and push**

  ```bash
  git add README.md
  git commit -m "docs: add Production Hardening and References — guide complete"
  git push
  ```
