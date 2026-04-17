# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

A Django + Node-RED + Raspberry Pi MFA prototype built for an MBSE study of tiered authentication architectures in a cyber-physical systems context. Users authenticate via RFID cards, fingerprints, and PINs to gain tiered access to protected resources.

**Authoritative truth source: the MBSE/SysML model, not the current code.** If they disagree, the model wins.

## Commands

### Django (run from `django_app/`)

```bash
# Install dependencies (use this on non-Pi machines — no hardware libs)
pip install -r django_app/requirements.txt

# Apply migrations
python manage.py migrate

# Run the dev server
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost python manage.py runserver 0.0.0.0:8000

# Run all tests
python manage.py test core

# Run a specific test module
python manage.py test core.tests.test_services
```

### Hardware Scripts (run from repo root, Raspberry Pi only)

```bash
python node_red/Read.py --timeout 15         # Read an RFID card
python node_red/write.py "VALUE" --timeout 15 # Write to an RFID card
python node_red/fingerprint_api.py            # Start fingerprint Flask server (port 5000)
```

Root-level `Read.py`, `write.py`, and `fingerprint_api.py` are forwarding wrappers for the above.

## Architecture

### Two-Part System

```
[Browser / API client]
        ↓
[Django — django_app/]          ← policy engine, session mgmt, credentials, UI
        ↓ HTTP
[Node-RED — port 1880]          ← hardware orchestration (mvp_flows.json)
        ↓                ↓
  [Read.py]    [fingerprint_api.py — port 5000]
  RFID GPIO         Fingerprint UART sensor
```

### Django App Structure (`django_app/core/`)

| File | Role |
|---|---|
| `models.py` | Core data models (see below) |
| `services.py` | All authentication logic — the main orchestrator |
| `node_red_client.py` | HTTP client to Node-RED; normalizes inconsistent sensor payloads |
| `views.py` | HTML UI (home, access attempt form, result page, enrollment) |
| `api_views.py` | JSON API (`POST /api/access/start/`) |
| `urls.py` | URL routing |

### Key Models

- **`ProtectedResource`** — a physical asset (e.g., a door)
- **`AccessPolicy`** — ties a resource to a tier (BASIC / ELEVATED / HIGH)
- **`Credential`** — an enrolled factor for a user (RFID, PIN, BIOMETRIC)
- **`AuthenticationSession`** — one access attempt; holds status, decision, and factor details in `details` (JSONField)
- **`AuditEvent`** — immutable log entry per decision point

### Authentication Flow

1. User submits access attempt via form or `POST /api/access/start/`
2. `services.run_node_red_access_attempt()` creates a session and calls Node-RED
3. Node-RED runs `Read.py` (RFID) and calls the fingerprint API, then returns collected factors
4. `node_red_client.py` normalizes the response
5. Service layer evaluates each factor against enrolled `Credential` records
6. `_finalize_session()` writes `AuthenticationSession.status` (APPROVED/DENIED) and creates `AuditEvent` rows

### Tier Requirements (MBSE model is authoritative)

| Tier | Label | Architecture | Required Factors | Notes |
|---|---|---|---|---|
| Tier 1 | BASIC | Highest-complexity normal | Possession (RFID) + Inherence (fingerprint) | Strongest normal mode; verifies evidence before access |
| Tier 2 | ELEVATED | Moderate-complexity normal | Possession (RFID) + Knowledge (PIN) | Denies if any factor fails; supports enrollment |
| Tier 3 | HIGH | Degraded mission-continuity | Possession (RFID) + Knowledge (PIN) | Denies if factors fail OR requested function is not approved for degraded operation |

**Critical:** Earlier code, tests, and UI used a wrong mapping where Tier 3 was described as "RFID + PIN + degraded resource approval" and implied it was additive over Tier 2. Per the MBSE model, Tier 3 is a *degraded architecture* — same factor types as Tier 2 but restricted to a pre-approved subset of functions. Treat any code/test that implies Tier 3 is a superset of Tier 2 as implementation drift.

Logic lives in `tier_requirement_definition()` in `services.py`.

## Environment Variables

```bash
# Django
DJANGO_ALLOWED_HOSTS       # Comma-separated (default: 127.0.0.1,localhost,testserver)
MFA_API_SHARED_SECRET      # Enables X-API-Key auth on JSON endpoints
MFA_API_VERSION            # API version string (default: prototype-v1)

# Node-RED integration
NODE_RED_BASE_URL          # Default: http://127.0.0.1:1880
NODE_RED_TIMEOUT           # Seconds (default: 60)
NODE_RED_SHARED_SECRET     # Enables X-API-Key header on Node-RED calls

# Fingerprint sensor (Pi only)
FINGERPRINT_SERIAL_PORT    # Default: /dev/serial0
FINGERPRINT_BAUDRATE       # Default: 57600
FINGERPRINT_API_PORT       # Default: 5000
```

## Architectural Constraints (enforce always)

- **Django** owns: tier logic, authentication/authorization decisions, persistence, audit, UI, and API. Must not talk directly to hardware.
- **Node-RED** owns: hardware factor collection and orchestration over HTTP. Must not make final access decisions.
- **Pi scripts** own: direct RFID/fingerprint hardware access only.
- **Enrollment**: RFID and fingerprint enrollment must be capture-driven via Node-RED — never revert to plain text entry for those credential types. PIN is manual entry.
- **Auth vs authorization**: keep these separated in code. Authentication = did the factors verify? Authorization = is access granted for this resource/tier?

## Current State (as of 2026-04-17)

- Django side is locally mature: 98 passing tests, preflight passed, local enroll/access rehearsal against fake Node-RED succeeded.
- Biggest remaining risks: live Pi integration-boundary issues and tier-semantics drift in code/UI.
- **Next task**: reconcile code, tests, and UI with corrected tier semantics so Tier 1 = highest-complexity normal, Tier 2 = simplified normal, Tier 3 = degraded mission continuity.

## How to Work on This Project

**The system is working. Do not break it. Make the smallest change that solves the problem.**

- Read actual files before proposing any change.
- One narrow fix at a time — no broad rewrites, no refactoring beyond what was asked.
- Preserve the Django/Node-RED/Pi architecture split.
- Preserve the authentication vs. authorization separation in `services.py`.
- Explicitly distinguish local readiness from live Pi readiness when reporting status.
- Trust the MBSE model over current implementation when they conflict.
- Trust rendered UI and live routes over summaries when checking behavior.
- If a fix touches tests, only change the tests that are directly wrong — do not reorganize or clean up surrounding tests.

## Database

SQLite3 at `django_app/db.sqlite3`. No external database needed for development.

## Tests

Tests live in `django_app/core/tests/` and are split by concern:
- `test_api.py` — JSON endpoint contracts
- `test_models.py` — model logic and credential matching
- `test_services.py` — factor evaluation and authorization
- `test_node_red_client.py` — payload normalization from hardware
- `test_views.py` — HTML form flows and enrollment
