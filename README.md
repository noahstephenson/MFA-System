# MFA System

**Author:** Noah Stephenson

A Django + Node-RED + Raspberry Pi prototype for studying tiered multi-factor authentication (MFA) architectures in cyber-physical systems. Built as part of an MBSE (Model-Based Systems Engineering) study, the SysML model is the authoritative source of truth for tier definitions and access logic, and the code implements it. The repository also includes a reproducible experiment harness; see [Reproducible Experiments](#reproducible-experiments).

Users authenticate via RFID cards, fingerprints, and PINs to gain tiered access to protected resources such as doors, machines, or restricted functions.

---

## Authentication Tiers

The system implements three access tiers defined in the MBSE model. Tier 1 is the most complex normal operation; Tier 3 is a degraded fallback.

| Tier | Label | Required Factors | Notes |
|---|---|---|---|
| Tier 1 | BASIC | RFID + Fingerprint | Highest-complexity normal, possession + inherence |
| Tier 2 | ELEVATED | RFID + PIN | Standard protected access, possession + knowledge |
| Tier 3 | HIGH | RFID + PIN | Degraded mission-continuity, same factors as Tier 2 but restricted to resources pre-approved for degraded operation |

> **Tier numbering and internal labels.** Tier 1 is the highest-assurance tier and Tier 3 is the degraded tier. The internal identifiers `BASIC`, `ELEVATED`, and `HIGH` (stored as `basic`, `elevated`, and `high`, and used by the JSON API) are legacy labels and do not describe assurance: `BASIC` is the strongest tier and `HIGH` is the degraded one. Assurance ranks are defined in `TIER_ASSURANCE_RANK` in [`django_app/core/models.py`](django_app/core/models.py) (`HIGH` = 0, `ELEVATED` = 1, `BASIC` = 2).

---

## System Architecture

```
Browser / API client
        |
   Django (port 8000)        policy engine, session management,
        |                    credentials, audit log, UI, JSON API
        | HTTP
  Node-RED (port 1880)       hardware orchestration only;
        |           |        makes no access decisions
    Read.py   fingerprint_api.py
    RFID GPIO  Fingerprint UART
```

**Django** owns all policy decisions, authentication logic, persistence, and the web UI. It never talks to hardware directly.

**Node-RED** receives a factor-collection request from Django, runs the Pi-side scripts, and returns normalized JSON. It has no decision-making authority.

**Pi scripts** (`node_red/Read.py`, `node_red/fingerprint_*.py`) own direct sensor access only.

---

## SysML Model

The SysML model is the source of truth for tier definitions and access logic. The model archives are Cameo Systems Modeler / MagicDraw project files in `docs/local_reference/`:

| File | Status |
|---|---|
| `Tiered_MFA_MBSE_Definitive_Version_V4.mdzip` | Current model |
| `Tiered_MFA_MBSE_Definitive_Version_V3.mdzip` | Previous version, kept for history |

The current archive predates the `minimum_tier` field on `ProtectedResource`, which exists in code only.

---

## Prerequisites

### Hardware

- Raspberry Pi (Pi 4 or Pi 5 recommended)
- MFRC522 RFID reader connected via SPI
- Adafruit optical fingerprint sensor connected via UART (`/dev/serial0`)

### Software

- Raspberry Pi OS Bookworm (64-bit recommended)
- Python 3.12 or later (required by Django 6.0.3)
- Node.js 18+ and npm (for Node-RED)
- Node-RED
- Git

---

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/noahstephenson/MFA-System.git
cd MFA-System
```

### Step 2: Create a virtual environment and install dependencies

**On a Raspberry Pi (full stack, Django + RFID + fingerprint):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**On a non-Pi development machine (Django only, no hardware libraries):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r django_app/requirements.txt
```

### Step 3: Apply database migrations

```bash
cd django_app
python manage.py migrate
```

This creates a local SQLite database at `django_app/db.sqlite3`. No external database is needed.

### Step 4: Install Node-RED (Pi only)

```bash
npm install -g --unsafe-perm node-red
```

Start Node-RED in a separate terminal (it runs in the foreground):

```bash
node-red
```

Node-RED will be available at `http://127.0.0.1:1880`.

### Step 5: Import the Node-RED flow (Pi only)

1. Open the Node-RED UI at `http://<PI_IP>:1880`.
2. Click the hamburger menu → **Import** → paste or upload `node_red/mvp_flows.json`.
3. Locate the `exec` nodes in the imported flow and update the following placeholders to match your Pi:
   - **Python interpreter path**, e.g. `/home/raspi/MFA-System/.venv/bin/python3`
   - **Repo root path**, e.g. `/home/raspi/MFA-System`
4. Click **Deploy**.

The flow exposes these HTTP endpoints that Django calls:

| Endpoint | Purpose |
|---|---|
| `POST /api/rfid/read` | Trigger an RFID card read |
| `POST /api/fingerprint/verify` | Verify a fingerprint against enrolled templates |
| `POST /api/fingerprint/enroll` | Enroll a new fingerprint |
| `POST /api/auth/collect-factors` | Combined flow, collect all required hardware factors |

### Step 6: Start the Django server

From the `django_app/` directory (with your virtual environment active):

```bash
cd django_app
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,raspberrypi,<PI_IP> python manage.py runserver 0.0.0.0:8000
```

Replace `<PI_IP>` with your Pi's IP address (e.g. `192.168.1.42`).

### Step 7: Use the system

| URL | Purpose |
|---|---|
| `http://<PI_IP>:8000/` | Home page |
| `http://<PI_IP>:8000/app/enroll/` | Enroll user credentials and protected resources |
| `http://<PI_IP>:8000/app/access/` | Submit an access attempt |

Start by enrolling a subject (user credentials) and a protected resource with an authentication tier on the enroll page, then submit an access attempt.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost,testserver` | Comma-separated list of allowed hostnames |
| `MFA_API_SHARED_SECRET` | *(unset)* | If set, JSON API callers must send `X-API-Key: <secret>` |
| `MFA_API_VERSION` | `prototype-v1` | API version string returned in responses |
| `NODE_RED_BASE_URL` | `http://127.0.0.1:1880` | Base URL for Node-RED HTTP endpoints |
| `NODE_RED_TIMEOUT` | `60` | Seconds before Django times out a Node-RED request |
| `NODE_RED_SHARED_SECRET` | *(unset)* | If set, Django sends `X-API-Key` on all Node-RED calls |
| `FINGERPRINT_SERIAL_PORT` | `/dev/serial0` | Serial port for the fingerprint sensor |
| `FINGERPRINT_BAUDRATE` | `57600` | Baud rate for the fingerprint sensor |
| `FINGERPRINT_API_PORT` | `5000` | Port for the optional fingerprint Flask server |

### Experiment Flags

These are Django settings in `django_app/mfa_project/settings.py`, not environment variables. The defaults are the intended behavior; the non-default values exist only to reproduce earlier behavior for measurement.

| Setting | Default | Effect |
|---|---|---|
| `SCOPE_MONOTONICITY_ENABLED` | `True` | Denies access when the asserted tier ranks below the resource's `minimum_tier`. |
| `FAIL_CLOSED_AUDIT_ENABLED` | `True` | An approved decision stands only if its `access_granted` audit event is written; otherwise the session is changed to denied. `False` restores the earlier fail-open behavior. |
| `AUDIT_SINK_AVAILABLE` | `True` | Test hook. `False` makes every audit write raise, simulating an unreachable audit sink. |

---

## Hardware Commands (Pi only)

These scripts are run directly from the repo root:

```bash
# One-shot RFID read: prints JSON to stdout and exits
python3 node_red/Read.py --timeout 10

# Write a value to an RFID card
python3 node_red/write.py "CARD-1001" --timeout 15

# One-shot fingerprint verification
python3 node_red/fingerprint_verify.py --timeout 10

# Enroll a fingerprint into slot 1
python3 node_red/fingerprint_enroll.py --id 1 --timeout 30

# Start the optional fingerprint Flask server (port 5000)
python3 node_red/fingerprint_api.py
```

The root-level `Read.py`, `write.py`, and `fingerprint_api.py` files are compatibility wrappers that forward to the above.

---

## Running Tests

Tests cover the Django layer only. No hardware or Node-RED connection is needed.

```bash
cd django_app
python manage.py test core
```

Tests are split by concern:

| File | Covers |
|---|---|
| `core/tests/test_models.py` | Model logic and credential matching |
| `core/tests/test_services.py` | Factor evaluation and authorization |
| `core/tests/test_views.py` | HTML form flows and enrollment |
| `core/tests/test_api.py` | JSON endpoint contracts |
| `core/tests/test_node_red_client.py` | Payload normalization from hardware |

---

## Reproducible Experiments

`django_app/core/management/commands/run_experiments.py` measures how far a possession-and-knowledge adversary gets under each tier, and whether access decisions stay accountable when the audit sink fails.

### Running it

From `django_app/` with the virtual environment active:

```bash
python manage.py run_experiments
```

It prints its tables and rewrites `docs/experiments/run_experiments_results.json`. No hardware, Node-RED instance, or network access is needed.

### Isolation

- The fixture is seeded into a scratch test database created with `create_test_db` and destroyed afterward. `db.sqlite3` is never read or written.
- Each attempt runs the same service-layer path a normal access request takes (`run_node_red_access_attempt`). Only the Node-RED boundary (`core.services.node_red_client.collect_factors`) is mocked, plus `core.services.create_audit_event` for the mid-flow failure measurement.
- Behavior is varied only through the experiment flags above, using `override_settings`.

### Fixture

- 20 protected resources. The last 5 allow degraded access. In the main fixture, the first 10 carry `minimum_tier = BASIC`, so they require Tier 1. The two sets are kept disjoint on purpose: if they overlapped, Tier 3 would reach nothing by construction and S3 would say nothing about degraded-scope containment.
- Every resource has an active policy for each of the three tiers.
- Two subjects. The adversary holds a cloned RFID badge and a known PIN, with no fingerprint enrolled. The legitimate subject holds RFID, PIN, and fingerprint.

### Scenarios

| Key | Subject | Asserted tier | Scope check | Purpose |
|---|---|---|---|---|
| S1 | adversary | Tier 2 | off | Baseline without the per-resource minimum tier check |
| S2 | adversary | Tier 2 | on | Containment by `minimum_tier` |
| S3 | adversary | Tier 3 | on | Degraded-scope containment |
| S4 | legitimate | Tier 1 | on | Control: valid access must survive, with 10 of 20 resources requiring Tier 1 |

### What it measures

1. **Sink outage matrix:** every scenario across `AUDIT_SINK_AVAILABLE` and `FAIL_CLOSED_AUDIT_ENABLED`. A sink that is down from the start blocks session creation, so no decision is ever made.
2. **Mid-flow sink failure:** `session_started` is written, then every later audit write fails. This is the case that can leave an access decision unrecorded.
3. **Minimum tier coverage sweep:** S2 with 0, 5, 10, 15, and 20 resources requiring Tier 1.
4. **Structural scope overlap:** ratios read directly off the policy configuration, for the default configuration and the main fixture.

### Results

Resources reached (of 20), audit sink available, fail-closed on:

| S1 | S2 | S3 | S4 |
|---|---|---|---|
| 20 | 10 | 5 | 20 |

Approved decisions left without a decision audit record, under mid-flow sink failure:

| Scenario | Fail-closed off | Fail-closed on |
|---|---|---|
| S1 | 20 | 0 |
| S2 | 10 | 0 |
| S3 | 5 | 0 |
| S4 | 20 | 0 |

With fail-closed off, Tiers 1 and 2 persist the approval and then raise on the audit write, while Tier 3 swallows the failure. With fail-closed on, no scenario reaches any resource while the sink is failing, including the legitimate control.

Minimum tier coverage sweep (S2):

| Resources requiring Tier 1 | 0 | 5 | 10 | 15 | 20 |
|---|---|---|---|---|---|
| Resources reached | 20 | 15 | 10 | 5 | 0 |

### Checking reproducibility

The committed results file regenerates byte-for-byte on Linux and Windows with Python 3.12 or later and Django 6.0.3.

To check on your machine, from `django_app/`:

```bash
python manage.py run_experiments
git diff --stat -- ../docs/experiments/run_experiments_results.json
```

Empty output means the regenerated file matches the committed one. To restore the committed copy afterward:

```bash
git checkout -- ../docs/experiments/run_experiments_results.json
```

---

## Known Limitations

- **The asserted tier is not bound to operating conditions.** The tier arrives with the access request and is checked only for being one of the three defined tiers. Nothing compares it against an observed or reported condition, so a subject holding RFID and PIN can assert Tier 2 instead of Tier 3 and receive standard scope rather than the degraded subset.
- **The accountability guarantee is narrow.** With `FAIL_CLOSED_AUDIT_ENABLED` on, no access decision persists as approved without a durable record of that decision. Denials, `session_started`, and the factor collection, authentication, and authorization events are best-effort and are lost when the sink is down.
- **Accountability costs availability.** With the audit sink down and fail-closed on, every request is denied, including a legitimate Tier 1 subject holding all three factors. Anyone who can disrupt the audit path can deny access without touching authentication.
- **Minimum assurance and degraded access conflict.** A resource whose `minimum_tier` is above Tier 3 cannot be reached in Tier 3, whatever its `allow_degraded_access` flag says, so a resource cannot be both high-assurance and reachable under degraded operation.
- **Prototype scope.** Protected resources are database records, not operational endpoints, so results describe the authorization decision rather than enforcement downstream of it. Degraded operation is set by configuration, not by physically denying a sensor or link. The system has not had a formal security assessment.

---

## JSON API

A JSON API endpoint is available for programmatic access attempts:

```
POST /api/access/start/
```

Example request body:

```json
{
  "resource_id": 3,
  "user_id": 4,
  "tier": "elevated",
  "knowledge_factor": "12345678"
}
```

See [`django_app/core/API.md`](django_app/core/API.md) for the full request/response specification.

---

## Repository Structure

```
MFA-System/
├── requirements.txt              Full Pi stack (Django + hardware libs)
├── Read.py                       Compatibility wrapper → node_red/Read.py
├── write.py                      Compatibility wrapper → node_red/write.py
├── fingerprint_api.py            Compatibility wrapper → node_red/fingerprint_api.py
│
├── django_app/
│   ├── requirements.txt          Django-only deps (no hardware libs)
│   ├── manage.py
│   └── core/
│       ├── models.py             ProtectedResource (incl. minimum_tier), AccessPolicy, Credential, AuthenticationSession, AuditEvent
│       ├── services.py           All authentication and authorization logic
│       ├── node_red_client.py    HTTP client to Node-RED; normalizes sensor payloads
│       ├── views.py              Web UI (home, enroll, access attempt, result)
│       ├── api_views.py          JSON API
│       ├── forms.py              Django forms
│       ├── urls.py               URL routing
│       ├── API.md                JSON API documentation
│       ├── management/commands/run_experiments.py   Reproducible experiment harness
│       └── tests/                Test suite
│
├── docs/
│   ├── experiments/
│   │   └── run_experiments_results.json   Committed results artifact from run_experiments
│   └── local_reference/
│       └── *.mdzip                       SysML model archives
│
└── node_red/
    ├── mvp_flows.json            Importable Node-RED flow
    ├── Read.py                   RFID read script
    ├── write.py                  RFID write script
    ├── fingerprint_api.py        Fingerprint Flask server
    ├── fingerprint_sensor.py     Shared sensor driver
    ├── fingerprint_verify.py     One-shot fingerprint verification
    └── fingerprint_enroll.py     One-shot fingerprint enrollment
```

`ProtectedResource.minimum_tier` was added in migration 0008; it is the field the scope-monotonicity behavior depends on.
