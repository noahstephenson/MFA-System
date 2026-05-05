# MFA System

A Django + Node-RED + Raspberry Pi prototype for studying tiered multi-factor authentication (MFA) architectures in cyber-physical systems. Built as part of an MBSE (Model-Based Systems Engineering) study — the SysML model is the authoritative source of truth for tier definitions and access logic. The code implements the model.

Users authenticate via RFID cards, fingerprints, and PINs to gain tiered access to protected resources such as doors, machines, or restricted functions.

---

## Authentication Tiers

The system implements three access tiers defined in the MBSE model. Tier 1 is the most complex normal operation; Tier 3 is a degraded fallback.

| Tier | Label | Required Factors | Notes |
|---|---|---|---|
| Tier 1 | BASIC | RFID + Fingerprint | Highest-complexity normal — possession + inherence |
| Tier 2 | ELEVATED | RFID + PIN | Standard protected access — possession + knowledge |
| Tier 3 | HIGH | RFID + PIN | Degraded mission-continuity — same factors as Tier 2 but restricted to resources pre-approved for degraded operation |

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

## Prerequisites

### Hardware

- Raspberry Pi (Pi 4 or Pi 5 recommended)
- MFRC522 RFID reader connected via SPI
- Adafruit optical fingerprint sensor connected via UART (`/dev/serial0`)

### Software

- Raspberry Pi OS Bookworm (64-bit recommended)
- Python 3.11 or later
- Node.js 18+ and npm (for Node-RED)
- Node-RED
- Git

---

## Installation

### Step 1 — Clone the repository

```bash
git clone https://github.com/noahstephenson/MFA-System.git
cd MFA-System
```

### Step 2 — Create a virtual environment and install dependencies

**On a Raspberry Pi (full stack — Django + RFID + fingerprint):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**On a non-Pi development machine (Django only — no hardware libraries):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r django_app/requirements.txt
```

### Step 3 — Apply database migrations

```bash
cd django_app
python manage.py migrate
```

This creates a local SQLite database at `django_app/db.sqlite3`. No external database is needed.

### Step 4 — Install Node-RED (Pi only)

```bash
npm install -g --unsafe-perm node-red
```

Start Node-RED in a separate terminal (it runs in the foreground):

```bash
node-red
```

Node-RED will be available at `http://127.0.0.1:1880`.

### Step 5 — Import the Node-RED flow (Pi only)

1. Open the Node-RED UI at `http://<PI_IP>:1880`.
2. Click the hamburger menu → **Import** → paste or upload `node_red/mvp_flows.json`.
3. Locate the `exec` nodes in the imported flow and update the following placeholders to match your Pi:
   - **Python interpreter path** — e.g. `/home/raspi/MFA-System/.venv/bin/python3`
   - **Repo root path** — e.g. `/home/raspi/MFA-System`
4. Click **Deploy**.

The flow exposes these HTTP endpoints that Django calls:

| Endpoint | Purpose |
|---|---|
| `POST /api/rfid/read` | Trigger an RFID card read |
| `POST /api/fingerprint/verify` | Verify a fingerprint against enrolled templates |
| `POST /api/fingerprint/enroll` | Enroll a new fingerprint |
| `POST /api/auth/collect-factors` | Combined flow — collect all required hardware factors |

### Step 6 — Start the Django server

From the `django_app/` directory (with your virtual environment active):

```bash
cd django_app
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,raspberrypi,<PI_IP> python manage.py runserver 0.0.0.0:8000
```

Replace `<PI_IP>` with your Pi's IP address (e.g. `192.168.1.42`).

### Step 7 — Use the system

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

---

## Hardware Commands (Pi only)

These scripts are run directly from the repo root:

```bash
# One-shot RFID read — prints JSON to stdout and exits
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
│       ├── models.py             ProtectedResource, AccessPolicy, Credential, AuthenticationSession, AuditEvent
│       ├── services.py           All authentication and authorization logic
│       ├── node_red_client.py    HTTP client to Node-RED; normalizes sensor payloads
│       ├── views.py              Web UI (home, enroll, access attempt, result)
│       ├── api_views.py          JSON API
│       ├── forms.py              Django forms
│       ├── urls.py               URL routing
│       ├── API.md                JSON API documentation
│       └── tests/                Test suite
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
