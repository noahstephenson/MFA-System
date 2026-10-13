# MFA System

A tiered multi-factor authentication prototype built with Django, Node-RED, and a Raspberry Pi. A SysML model defines the three operating tiers. The prototype measures how their authentication factors, access scope, and audit behavior interact.

## Paper and presentation

*Model-Based Rapid Prototyping of Tiered MFA for Cyber-Physical Systems in Contested Environments*

Noah Stephenson and Matthew Wolfe, Department of Systems Engineering, United States Military Academy. MILCOM 2026, Workshop 3.

- [Paper (PDF)](docs/MILCOM_MFA_Camera_Ready.pdf)
- [Presentation (PDF)](docs/Stephenson_MILCOM2026_WS3.pdf)

## How it works

Django handles authentication, authorization, credentials, and audit records. Node-RED collects hardware factors through the Raspberry Pi scripts. PIN verification stays in Django.

| Tier | Required factors | Access scope |
|---|---|---|
| 1 | RFID + fingerprint | Standard protected access |
| 2 | RFID + PIN | Standard protected access |
| 3 | RFID + PIN | Resources approved for degraded operation |

Each resource can also require a minimum tier. The code uses the legacy values `basic`, `elevated`, and `high` for Tiers 1, 2, and 3 respectively. Tier 1 has the highest assurance; Tier 3 is the degraded mode.

## Run locally

Use Python 3.12 or later. From the repository root, create a virtual environment:

```bash
python -m venv .venv
```

Activate it with `.\.venv\Scripts\Activate.ps1` in Windows PowerShell or `source .venv/bin/activate` on Linux and macOS. Then run:

```bash
python -m pip install -r django_app/requirements.txt
cd django_app
python manage.py migrate
python manage.py runserver
```

Open [localhost:8000](http://localhost:8000/). Use `/app/enroll/` to enroll credentials and resources, then `/app/access/` to request access. RFID and fingerprint capture require the [Raspberry Pi and Node-RED setup](docs/setup.md).

## Tests and experiments

From `django_app/`, with the virtual environment active:

```bash
python manage.py test core
python manage.py run_experiments
```

Both commands run without hardware or Node-RED. The experiment harness uses a scratch database and writes [the results](docs/experiments/run_experiments_results.json).

In the main fixture, an adversary with a cloned RFID badge and a known PIN reaches 20 of 20 resources without a minimum-tier check. Requiring Tier 1 on ten resources reduces this to 10 of 20. Tier 3 limits access to five resources approved for degraded operation. The legitimate Tier 1 control reaches all twenty.

See [the experiment notes](docs/experiments.md) for the scenarios, audit failures, and measurement limits.

## Repository

| Path | Contents |
|---|---|
| [`django_app/`](django_app/) | Django application, policy logic, API, tests, and experiment command |
| [`node_red/`](node_red/) | Node-RED flow and Raspberry Pi sensor scripts |
| [`docs/`](docs/) | Paper, slides, setup instructions, and experiment notes |
| [`docs/local_reference/`](docs/local_reference/) | Cameo / MagicDraw SysML model archives, V4 current and V3 previous |

The root sensor scripts forward to their counterparts in `node_red/`. The [JSON API documentation](django_app/core/API.md) describes programmatic access requests.

## Limits

This is a research prototype. The experiments measure authorization decisions against database resources, with mocked sensor inputs and configured degradation. They do not establish operational security. The asserted tier is not checked against operating conditions, and a resource requiring assurance above Tier 3 cannot also be reached under degraded access. Requiring an audit record prevents unaudited approvals but denies all access when that record cannot be written.
