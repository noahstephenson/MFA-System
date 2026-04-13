# MFA System

This repository has two code areas:

- `django_app/`: the Django application and API.
- `node_red/`: Raspberry Pi and Node-RED-side RFID and fingerprint scripts.

Compatibility wrappers remain at the repository root for the original Pi commands:

- `python Read.py`
- `python write.py`
- `python fingerprint_api.py`

Recommended setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you only want the Django app on a non-Pi machine, install from `django_app/requirements.txt` instead so you do not pull Raspberry Pi hardware packages.

Recommended entry points:

```bash
python node_red/Read.py
python node_red/write.py "CARD-1001"
python node_red/fingerprint_api.py
python django_app/manage.py runserver
```
