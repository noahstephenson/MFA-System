# MFA System

This repository has two code areas:

- `django_app/`: the Django application and API.
- `hardware/`: Raspberry Pi hardware scripts for RFID and fingerprint devices.

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

Recommended entry points:

```bash
python hardware/rfid_read.py
python hardware/rfid_write.py "CARD-1001"
python hardware/fingerprint_api.py
python django_app/manage.py runserver
```
