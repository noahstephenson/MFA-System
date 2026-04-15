# MFA System

This repository has two code areas:

- `django_app/`: the Django application and API.
- `node_red/`: Raspberry Pi and Node-RED-side RFID and fingerprint scripts.

Compatibility wrappers remain at the repository root for the original Pi commands:

- `python Read.py`
- `python write.py`
- `python fingerprint_api.py`

Recommended setup on the Raspberry Pi for the full MVP stack:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd django_app
python manage.py migrate
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,testserver,raspberrypi,<PI_IP> python manage.py runserver 0.0.0.0:8000
```

Why the root install matters:

- `requirements.txt` now includes both the Django app requirements and the Pi hardware packages.
- Use the root file on the Pi when you want the full stack.
- If you only want Django on a non-Pi machine, install from `django_app/requirements.txt` instead so you do not pull Raspberry Pi hardware packages.

Recommended entry points:

```bash
python node_red/Read.py
python node_red/write.py "CARD-1001"
python node_red/fingerprint_api.py
python django_app/manage.py migrate
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost,testserver,raspberrypi,<PI_IP> python django_app/manage.py runserver 0.0.0.0:8000
```
