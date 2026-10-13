# Setup

The local Django setup is in the [README](../README.md). This page covers the hardware connection and configuration.

## Raspberry Pi

The prototype uses a Raspberry Pi with an MFRC522 RFID reader over SPI and an Adafruit optical fingerprint sensor over UART. Enable the interfaces used by the sensors. The fingerprint scripts default to `/dev/serial0` at 57600 baud.

Use Python 3.12 or later. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python django_app/manage.py migrate
```

The root `requirements.txt` installs both Django and the hardware libraries. The separate `django_app/requirements.txt` is sufficient for tests and experiments on a machine without sensors.

## Node-RED

Install Node-RED on the Pi and start it in a separate terminal:

```bash
npm install -g --unsafe-perm node-red
node-red
```

1. Open `http://<PI_IP>:1880`.
2. Import [`node_red/mvp_flows.json`](../node_red/mvp_flows.json).
3. Update the `exec` nodes to use the virtual environment Python interpreter and the actual repository path. The flow contains `/usr/bin/python3` and `/home/pi/MFA-System` placeholders.
4. Check the local HTTP URLs, then deploy the flow.

The flow exposes the endpoints Django calls:

| Endpoint | Purpose |
|---|---|
| `POST /api/rfid/read` | Read an RFID card |
| `POST /api/fingerprint/verify` | Verify a fingerprint |
| `POST /api/fingerprint/enroll` | Enroll a fingerprint |
| `POST /api/auth/collect-factors` | Collect the requested hardware factors |

Node-RED runs the sensor scripts directly. It does not make access decisions. The optional fingerprint Flask server is available for manual sensor operations and compatibility with older integrations; the imported flow does not require it.

See [`node_red/README.md`](../node_red/README.md) for the flow behavior.

## Start Django on the Pi

From the repository root, with the virtual environment active:

```bash
DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost,raspberrypi,<PI_IP>" python django_app/manage.py runserver 0.0.0.0:8000
```

Replace `<PI_IP>` with the Pi address. Open `http://<PI_IP>:8000/app/enroll/` to enroll credentials and protected resources. Open `/app/access/` to submit an access attempt. SQLite stores the local data in `django_app/db.sqlite3`.

## Configuration

Set environment variables in the terminal that starts Django or the sensor process.

| Variable | Default | Purpose |
|---|---|---|
| `DJANGO_ALLOWED_HOSTS` | `127.0.0.1,localhost,testserver,0.0.0.0` | Allowed Django hostnames, separated by commas |
| `MFA_API_SHARED_SECRET` | Unset | Require `X-API-Key` on Django JSON API requests |
| `NODE_RED_BASE_URL` | `http://127.0.0.1:1880` | Node-RED address |
| `NODE_RED_TIMEOUT` | `60` | Node-RED request timeout in seconds |
| `NODE_RED_SHARED_SECRET` | Unset | Send `X-API-Key` with requests to Node-RED |
| `FINGERPRINT_SERIAL_PORT` | `/dev/serial0` | Fingerprint sensor serial port |
| `FINGERPRINT_BAUDRATE` | `57600` | Sensor baud rate |
| `FINGERPRINT_API_PORT` | `5000` | Optional fingerprint Flask server port |

The Django API version is the `MFA_API_VERSION` setting in `django_app/mfa_project/settings.py`, currently `prototype-v1`.

## Sensor commands

Run these from the repository root on the Pi:

```bash
python node_red/Read.py --timeout 10
python node_red/write.py "CARD-1001" --timeout 15
python node_red/fingerprint_verify.py --timeout 10
python node_red/fingerprint_enroll.py --id 1 --timeout 30
python node_red/fingerprint_api.py
```

The read, write, verify, and enroll commands each print one JSON object and exit. The final command starts the optional Flask server.
