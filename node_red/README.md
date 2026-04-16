# Node-RED Integration Files

This folder holds the Raspberry Pi side of the MFA prototype.

- `Read.py`: one-shot RFID read script. It prints exactly one JSON object to stdout and exits.
- `write.py`: one-shot RFID write script. It prints exactly one JSON object to stdout and exits.
- `fingerprint_sensor.py`: shared fingerprint hardware logic used by both the CLI and Flask entry points.
- `fingerprint_verify.py`: one-shot fingerprint verification script for Node-RED `exec` nodes.
- `fingerprint_enroll.py`: one-shot fingerprint enrollment script for Node-RED `exec` nodes.
- `fingerprint_api.py`: optional local Flask service for compatibility and manual sensor operations.
- `mvp_flows.json`: importable Node-RED flow export for the MVP Pi-side HTTP endpoints.

Recommended MVP execution path:

- Node-RED calls `Read.py` directly for RFID reads.
- Node-RED calls `fingerprint_verify.py` directly for fingerprint verification.
- Node-RED calls `fingerprint_enroll.py` directly for fingerprint enrollment.
- Node-RED exposes the local HTTP endpoints Django already expects:
  - `POST /api/rfid/read`
  - `POST /api/fingerprint/verify`
  - `POST /api/fingerprint/enroll`
  - `POST /api/auth/collect-factors`

Current combined-flow behavior:

- `allowed_factor_types` is honored for hardware factors only.
- `rfid` requests trigger the RFID read endpoint.
- `biometric` or `fingerprint` requests trigger fingerprint verification.
- `pin` is intentionally ignored by Node-RED because PIN remains Django-side knowledge-factor logic.
- If `allowed_factor_types` is omitted, the combined flow collects both RFID and fingerprint.

The top-level `Read.py`, `write.py`, and `fingerprint_api.py` files remain in place as compatibility launchers so existing shell commands do not break.

Useful Pi-side commands:

```bash
python3 node_red/Read.py --timeout 10
python3 node_red/write.py "CARD-1001" --timeout 15
python3 node_red/fingerprint_verify.py --timeout 10
python3 node_red/fingerprint_enroll.py --id 7 --timeout 30
python3 node_red/fingerprint_api.py
```

After importing `mvp_flows.json` into Node-RED, edit these placeholders before deploying:

- `/usr/bin/python3`
- `/home/pi/MFA-System`
- `http://127.0.0.1:1880`

If your Pi repo checkout lives somewhere else, update the `exec` node append arguments so they point at the real script paths in this repo.
