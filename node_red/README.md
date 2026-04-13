# Node-RED Integration Files

This folder holds the Raspberry Pi side of the MFA prototype.

- `Read.py`: low-level RFID read script
- `write.py`: low-level RFID write script, optionally `python write.py "CARD-1001"`
- `fingerprint_api.py`: local Flask API for the fingerprint sensor

The top-level `Read.py`, `write.py`, and `fingerprint_api.py` files remain in place as compatibility launchers so existing Node-RED flows and shell commands do not break.
