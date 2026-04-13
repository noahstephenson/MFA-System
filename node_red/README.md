# Node-RED Integration Files

This folder holds the Raspberry Pi side of the MFA prototype.

- `pi_drivers/rfid_read.py`: low-level RFID read script
- `pi_drivers/rfid_write.py`: low-level RFID write script
- `pi_drivers/fingerprint_service.py`: local Flask API for the fingerprint sensor

The top-level `Read.py`, `write.py`, and `fingerprint_api.py` files remain in place as compatibility launchers so existing Node-RED flows and shell commands do not break.
