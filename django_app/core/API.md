# Core Access API

This Django MVP exposes one active JSON endpoint. Django remains the decision
maker and system of record; Node-RED only collects the Pi-side factors and
returns normalized JSON.

## Endpoint

### `POST /api/access/start/`

Start a new access attempt, call the combined Node-RED factor collection
endpoint, evaluate the returned RFID and fingerprint values against the enrolled
credentials for the selected user, and persist the result.

Example request:

```json
{
  "user_id": 4,
  "tier": "elevated"
}
```

Notes:
- `user_id` is required.
- `tier` is required.
- Django resolves the one active demo policy configured for the selected tier.
- `policy_id` is optional. If supplied, it must still match the selected tier.
- If `MFA_API_SHARED_SECRET` is configured, callers must send `X-API-Key`.

## Response Shape

Successful responses use this envelope:

```json
{
  "ok": true,
  "message": "Authentication requirements satisfied. Access granted.",
  "data": {
    "session": {
      "id": 12,
      "user": "operator",
      "tier": "elevated",
      "policy": "Elevated Access",
      "status": "approved",
      "decision": "granted",
      "required_factor_count": 2,
      "accepted_factor_count": 2,
      "remaining_factor_count": 0,
      "submitted_factors": [],
      "is_complete": true,
      "is_access_granted": true,
      "factor_collection_result": {},
      "result_url": "http://127.0.0.1:8000/app/access/result/12/"
    },
    "node_red": {
      "ok": true,
      "error": "",
      "message": ""
    }
  }
}
```

Validation and auth failures use this envelope:

```json
{
  "ok": false,
  "message": "Request validation failed.",
  "errors": {
    "field_name": ["Error message."]
  }
}
```
