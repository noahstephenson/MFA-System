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
  "resource_id": 1,
  "user_id": 4,
  "policy_id": 2
}
```

Notes:
- `resource_id` is required.
- `user_id` is required.
- `policy_id` is optional. If omitted, Django uses the resource's first active
  policy ordered by `id`.
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
      "resource": "Main Lab Door",
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
