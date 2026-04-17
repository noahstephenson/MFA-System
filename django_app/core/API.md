# Core Access API

This Django MVP exposes one active JSON endpoint. Django remains the decision
maker and system of record; Node-RED only collects the Pi-side factors and
returns normalized JSON.

## Endpoint

### `POST /api/access/start/`

Start a new access attempt, call the combined Node-RED factor collection
endpoint, evaluate the returned RFID and fingerprint values against the enrolled
credentials for the selected user, verify the Django-side knowledge factor when
the selected tier requires it, then authorize the requested resource and persist
the result.

Example request:

```json
{
  "resource_id": 3,
  "user_id": 4,
  "tier": "elevated",
  "knowledge_factor": "12345678"
}
```

Notes:
- `resource_id` is required.
- `user_id` is required.
- `tier` is required.
- `knowledge_factor` is required for Tier 2 and Tier 3.
- Django resolves the one active demo policy configured for the selected resource and tier.
- Tier 1 requires RFID + fingerprint.
- Tier 2 requires RFID + knowledge factor.
- Tier 3 requires RFID + knowledge factor, then Django must confirm the resource is approved for degraded access.
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
      "tier": "elevated",
      "policy": "Elevated Access",
      "status": "approved",
      "decision": "granted",
      "required_factor_count": 2,
      "required_factor_types": ["rfid", "pin"],
      "accepted_factor_count": 2,
      "remaining_factor_count": 0,
      "submitted_factors": [],
      "is_complete": true,
      "is_access_granted": true,
      "factor_collection_result": {},
      "authentication": {
        "ok": true,
        "tier": "elevated",
        "required_factor_types": ["rfid", "pin"],
        "verified_factor_types": ["rfid", "pin"],
        "message": "Authentication evidence satisfied the selected tier requirements."
      },
      "authorization": {
        "ok": true,
        "degraded_access_required": false,
        "resource_allows_degraded_access": false,
        "message": "Authorization granted for the selected resource."
      },
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
