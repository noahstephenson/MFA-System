# Core Authentication API

This app exposes a small JSON API for future external clients such as Node-RED.
The API does not control system state on its own. Django remains the
authoritative backend and system of record, and both the API and the simulation
pages call the same service-layer logic.

## Response Shape

Successful responses use this envelope:

```json
{
  "ok": true,
  "message": "Optional human-readable message.",
  "data": {
    "...": "payload"
  }
}
```

Validation and lookup failures use this envelope:

```json
{
  "ok": false,
  "message": "Request validation failed.",
  "errors": {
    "field_name": ["Error message."]
  }
}
```

## Endpoints

### `POST /api/auth/start/`

Start a new authentication session for a protected resource.

Example request:

```json
{
  "resource_id": 1,
  "user_id": 4,
  "policy_id": 2
}
```

Notes:
- `user_id` is optional.
- `policy_id` is optional. If omitted, the resource's first active policy is used.

### `POST /api/auth/factor/`

Submit one abstract authentication factor to an existing session.

Example request:

```json
{
  "session_id": 12,
  "credential_type": "rfid",
  "identifier": "CARD-1001"
}
```

Notes:
- The API accepts abstract factor values only. No hardware, MQTT, or device logic is implemented here.
- The response includes whether the factor was accepted and the updated session state.

### `GET /api/auth/session/<id>/`

Return the current state of an authentication session for polling-style clients.

Session payload highlights:
- `status`
- `decision`
- `required_factor_count`
- `accepted_factor_count`
- `remaining_factor_count`
- `is_complete`
- `is_access_granted`
- `submitted_factors`
