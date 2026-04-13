"""Machine-friendly JSON endpoints for local clients such as Node-RED.

These views are intentionally CSRF-exempt because they are designed for
non-browser callers. HTML pages remain protected by Django's normal CSRF
middleware. If the local API is exposed beyond localhost, set
MFA_API_SHARED_SECRET and send it as X-API-Key.
"""

import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from .models import Credential
from .services import (
    get_authentication_session,
    run_node_red_access_attempt,
    start_authentication_session,
    submit_authentication_factor,
)


def _json_error(message, *, errors=None, http_status=400):
    return JsonResponse(
        {
            "ok": False,
            "message": message,
            "errors": errors or {},
        },
        status=http_status,
    )


def _validation_errors(exc):
    return getattr(exc, "message_dict", {"detail": exc.messages})


def _parse_json_body(request):
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValidationError({"body": ["Request body must be valid JSON."]})

    if not isinstance(body, dict):
        raise ValidationError({"body": ["Request body must be a JSON object."]})
    return body


def _parse_positive_int(data, field_name, *, required=True):
    value = data.get(field_name)
    if value in (None, ""):
        if required:
            raise ValidationError({field_name: ["This field is required."]})
        return None

    try:
        integer_value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError({field_name: ["Enter a whole number."]}) from exc

    if integer_value < 1:
        raise ValidationError({field_name: ["Ensure this value is greater than 0."]})
    return integer_value


def _parse_credential_type(data):
    credential_type = str(data.get("credential_type") or "").strip().lower()
    valid_types = {choice for choice, _label in Credential.CredentialType.choices}
    if not credential_type:
        raise ValidationError({"credential_type": ["This field is required."]})
    if credential_type not in valid_types:
        raise ValidationError({"credential_type": ["Select a valid choice."]})
    return credential_type


def _parse_identifier(data):
    identifier = str(data.get("identifier") or "").strip()
    if not identifier:
        raise ValidationError({"identifier": ["This field is required."]})
    return identifier


def _request_provenance(request):
    provenance = {"channel": "api"}
    if getattr(settings, "MFA_API_SHARED_SECRET", "").strip():
        provenance["auth_mode"] = "shared_secret"
    else:
        provenance["auth_mode"] = "open"

    request_id = request.headers.get("X-Request-ID", "").strip()
    client_name = request.headers.get("X-Client-Name", "").strip()
    remote_addr = request.META.get("REMOTE_ADDR", "").strip()
    if request_id:
        provenance["request_id"] = request_id
    if client_name:
        provenance["client_name"] = client_name
    if remote_addr:
        provenance["remote_addr"] = remote_addr
    return provenance


def _api_auth_error():
    return _json_error(
        "API authentication failed.",
        errors={"detail": ["Provide a valid X-API-Key header."]},
        http_status=403,
    )


def _require_api_auth(request):
    shared_secret = getattr(settings, "MFA_API_SHARED_SECRET", "").strip()
    if not shared_secret:
        return None

    provided_secret = request.headers.get("X-API-Key", "").strip()
    if provided_secret != shared_secret:
        return _api_auth_error()
    return None


def _access_grant_payload(session):
    access_grant = session.issued_access_grant
    if access_grant is None:
        return None
    return {
        "id": access_grant.id,
        "status": access_grant.status,
        "reason_code": access_grant.reason_code,
        "expires_at": access_grant.expires_at.isoformat() if access_grant.expires_at else None,
    }


def _session_payload(request, session):
    return {
        "id": session.id,
        "user": session.user.username if session.user else None,
        "resource": session.resource.name,
        "policy": session.policy.name if session.policy else None,
        "status": session.status,
        "status_display": session.get_status_display(),
        "decision": session.decision,
        "decision_display": session.get_decision_display(),
        "authentication_state": session.authentication_state,
        "authorization_state": session.authorization_state,
        "authorization_reason": session.authorization_reason_display,
        "required_factor_count": session.required_factor_count,
        "accepted_factor_count": session.accepted_factor_count,
        "remaining_factor_count": session.remaining_factor_count,
        "submitted_factors": session.submitted_factors,
        "degraded_mode_applied": session.degraded_mode_applied,
        "is_complete": session.is_complete,
        "is_access_granted": session.is_access_granted,
        "access_grant": _access_grant_payload(session),
        "factor_collection_result": (session.details or {}).get("factor_collection_result") or None,
        "result_url": request.build_absolute_uri(
            reverse("core:access-result", args=[session.id])
        ),
    }


def _session_detail_response(request, session):
    return JsonResponse(
        {
            "ok": True,
            "data": {
                "session": _session_payload(request, session),
            },
        }
    )


@csrf_exempt
def api_access_start(request):
    auth_error = _require_api_auth(request)
    if auth_error is not None:
        return auth_error

    if request.method != "POST":
        return _json_error("Request method not allowed.", http_status=405)

    try:
        data = _parse_json_body(request)
        result = run_node_red_access_attempt(
            resource_id=_parse_positive_int(data, "resource_id"),
            user_id=_parse_positive_int(data, "user_id"),
            policy_id=_parse_positive_int(data, "policy_id", required=False),
            request_provenance=_request_provenance(request),
        )
    except ValidationError as exc:
        return _json_error("Request validation failed.", errors=_validation_errors(exc))

    return JsonResponse(
        {
            "ok": True,
            "message": result["message"],
            "data": {
                "session": _session_payload(request, result["session"]),
                "node_red": {
                    "ok": result["node_red_result"]["ok"] if result["node_red_result"] else None,
                    "error": result["node_red_result"]["error"] if result["node_red_result"] else "",
                    "message": result["node_red_result"]["message"] if result["node_red_result"] else "",
                },
            },
        },
        status=201,
    )


@csrf_exempt
def api_access_session_detail(request, session_id):
    auth_error = _require_api_auth(request)
    if auth_error is not None:
        return auth_error

    if request.method != "GET":
        return _json_error("Request method not allowed.", http_status=405)

    try:
        session = get_authentication_session(session_id)
    except ValidationError as exc:
        return _json_error("Resource not found.", errors={"session_id": exc.messages}, http_status=404)

    return _session_detail_response(request, session)


@csrf_exempt
def api_auth_start(request):
    auth_error = _require_api_auth(request)
    if auth_error is not None:
        return auth_error

    if request.method != "POST":
        return _json_error("Request method not allowed.", http_status=405)

    try:
        data = _parse_json_body(request)
        session = start_authentication_session(
            resource_id=_parse_positive_int(data, "resource_id"),
            user_id=_parse_positive_int(data, "user_id", required=False),
            policy_id=_parse_positive_int(data, "policy_id", required=False),
            request_provenance=_request_provenance(request),
        )
    except ValidationError as exc:
        return _json_error("Request validation failed.", errors=_validation_errors(exc))

    return JsonResponse(
        {
            "ok": True,
            "message": "Authentication session started.",
            "data": {
                "session": _session_payload(request, session),
            },
        },
        status=201,
    )


@csrf_exempt
def api_auth_factor(request):
    auth_error = _require_api_auth(request)
    if auth_error is not None:
        return auth_error

    if request.method != "POST":
        return _json_error("Request method not allowed.", http_status=405)

    try:
        data = _parse_json_body(request)
        result = submit_authentication_factor(
            session_id=_parse_positive_int(data, "session_id"),
            credential_type=_parse_credential_type(data),
            identifier=_parse_identifier(data),
            request_provenance=_request_provenance(request),
        )
    except ValidationError as exc:
        return _json_error("Request validation failed.", errors=_validation_errors(exc))

    return JsonResponse(
        {
            "ok": True,
            "message": result["message"],
            "data": {
                "accepted": result["accepted"],
                "outcome": result["outcome"],
                "reason_code": result["reason_code"],
                "session": _session_payload(request, result["session"]),
            },
        }
    )


@csrf_exempt
def api_auth_session_detail(request, session_id):
    return api_access_session_detail(request, session_id)
