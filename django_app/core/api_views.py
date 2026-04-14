"""Machine-friendly JSON endpoint for the Django MVP."""

import json

from django.conf import settings
from django.core.exceptions import ValidationError
from django.http import JsonResponse
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt

from .services import run_node_red_access_attempt


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


def _request_provenance(request):
    provenance = {"channel": "api"}
    provenance["auth_mode"] = (
        "shared_secret" if getattr(settings, "MFA_API_SHARED_SECRET", "").strip() else "open"
    )

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


def _require_api_auth(request):
    shared_secret = getattr(settings, "MFA_API_SHARED_SECRET", "").strip()
    if not shared_secret:
        return None

    provided_secret = request.headers.get("X-API-Key", "").strip()
    if provided_secret == shared_secret:
        return None

    return _json_error(
        "API authentication failed.",
        errors={"detail": ["Provide a valid X-API-Key header."]},
        http_status=403,
    )


def _session_payload(request, session):
    return {
        "id": session.id,
        "user": session.user.username if session.user else None,
        "resource": session.resource.name,
        "policy": session.policy.name if session.policy else None,
        "status": session.status,
        "decision": session.decision,
        "required_factor_count": session.required_factor_count,
        "accepted_factor_count": session.accepted_factor_count,
        "remaining_factor_count": session.remaining_factor_count,
        "submitted_factors": session.submitted_factors,
        "is_complete": session.is_complete,
        "is_access_granted": session.is_access_granted,
        "factor_collection_result": (session.details or {}).get("factor_collection_result") or None,
        "result_url": request.build_absolute_uri(reverse("core:access-result", args=[session.id])),
    }


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
                    "ok": result["node_red_result"]["ok"],
                    "error": result["node_red_result"]["error"],
                    "message": result["node_red_result"]["message"],
                },
            },
        },
        status=201,
    )
