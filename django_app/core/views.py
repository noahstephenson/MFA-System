from django.conf import settings
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import redirect, render

from .forms import AccessStartForm
from .services import get_authentication_session, run_node_red_access_attempt


def _get_session_or_404(session_id):
    try:
        return get_authentication_session(session_id)
    except ValidationError as exc:
        raise Http404(exc.messages[0]) from exc


def _add_form_errors(form, exc):
    if hasattr(exc, "message_dict"):
        for field, errors in exc.message_dict.items():
            target_field = field if field in form.fields else None
            for error in errors:
                form.add_error(target_field, error)
        return

    for error in exc.messages:
        form.add_error(None, error)


def _request_provenance(request, *, channel):
    provenance = {"channel": channel}
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


def _result_message(session):
    factor_collection_result = (session.details or {}).get("factor_collection_result") or {}
    if factor_collection_result.get("message"):
        return factor_collection_result["message"]

    for sensor_name in ("rfid", "fingerprint"):
        sensor_result = factor_collection_result.get(sensor_name) or {}
        if sensor_result and not sensor_result.get("ok") and sensor_result.get("message"):
            return sensor_result["message"]

    return (
        session.authorization_reason_display
        or "The access attempt did not satisfy policy requirements."
    )


def home(request):
    return render(
        request,
        "core/home.html",
        {"node_red_base_url": settings.NODE_RED_BASE_URL},
    )


def access_start(request):
    form = AccessStartForm()
    return render(
        request,
        "core/access_start.html",
        {
            "form": form,
            "node_red_base_url": settings.NODE_RED_BASE_URL,
        },
    )


def access_start_submit(request):
    if request.method != "POST":
        return redirect("core:access-start")

    form = AccessStartForm(request.POST)
    if form.is_valid():
        try:
            result = run_node_red_access_attempt(
                resource_id=form.cleaned_data["resource"].id,
                user_id=form.cleaned_data["user"].id,
                request_provenance=_request_provenance(request, channel="html"),
            )
        except ValidationError as exc:
            _add_form_errors(form, exc)
        else:
            level = messages.SUCCESS if result["session"].is_access_granted else messages.WARNING
            messages.add_message(request, level, result["message"])
            return redirect("core:access-result", session_id=result["session"].id)

    return render(
        request,
        "core/access_start.html",
        {
            "form": form,
            "node_red_base_url": settings.NODE_RED_BASE_URL,
        },
    )


def access_result(request, session_id):
    session = _get_session_or_404(session_id)
    audit_events = list(session.audit_events.select_related("user").order_by("-timestamp")[:8])
    factor_collection_result = (session.details or {}).get("factor_collection_result") or {}
    return render(
        request,
        "core/access_result.html",
        {
            "session": session,
            "access_grant": session.issued_access_grant,
            "audit_events": audit_events,
            "factor_collection_result": factor_collection_result,
            "result_message": _result_message(session),
            "node_red_base_url": settings.NODE_RED_BASE_URL,
        },
    )


def legacy_access_start_redirect(request, **kwargs):
    return redirect("core:access-start")


def legacy_session_result_redirect(request, session_id, **kwargs):
    return redirect("core:access-result", session_id=session_id)
