from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse

from .forms import AccessStartForm, EnrollmentForm
from .models import AccessPolicy, Credential, ProtectedResource, normalize_access_tier, tier_requirement_definition
from .services import enroll_credential, get_authentication_session, run_node_red_access_attempt

User = get_user_model()


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


def _selected_tier_from_form(form):
    raw_tier = ""
    if form.is_bound:
        raw_tier = form.data.get("tier", "")
    else:
        raw_tier = form.initial.get("tier", "")
    return normalize_access_tier(raw_tier) or AccessPolicy.Tier.BASIC


def _tier_note(selected_tier):
    notes = {
        AccessPolicy.Tier.BASIC: "Tier 1: Badge + Fingerprint",
        AccessPolicy.Tier.ELEVATED: "Tier 2: Badge + PIN",
        AccessPolicy.Tier.HIGH: "Tier 3: Badge + PIN + Degraded resource only",
    }
    return notes.get(selected_tier, "Select a tier to see the required factors.")


def _operator_message(message):
    cleaned = str(message or "").strip()
    if not cleaned:
        return ""

    rewrites = {
        "Node-RED request timed out.": "Factor service timed out.",
        "Node-RED returned an invalid factor payload.": "Factor data was incomplete.",
        "Node-RED did not return any factor data.": "No factor data was returned.",
        "RFID data was not collected.": "Badge scan unavailable.",
        "RFID data was not returned.": "Badge scan unavailable.",
        "Fingerprint data was not returned.": "Fingerprint result unavailable.",
    }
    if cleaned in rewrites:
        return rewrites[cleaned]

    return cleaned.replace("Node-RED", "Factor service").replace("RFID", "Badge")


def _access_factor_cards(selected_tier):
    required_factor_types = set(tier_requirement_definition(selected_tier)["required_factor_types"])
    return [
        {
            "key": "rfid",
            "label": "Badge",
            "state": "neutral",
            "status": "Pending",
            "detail": "Required",
        },
        {
            "key": "biometric",
            "label": "Fingerprint",
            "state": "neutral" if Credential.CredentialType.BIOMETRIC in required_factor_types else "muted",
            "status": "Pending"
            if Credential.CredentialType.BIOMETRIC in required_factor_types
            else "Not Required",
            "detail": "Required"
            if Credential.CredentialType.BIOMETRIC in required_factor_types
            else "Not required",
        },
        {
            "key": "pin",
            "label": "PIN",
            "state": "neutral" if Credential.CredentialType.PIN in required_factor_types else "muted",
            "status": "Pending" if Credential.CredentialType.PIN in required_factor_types else "Not Required",
            "detail": "Enter PIN" if Credential.CredentialType.PIN in required_factor_types else "Not required",
        },
    ]


def _selected_user_for_enrollment(request, form):
    raw_user_id = ""
    if form.is_bound:
        raw_user_id = form.data.get("user", "")
    else:
        raw_user_id = request.GET.get("user", "") or form.initial.get("user", "")

    if not str(raw_user_id).isdigit():
        return None

    return User.objects.filter(id=int(raw_user_id), is_active=True).first()


def _factor_cards_for_result(session, factor_collection_result, authentication_result):
    required_factor_types = set(authentication_result.get("required_factor_types") or [])
    verified_factor_types = set(authentication_result.get("verified_factor_types") or [])
    submitted_factors = {
        factor.get("credential_type"): factor
        for factor in (session.submitted_factors or [])
        if isinstance(factor, dict)
    }

    rfid_result = factor_collection_result.get("rfid") or {}
    fingerprint_result = factor_collection_result.get("fingerprint") or {}
    knowledge_submission = submitted_factors.get(Credential.CredentialType.PIN, {})

    cards = []

    if Credential.CredentialType.RFID in verified_factor_types:
        cards.append(
            {
                "label": "Badge",
                "state": "success",
                "status": "Accepted",
                "detail": f"UID {rfid_result.get('uid', 'unknown')}",
            }
        )
    else:
        cards.append(
            {
                "label": "Badge",
                "state": "error",
                "status": "Failed",
                "detail": submitted_factors.get(Credential.CredentialType.RFID, {}).get("reason_message")
                or rfid_result.get("message")
                or "Badge scan not available.",
            }
        )

    if Credential.CredentialType.BIOMETRIC in required_factor_types:
        if Credential.CredentialType.BIOMETRIC in verified_factor_types:
            cards.append(
                {
                    "label": "Fingerprint",
                    "state": "success",
                    "status": "Accepted",
                    "detail": f"Fingerprint ID {fingerprint_result.get('finger_id', 'unknown')}",
                }
            )
        else:
            cards.append(
                {
                    "label": "Fingerprint",
                    "state": "error",
                    "status": "Failed",
                    "detail": submitted_factors.get(Credential.CredentialType.BIOMETRIC, {}).get("reason_message")
                    or fingerprint_result.get("message")
                    or "Fingerprint not available.",
                }
            )
    else:
        cards.append(
            {
                "label": "Fingerprint",
                "state": "muted",
                "status": "Not Required",
                "detail": "Not required",
            }
        )

    if Credential.CredentialType.PIN in required_factor_types:
        if Credential.CredentialType.PIN in verified_factor_types:
            cards.append(
                {
                    "label": "PIN",
                    "state": "success",
                    "status": "Accepted",
                    "detail": "PIN accepted",
                }
            )
        else:
            cards.append(
                {
                    "label": "PIN",
                    "state": "error",
                    "status": "Failed",
                    "detail": knowledge_submission.get("reason_message")
                    or "PIN not accepted.",
                }
            )
    else:
        cards.append(
            {
                "label": "PIN",
                "state": "muted",
                "status": "Not Required",
                "detail": "Not required",
            }
        )

    return cards


def _operator_collection_summary(factor_collection_result):
    collection = factor_collection_result or {}
    rfid_result = collection.get("rfid") or {}
    fingerprint_result = collection.get("fingerprint") or {}

    if rfid_result.get("ok"):
        badge_detail = f"UID {rfid_result.get('uid', 'unknown')}"
    else:
        badge_detail = _operator_message(rfid_result.get("message")) or "Badge scan unavailable."

    if fingerprint_result.get("ok"):
        fingerprint_detail = f"Match {fingerprint_result.get('finger_id', 'unknown')}"
    else:
        fingerprint_detail = _operator_message(fingerprint_result.get("message")) or "Fingerprint result unavailable."

    return {
        "ok": bool(collection.get("ok")),
        "message": _operator_message(collection.get("message") or collection.get("error")),
        "badge_detail": badge_detail,
        "fingerprint_detail": fingerprint_detail,
    }


def _operator_audit_entries(audit_events):
    labels = {
        "session_started": "Request",
        "factor_collection_completed": "Factors",
        "factor_collection_failed": "Factors",
        "authentication_succeeded": "Authentication",
        "authentication_failed": "Authentication",
        "authorization_granted": "Authorization",
        "authorization_denied": "Authorization",
        "access_granted": "Decision",
        "access_denied": "Decision",
    }
    entries = []
    for event in audit_events:
        entries.append(
            {
                "label": labels.get(event.event_type, "Audit"),
                "message": _operator_message(event.message),
            }
        )
    return entries


def home(request):
    context = {
        "active_user_count": User.objects.filter(is_active=True).count(),
        "active_resource_count": ProtectedResource.objects.filter(active=True).count(),
        "active_credential_count": Credential.objects.filter(active=True).count(),
    }
    return render(request, "core/home.html", context)


def access_start(request):
    form = AccessStartForm(request.POST or None)
    selected_tier = _selected_tier_from_form(form)

    if request.method == "POST" and form.is_valid():
        try:
            result = run_node_red_access_attempt(
                resource_id=form.cleaned_data["resource"].id,
                user_id=form.cleaned_data["user"].id,
                tier=form.cleaned_data["tier"],
                knowledge_factor=form.cleaned_data.get("knowledge_factor", ""),
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
            "selected_tier": selected_tier,
            "tier_note": _tier_note(selected_tier),
            "factor_cards": _access_factor_cards(selected_tier),
        },
    )


def access_result(request, session_id):
    session = _get_session_or_404(session_id)
    audit_events = list(session.audit_events.select_related("user").order_by("-timestamp")[:8])
    factor_collection_result = (session.details or {}).get("factor_collection_result") or {}
    authentication_result = (session.details or {}).get("authentication_result") or {}
    authorization_result = (session.details or {}).get("authorization_result") or {}
    result_message = _operator_message((session.details or {}).get("result_message")) or "Access attempt completed."
    return render(
        request,
        "core/access_result.html",
        {
            "session": session,
            "audit_entries": _operator_audit_entries(audit_events),
            "factor_collection_result": factor_collection_result,
            "collection_summary": _operator_collection_summary(factor_collection_result),
            "authentication_result": authentication_result,
            "authorization_result": authorization_result,
            "factor_cards": _factor_cards_for_result(session, factor_collection_result, authentication_result),
            "result_message": result_message,
        },
    )


def enroll(request):
    initial = {}
    selected_user_id = request.GET.get("user", "").strip()
    if selected_user_id.isdigit():
        initial["user"] = int(selected_user_id)

    form = EnrollmentForm(request.POST or None, initial=initial)

    if request.method == "POST" and form.is_valid():
        try:
            result = enroll_credential(
                user_id=form.cleaned_data["user"].id,
                credential_type=form.cleaned_data["credential_type"],
                identifier=form.cleaned_data["identifier"],
                label=form.cleaned_data.get("label", ""),
                request_provenance=_request_provenance(request, channel="html"),
            )
        except ValidationError as exc:
            _add_form_errors(form, exc)
        else:
            messages.success(request, result["message"])
            return redirect(f"{reverse('core:enroll')}?user={result['credential'].user_id}")

    selected_user = _selected_user_for_enrollment(request, form)
    selected_credentials = (
        Credential.objects.filter(user=selected_user).order_by("credential_type", "label", "identifier")
        if selected_user is not None
        else []
    )

    return render(
        request,
        "core/enroll.html",
        {
            "form": form,
            "selected_user": selected_user,
            "selected_credentials": selected_credentials,
        },
    )
