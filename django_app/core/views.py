from django.conf import settings
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
        AccessPolicy.Tier.BASIC: "Tier 1 uses RFID plus fingerprint.",
        AccessPolicy.Tier.ELEVATED: "Tier 2 uses RFID plus PIN/passcode.",
        AccessPolicy.Tier.HIGH: "Tier 3 uses RFID plus PIN/passcode and a degraded-approved resource.",
    }
    return notes.get(selected_tier, "Select a tier to see the required factors.")


def _access_factor_cards(selected_tier):
    required_factor_types = set(tier_requirement_definition(selected_tier)["required_factor_types"])
    return [
        {
            "key": "rfid",
            "label": "RFID",
            "source": "Node-RED",
            "state": "neutral",
            "status": "Required",
            "detail": "Collected from the badge reader.",
        },
        {
            "key": "biometric",
            "label": "Fingerprint",
            "source": "Node-RED",
            "state": "neutral" if Credential.CredentialType.BIOMETRIC in required_factor_types else "muted",
            "status": "Required"
            if Credential.CredentialType.BIOMETRIC in required_factor_types
            else "Not used",
            "detail": "Required for Tier 1."
            if Credential.CredentialType.BIOMETRIC in required_factor_types
            else "Ignored for Tier 2 and Tier 3.",
        },
        {
            "key": "pin",
            "label": "Knowledge factor",
            "source": "Django",
            "state": "neutral" if Credential.CredentialType.PIN in required_factor_types else "muted",
            "status": "Required" if Credential.CredentialType.PIN in required_factor_types else "Not used",
            "detail": "Checked in Django after RFID."
            if Credential.CredentialType.PIN in required_factor_types
            else "Only used for Tier 2 and Tier 3.",
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
                "label": "RFID",
                "source": "Node-RED",
                "state": "success",
                "status": "Accepted",
                "detail": f"UID {rfid_result.get('uid', 'unknown')} matched the enrolled credential.",
            }
        )
    else:
        cards.append(
            {
                "label": "RFID",
                "source": "Node-RED",
                "state": "error",
                "status": "Failed",
                "detail": submitted_factors.get(Credential.CredentialType.RFID, {}).get("reason_message")
                or rfid_result.get("message")
                or "RFID data was not collected.",
            }
        )

    if Credential.CredentialType.BIOMETRIC in required_factor_types:
        if Credential.CredentialType.BIOMETRIC in verified_factor_types:
            cards.append(
                {
                    "label": "Fingerprint",
                    "source": "Node-RED",
                    "state": "success",
                    "status": "Accepted",
                    "detail": f"Fingerprint ID {fingerprint_result.get('finger_id', 'unknown')} matched the enrolled credential.",
                }
            )
        else:
            cards.append(
                {
                    "label": "Fingerprint",
                    "source": "Node-RED",
                    "state": "error",
                    "status": "Failed",
                    "detail": submitted_factors.get(Credential.CredentialType.BIOMETRIC, {}).get("reason_message")
                    or fingerprint_result.get("message")
                    or "Fingerprint data was not collected.",
                }
            )
    else:
        cards.append(
            {
                "label": "Fingerprint",
                "source": "Node-RED",
                "state": "muted",
                "status": "Not used",
                "detail": "Ignored for Tier 2 and Tier 3.",
            }
        )

    if Credential.CredentialType.PIN in required_factor_types:
        if Credential.CredentialType.PIN in verified_factor_types:
            cards.append(
                {
                    "label": "Knowledge factor",
                    "source": "Django",
                    "state": "success",
                    "status": "Accepted",
                    "detail": "PIN/passcode matched the enrolled credential.",
                }
            )
        else:
            cards.append(
                {
                    "label": "Knowledge factor",
                    "source": "Django",
                    "state": "error",
                    "status": "Failed",
                    "detail": knowledge_submission.get("reason_message")
                    or "Knowledge factor was not accepted.",
                }
            )
    else:
        cards.append(
            {
                "label": "Knowledge factor",
                "source": "Django",
                "state": "muted",
                "status": "Not used",
                "detail": "Only required for Tier 2 and Tier 3.",
            }
        )

    return cards


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
            "node_red_base_url": settings.NODE_RED_BASE_URL,
        },
    )


def access_result(request, session_id):
    session = _get_session_or_404(session_id)
    audit_events = list(session.audit_events.select_related("user").order_by("-timestamp")[:8])
    factor_collection_result = (session.details or {}).get("factor_collection_result") or {}
    authentication_result = (session.details or {}).get("authentication_result") or {}
    authorization_result = (session.details or {}).get("authorization_result") or {}
    result_message = (session.details or {}).get("result_message") or "Access attempt completed."
    return render(
        request,
        "core/access_result.html",
        {
            "session": session,
            "audit_events": audit_events,
            "factor_collection_result": factor_collection_result,
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
