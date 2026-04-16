from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.http import Http404
from django.shortcuts import redirect, render
from django.utils.text import slugify
from django.urls import reverse

from .forms import AccessStartForm, CapturedCredentialForm, EnrollmentChooserForm, PinEnrollmentForm
from .models import AccessPolicy, Credential, normalize_access_tier, tier_requirement_definition
from .services import (
    capture_enrollment_identifier,
    enroll_credential,
    get_authentication_session,
    run_node_red_access_attempt,
)

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
        AccessPolicy.Tier.HIGH: "Tier 3: Badge + PIN + approved degraded resource",
    }
    return notes.get(selected_tier, "Select a tier to see the required factors.")


def _operator_message(message):
    cleaned = str(message or "").strip()
    if not cleaned:
        return ""

    rewrites = {
        "Authentication evidence satisfied the selected tier requirements.": "Identity confirmed.",
        "Authentication succeeded and access was authorized.": "Access approved.",
        "Authentication failed.": "Identity check failed.",
        "Authorization denied because authentication failed.": "Access stopped because identity check failed.",
        "Authorization granted for the selected resource.": "Resource approved.",
        "Tier 3 degraded access is approved for the selected resource.": "Resource approved for Tier 3 access.",
        "Selected resource is not approved for Tier 3 degraded access.": "Resource is not approved for Tier 3 access.",
        "Knowledge factor is required for this tier.": "PIN is required for this tier.",
        "Knowledge factor did not match the enrolled credential.": "PIN did not match.",
        "Node-RED factor collection failed.": "Factor service unavailable.",
        "Node-RED returned factor collection results.": "Factors received.",
        "Node-RED returned factor collection results with errors.": "Factors received with errors.",
        "Node-RED request timed out.": "Factor service timed out.",
        "Node-RED returned an invalid factor payload.": "Factor data was incomplete.",
        "Node-RED did not return any factor data.": "No factor data was returned.",
        "RFID credential is not enrolled for this user.": "Badge is not enrolled for this subject.",
        "RFID data was not collected.": "Badge scan unavailable.",
        "RFID data was not returned.": "Badge scan unavailable.",
        "Fingerprint credential is not enrolled for this user.": "Fingerprint is not enrolled for this subject.",
        "Fingerprint data was not returned.": "Fingerprint result unavailable.",
    }
    if cleaned in rewrites:
        return rewrites[cleaned]

    return (
        cleaned.replace("Node-RED", "Factor service")
        .replace("RFID", "Badge")
        .replace("Knowledge factor", "PIN")
    )


def _credential_type_label(credential_type):
    return {
        Credential.CredentialType.RFID: "Badge",
        Credential.CredentialType.BIOMETRIC: "Fingerprint",
        Credential.CredentialType.PIN: "PIN",
    }.get(credential_type, "Credential")


def _credential_saved_message(credential, *, created):
    action = "saved" if created else "updated"
    return f"{_credential_type_label(credential.credential_type)} {action} for {credential.user.username}."


def _selected_user_from_value(raw_user_id):
    if not str(raw_user_id).isdigit():
        return None
    return User.objects.filter(id=int(raw_user_id), is_active=True).first()


def _normalize_username(raw_username):
    return str(raw_username or "").strip()


def _canonical_username(raw_username):
    normalized_username = _normalize_username(raw_username)
    username = slugify(normalized_username).replace("-", "_")
    return username or normalized_username


def _get_or_create_subject(username):
    canonical_username = _canonical_username(username)
    if not canonical_username:
        return None

    user = User.objects.filter(username__iexact=canonical_username).first()
    if user is None:
        user = User.objects.create_user(username=canonical_username)
    if not user.is_active:
        user.is_active = True
        user.save(update_fields=["is_active"])
    return user


def _selected_username_from_request(request):
    return _normalize_username(request.POST.get("username") or request.GET.get("username"))


def _selected_user_from_request(request):
    username = _selected_username_from_request(request)
    if username:
        return _get_or_create_subject(username)
    return _selected_user_from_value(request.POST.get("user", "")) or _selected_user_from_value(request.GET.get("user", ""))


def _initial_username_value(selected_user, username=""):
    if username:
        return {"username": username}
    return {"username": selected_user.username} if selected_user is not None else {}


def _selected_credential_type(request):
    raw_type = str(request.POST.get("credential_type") or request.GET.get("credential_type") or "").strip()
    valid_types = {
        Credential.CredentialType.RFID,
        Credential.CredentialType.BIOMETRIC,
        Credential.CredentialType.PIN,
    }
    return raw_type if raw_type in valid_types else Credential.CredentialType.RFID


def _capture_preview(credential_type, *, ok=None, identifier="", message=""):
    normalized_identifier = str(identifier or "").strip()
    if ok is True and normalized_identifier:
        prefix = "UID" if credential_type == Credential.CredentialType.RFID else "ID"
        return {
            "state": "success",
            "status": "Ready to save",
            "detail": f"{prefix} {normalized_identifier}",
        }
    if ok is False and message:
        return {
            "state": "error",
            "status": "Capture failed",
            "detail": _operator_message(message) or "Capture failed.",
        }
    if normalized_identifier:
        prefix = "UID" if credential_type == Credential.CredentialType.RFID else "ID"
        return {
            "state": "success",
            "status": "Ready to save",
            "detail": f"{prefix} {normalized_identifier}",
        }
    return None


def _access_factor_cards(selected_tier):
    required_factor_types = set(tier_requirement_definition(selected_tier)["required_factor_types"])
    return [
        {
            "key": "rfid",
            "label": "Badge",
            "state": "neutral",
            "status": "Pending",
            "detail": "Scan badge",
        },
        {
            "key": "biometric",
            "label": "Fingerprint",
            "state": "neutral" if Credential.CredentialType.BIOMETRIC in required_factor_types else "muted",
            "status": "Pending"
            if Credential.CredentialType.BIOMETRIC in required_factor_types
            else "Not Required",
            "detail": "Capture fingerprint"
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
                "detail": _operator_message(
                    submitted_factors.get(Credential.CredentialType.RFID, {}).get("reason_message")
                    or rfid_result.get("message")
                    or "Badge scan not available."
                ),
            }
        )

    if Credential.CredentialType.BIOMETRIC in required_factor_types:
        if Credential.CredentialType.BIOMETRIC in verified_factor_types:
            cards.append(
                {
                    "label": "Fingerprint",
                    "state": "success",
                    "status": "Accepted",
                    "detail": f"ID {fingerprint_result.get('finger_id', 'unknown')}",
                }
            )
        else:
            cards.append(
                {
                    "label": "Fingerprint",
                    "state": "error",
                    "status": "Failed",
                    "detail": _operator_message(
                        submitted_factors.get(Credential.CredentialType.BIOMETRIC, {}).get("reason_message")
                        or fingerprint_result.get("message")
                        or "Fingerprint not available."
                    ),
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
                    "detail": "Accepted",
                }
            )
        else:
            cards.append(
                {
                    "label": "PIN",
                    "state": "error",
                    "status": "Failed",
                    "detail": _operator_message(knowledge_submission.get("reason_message") or "PIN not accepted."),
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
        "authentication_succeeded": "Identity",
        "authentication_failed": "Identity",
        "authorization_granted": "Resource",
        "authorization_denied": "Resource",
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
    return render(request, "core/home.html", {"nav_key": "home"})


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
            messages.add_message(request, level, _operator_message(result["message"]))
            return redirect("core:access-result", session_id=result["session"].id)

    return render(
        request,
        "core/access_start.html",
        {
            "form": form,
            "nav_key": "access",
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
    authentication_note = _operator_message(authentication_result.get("message"))
    authorization_note = _operator_message(authorization_result.get("message"))
    result_message = _operator_message((session.details or {}).get("result_message")) or "Access attempt completed."
    return render(
        request,
        "core/access_result.html",
        {
            "session": session,
            "nav_key": "access",
            "audit_entries": _operator_audit_entries(audit_events),
            "authentication_result": authentication_result,
            "authentication_note": authentication_note,
            "authorization_result": authorization_result,
            "authorization_note": authorization_note,
            "decision_note": authorization_note if authentication_result.get("ok") else authentication_note,
            "factor_cards": _factor_cards_for_result(session, factor_collection_result, authentication_result),
            "result_message": result_message,
        },
    )


def enroll(request):
    selected_username = _selected_username_from_request(request)
    selected_user = _selected_user_from_request(request)
    selected_credential_type = _selected_credential_type(request)
    badge_capture = None
    fingerprint_capture = None
    chooser_initial = {
        **_initial_username_value(selected_user, selected_username),
        "credential_type": selected_credential_type,
    }

    chooser_form = EnrollmentChooserForm(initial=chooser_initial)
    if request.method == "POST":
        chooser_form = EnrollmentChooserForm(request.POST)
        chooser_form.fields["credential_type"].required = False

    username_initial = _initial_username_value(selected_user, selected_username)
    badge_save_form = CapturedCredentialForm(initial=username_initial)
    fingerprint_save_form = CapturedCredentialForm(initial=username_initial)
    pin_form = PinEnrollmentForm(initial=username_initial)

    if request.method == "POST":
        action = str(request.POST.get("action") or "").strip()
        if action and selected_user is None:
            messages.warning(request, "Enter a username first.")
        elif action == "save-pin":
            pin_form = PinEnrollmentForm(request.POST)
            if pin_form.is_valid():
                try:
                    user = _get_or_create_subject(pin_form.cleaned_data["username"])
                    result = enroll_credential(
                        user_id=user.id,
                        credential_type=Credential.CredentialType.PIN,
                        identifier=pin_form.cleaned_data["pin"],
                        label=pin_form.cleaned_data.get("label", ""),
                        request_provenance=_request_provenance(request, channel="html"),
                    )
                except ValidationError as exc:
                    _add_form_errors(pin_form, exc)
                else:
                    messages.success(
                        request,
                        _credential_saved_message(result["credential"], created=result["created"]),
                    )
                    return redirect(
                        f"{reverse('core:enroll')}?username={result['credential'].user.username}&credential_type={Credential.CredentialType.PIN}"
                    )
        elif action == "capture-rfid":
            try:
                capture_result = capture_enrollment_identifier(
                    user_id=selected_user.id,
                    credential_type=Credential.CredentialType.RFID,
                    request_provenance=_request_provenance(request, channel="html"),
                )
            except ValidationError as exc:
                badge_capture = _capture_preview(
                    Credential.CredentialType.RFID,
                    ok=False,
                    message=exc.messages[0],
                )
            else:
                badge_capture = _capture_preview(
                    Credential.CredentialType.RFID,
                    ok=capture_result["ok"],
                    identifier=capture_result["identifier"],
                    message=capture_result["message"],
                )
                if capture_result["ok"]:
                    badge_save_form = CapturedCredentialForm(
                        initial={
                            **_initial_username_value(selected_user, selected_username),
                            "captured_identifier": capture_result["identifier"],
                        }
                    )
        elif action == "save-rfid":
            badge_save_form = CapturedCredentialForm(request.POST)
            if badge_save_form.is_valid():
                try:
                    user = _get_or_create_subject(badge_save_form.cleaned_data["username"])
                    result = enroll_credential(
                        user_id=user.id,
                        credential_type=Credential.CredentialType.RFID,
                        identifier=badge_save_form.cleaned_data["captured_identifier"],
                        label=badge_save_form.cleaned_data.get("label", ""),
                        request_provenance=_request_provenance(request, channel="html"),
                    )
                except ValidationError as exc:
                    _add_form_errors(badge_save_form, exc)
                else:
                    messages.success(
                        request,
                        _credential_saved_message(result["credential"], created=result["created"]),
                    )
                    return redirect(
                        f"{reverse('core:enroll')}?username={result['credential'].user.username}&credential_type={Credential.CredentialType.RFID}"
                    )
            else:
                if not str(request.POST.get("captured_identifier") or "").strip():
                    messages.warning(request, "Scan the badge before saving.")
            badge_capture = _capture_preview(
                Credential.CredentialType.RFID,
                identifier=request.POST.get("captured_identifier", ""),
            )
        elif action == "capture-fingerprint":
            try:
                capture_result = capture_enrollment_identifier(
                    user_id=selected_user.id,
                    credential_type=Credential.CredentialType.BIOMETRIC,
                    request_provenance=_request_provenance(request, channel="html"),
                )
            except ValidationError as exc:
                fingerprint_capture = _capture_preview(
                    Credential.CredentialType.BIOMETRIC,
                    ok=False,
                    message=exc.messages[0],
                )
            else:
                fingerprint_capture = _capture_preview(
                    Credential.CredentialType.BIOMETRIC,
                    ok=capture_result["ok"],
                    identifier=capture_result["identifier"],
                    message=capture_result["message"],
                )
                if capture_result["ok"]:
                    fingerprint_save_form = CapturedCredentialForm(
                        initial={
                            **_initial_username_value(selected_user, selected_username),
                            "captured_identifier": capture_result["identifier"],
                        }
                    )
        elif action == "save-fingerprint":
            fingerprint_save_form = CapturedCredentialForm(request.POST)
            if fingerprint_save_form.is_valid():
                try:
                    user = _get_or_create_subject(fingerprint_save_form.cleaned_data["username"])
                    result = enroll_credential(
                        user_id=user.id,
                        credential_type=Credential.CredentialType.BIOMETRIC,
                        identifier=fingerprint_save_form.cleaned_data["captured_identifier"],
                        label=fingerprint_save_form.cleaned_data.get("label", ""),
                        request_provenance=_request_provenance(request, channel="html"),
                    )
                except ValidationError as exc:
                    _add_form_errors(fingerprint_save_form, exc)
                else:
                    messages.success(
                        request,
                        _credential_saved_message(result["credential"], created=result["created"]),
                    )
                    return redirect(
                        f"{reverse('core:enroll')}?username={result['credential'].user.username}&credential_type={Credential.CredentialType.BIOMETRIC}"
                    )
            else:
                if not str(request.POST.get("captured_identifier") or "").strip():
                    messages.warning(request, "Capture the fingerprint before saving.")
            fingerprint_capture = _capture_preview(
                Credential.CredentialType.BIOMETRIC,
                identifier=request.POST.get("captured_identifier", ""),
            )

    return render(
        request,
        "core/enroll.html",
        {
            "badge_capture": badge_capture,
            "badge_save_form": badge_save_form,
            "chooser_form": chooser_form,
            "fingerprint_capture": fingerprint_capture,
            "fingerprint_save_form": fingerprint_save_form,
            "nav_key": "enroll",
            "pin_form": pin_form,
            "selected_credential_type": selected_credential_type,
            "selected_user": selected_user,
        },
    )
