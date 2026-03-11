from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import Http404
from django.db.models import Prefetch
from django.shortcuts import get_object_or_404, redirect, render

from .forms import SimulationFactorForm, SimulationStartForm
from .models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource
from .services import (
    deny_authentication_session,
    get_access_policy_queryset,
    get_authentication_session,
    get_authentication_session_queryset,
    get_credential_queryset,
    start_authentication_session,
    submit_authentication_factor,
)


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


def _get_session_audit_events(session):
    return list(session.audit_events.select_related("user")[:10])


def _get_simulation_resources():
    return ProtectedResource.objects.filter(active=True).order_by("name").prefetch_related(
        Prefetch(
            "policies",
            queryset=AccessPolicy.objects.filter(active=True).order_by("id"),
            to_attr="simulation_policies",
        )
    )


def _get_session_state_summary(session, audit_events):
    latest_event = audit_events[0] if audit_events else None
    next_factor_number = min(session.accepted_factor_count + 1, session.required_factor_count)

    if session.is_access_granted:
        return {
            "title": "Access granted",
            "message": "All required factors were accepted for this resource.",
            "tone": "success",
            "latest_event": latest_event,
            "next_factor_number": session.required_factor_count,
        }

    if session.is_complete:
        return {
            "title": "Access denied",
            "message": latest_event.message if latest_event else "The access attempt ended before the policy was satisfied.",
            "tone": "warning",
            "latest_event": latest_event,
            "next_factor_number": next_factor_number,
        }

    if latest_event and latest_event.event_type == "factor_rejected":
        return {
            "title": "Factor rejected",
            "message": (
                f"The last credential was not accepted. Present factor {next_factor_number} "
                f"of {session.required_factor_count}."
            ),
            "tone": "warning",
            "latest_event": latest_event,
            "next_factor_number": next_factor_number,
        }

    if latest_event and latest_event.event_type == "factor_duplicate":
        return {
            "title": "Factor already used",
            "message": (
                f"That factor was already accepted for this attempt. Present factor {next_factor_number} "
                f"of {session.required_factor_count}."
            ),
            "tone": "warning",
            "latest_event": latest_event,
            "next_factor_number": next_factor_number,
        }

    if session.accepted_factor_count == 0:
        return {
            "title": "Access attempt started",
            "message": (
                f"This resource requires {session.required_factor_count} factor"
                f"{'' if session.required_factor_count == 1 else 's'}. Present factor 1 now."
            ),
            "tone": "info",
            "latest_event": latest_event,
            "next_factor_number": 1,
        }

    return {
        "title": "Awaiting next factor",
        "message": (
            f"{session.accepted_factor_count} factor"
            f"{'' if session.accepted_factor_count == 1 else 's'} accepted. Present factor {next_factor_number} "
            f"of {session.required_factor_count} to continue."
        ),
        "tone": "info",
        "latest_event": latest_event,
        "next_factor_number": next_factor_number,
    }


def _get_demo_credentials(session):
    if session.user_id is None:
        return Credential.objects.none()

    return session.user.credentials.filter(active=True).order_by("credential_type", "identifier")


def _get_session_context(session, *, include_demo_credentials=False):
    audit_events = _get_session_audit_events(session)
    state_summary = _get_session_state_summary(session, audit_events)
    context = {
        "session": session,
        "session_audit_events": audit_events,
        "session_state_title": state_summary["title"],
        "session_state_message": state_summary["message"],
        "session_state_tone": state_summary["tone"],
        "latest_session_event": state_summary["latest_event"],
        "next_factor_number": state_summary["next_factor_number"],
    }
    if include_demo_credentials:
        context["available_credentials"] = _get_demo_credentials(session)
    return context


def home(request):
    recent_sessions = AuthenticationSession.objects.select_related(
        "resource",
        "user",
        "policy",
    )[:5]
    recent_audit_events = AuditEvent.objects.select_related("session", "user")[:5]

    context = {
        "resource_count": ProtectedResource.objects.filter(active=True).count(),
        "policy_count": AccessPolicy.objects.filter(active=True).count(),
        "session_count": AuthenticationSession.objects.count(),
        "credential_count": Credential.objects.filter(active=True).count(),
        "audit_event_count": AuditEvent.objects.count(),
        "recent_sessions": recent_sessions,
        "recent_audit_events": recent_audit_events,
    }
    return render(request, "core/home.html", context)


def simulation_start(request):
    form = SimulationStartForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        try:
            session = start_authentication_session(
                resource_id=form.cleaned_data["resource"].id,
                user_id=form.cleaned_data["user"].id,
            )
        except ValidationError as exc:
            _add_form_errors(form, exc)
        else:
            messages.info(request, "Access attempt started. Follow the applied policy below.")
            return redirect("core:simulation-session", session_id=session.id)

    return render(
        request,
        "core/simulation_start.html",
        {
            "form": form,
            "simulation_resources": _get_simulation_resources(),
        },
    )


def protected_resource_list(request):
    resources = ProtectedResource.objects.prefetch_related(
        Prefetch(
            "policies",
            queryset=AccessPolicy.objects.filter(active=True).order_by("name"),
            to_attr="active_policies",
        )
    )
    return render(request, "core/protected_resource_list.html", {"resources": resources})


def protected_resource_detail(request, resource_id):
    resource = get_object_or_404(ProtectedResource, id=resource_id)
    context = {
        "resource": resource,
        "policies": resource.policies.order_by("name"),
        "recent_sessions": resource.authentication_sessions.select_related("user", "policy")[:10],
        "recent_audit_events": AuditEvent.objects.filter(session__resource=resource).select_related(
            "user",
            "session",
        )[:10],
    }
    return render(request, "core/protected_resource_detail.html", context)


def access_policy_list(request):
    policies = get_access_policy_queryset().order_by("resource__name", "name")
    return render(request, "core/access_policy_list.html", {"policies": policies})


def access_policy_detail(request, policy_id):
    policy = get_object_or_404(get_access_policy_queryset(), id=policy_id)
    context = {
        "policy": policy,
        "recent_sessions": policy.authentication_sessions.select_related("user", "resource")[:10],
    }
    return render(request, "core/access_policy_detail.html", context)


def credential_list(request):
    credentials = get_credential_queryset().order_by("user__username", "credential_type", "identifier")
    return render(request, "core/credential_list.html", {"credentials": credentials})


def credential_detail(request, credential_id):
    credential = get_object_or_404(get_credential_queryset(), id=credential_id)
    context = {
        "credential": credential,
        "recent_sessions": get_authentication_session_queryset().filter(user=credential.user)[:10],
    }
    return render(request, "core/credential_detail.html", context)


def authentication_session_detail(request, session_id):
    session = _get_session_or_404(session_id)
    return render(request, "core/authentication_session_detail.html", _get_session_context(session))


def audit_log(request):
    audit_events = AuditEvent.objects.select_related("session", "user")[:50]
    return render(request, "core/audit_log.html", {"audit_events": audit_events})


def simulation_session(request, session_id):
    session = _get_session_or_404(session_id)

    if session.is_complete:
        return redirect("core:simulation-result", session_id=session.id)

    factor_form = SimulationFactorForm()

    if request.method == "POST":
        if "deny_session" in request.POST:
            try:
                session = deny_authentication_session(
                    session_id=session.id,
                    reason="Simulation ended before the required factors were completed.",
                )
            except ValidationError as exc:
                messages.error(request, exc.messages[0])
            else:
                messages.warning(request, "Access attempt ended. Access denied.")
                return redirect("core:simulation-result", session_id=session.id)
        else:
            factor_form = SimulationFactorForm(request.POST)
            if factor_form.is_valid():
                try:
                    result = submit_authentication_factor(
                        session_id=session.id,
                        credential_type=factor_form.cleaned_data["credential_type"],
                        identifier=factor_form.cleaned_data["identifier"],
                    )
                except ValidationError as exc:
                    _add_form_errors(factor_form, exc)
                else:
                    message_level = messages.SUCCESS if result["accepted"] else messages.WARNING
                    messages.add_message(request, message_level, result["message"])

                    if result["session"].is_complete:
                        return redirect("core:simulation-result", session_id=session.id)

                    return redirect("core:simulation-session", session_id=session.id)

    context = _get_session_context(session, include_demo_credentials=True)
    context["factor_form"] = factor_form
    return render(request, "core/simulation_session.html", context)


def simulation_result(request, session_id):
    session = _get_session_or_404(session_id)

    if not session.is_complete:
        return redirect("core:simulation-session", session_id=session.id)

    return render(request, "core/simulation_result.html", _get_session_context(session))
