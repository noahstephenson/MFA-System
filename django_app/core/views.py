from django.core.exceptions import ValidationError
from django.http import Http404
from django.db.models import Prefetch
from django.shortcuts import render

from .models import AccessPolicy, AuditEvent, AuthenticationSession, Credential, ProtectedResource
from .services import get_authentication_session


def home(request):
    recent_sessions = AuthenticationSession.objects.select_related(
        "resource",
        "user",
        "policy",
    )[:5]
    recent_audit_events = AuditEvent.objects.select_related("session", "user")[:5]

    context = {
        "resource_count": ProtectedResource.objects.filter(active=True).count(),
        "session_count": AuthenticationSession.objects.count(),
        "credential_count": Credential.objects.filter(active=True).count(),
        "audit_event_count": AuditEvent.objects.count(),
        "recent_sessions": recent_sessions,
        "recent_audit_events": recent_audit_events,
    }
    return render(request, "core/home.html", context)


def protected_resource_list(request):
    resources = ProtectedResource.objects.prefetch_related(
        Prefetch(
            "policies",
            queryset=AccessPolicy.objects.filter(active=True).order_by("name"),
            to_attr="active_policies",
        )
    )
    return render(request, "core/protected_resource_list.html", {"resources": resources})


def authentication_session_detail(request, session_id):
    try:
        session = get_authentication_session(session_id)
    except ValidationError as exc:
        raise Http404(exc.messages[0]) from exc

    session_audit_events = session.audit_events.select_related("user")[:10]
    context = {"session": session, "session_audit_events": session_audit_events}
    return render(request, "core/authentication_session_detail.html", context)


def audit_log(request):
    audit_events = AuditEvent.objects.select_related("session", "user")[:50]
    return render(request, "core/audit_log.html", {"audit_events": audit_events})
