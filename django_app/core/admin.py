from django.contrib import admin
from django.db.models import Count

from .models import (
    AccessPolicy,
    AuditEvent,
    AuthenticationSession,
    Credential,
    ProtectedResource,
)


@admin.register(ProtectedResource)
class ProtectedResourceAdmin(admin.ModelAdmin):
    list_display = ("name", "active", "policy_count", "session_count", "created_at")
    list_filter = ("active",)
    list_editable = ("active",)
    ordering = ("name",)
    readonly_fields = ("created_at", "updated_at")
    search_help_text = "Search by resource name or description."
    search_fields = ("name", "description")
    fieldsets = (
        ("Resource", {"fields": ("name", "description", "active")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.annotate(
            policy_total=Count("policies", distinct=True),
            session_total=Count("authentication_sessions", distinct=True),
        )

    @admin.display(ordering="policy_total", description="Policies")
    def policy_count(self, obj):
        return obj.policy_total

    @admin.display(ordering="session_total", description="Sessions")
    def session_count(self, obj):
        return obj.session_total


@admin.register(AccessPolicy)
class AccessPolicyAdmin(admin.ModelAdmin):
    list_display = ("name", "resource", "tier", "required_factor_count", "active", "updated_at")
    list_filter = ("tier", "active")
    list_select_related = ("resource",)
    list_editable = ("active",)
    ordering = ("resource__name", "name")
    autocomplete_fields = ("resource",)
    readonly_fields = ("created_at", "updated_at")
    search_help_text = "Search by policy name, resource, or description."
    search_fields = ("name", "resource__name", "description")
    fieldsets = (
        ("Policy", {"fields": ("resource", "name", "description")}),
        ("Requirements", {"fields": ("tier", "required_factor_count", "active")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )


@admin.register(Credential)
class CredentialAdmin(admin.ModelAdmin):
    list_display = (
        "display_name",
        "user",
        "credential_type",
        "identifier",
        "active",
        "updated_at",
    )
    list_filter = ("credential_type", "active")
    list_select_related = ("user",)
    list_editable = ("active",)
    ordering = ("user__username", "credential_type", "identifier")
    autocomplete_fields = ("user",)
    readonly_fields = ("created_at", "updated_at")
    search_help_text = "Search by username, credential label, or identifier."
    search_fields = ("user__username", "identifier", "label")
    fieldsets = (
        ("Credential", {"fields": ("user", "credential_type", "label", "identifier", "active")}),
        ("Metadata", {"fields": ("metadata",)}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    )

    @admin.display(description="Credential")
    def display_name(self, obj):
        return obj.label or obj.identifier


@admin.register(AuthenticationSession)
class AuthenticationSessionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "resource",
        "user",
        "policy",
        "status",
        "decision",
        "progress_display",
        "submitted_factor_total",
        "started_at",
        "completed_at",
    )
    list_filter = ("status", "decision", "resource", "policy")
    list_select_related = ("user", "resource", "policy")
    date_hierarchy = "started_at"
    ordering = ("-started_at",)
    autocomplete_fields = ("user", "resource", "policy")
    readonly_fields = (
        "progress_display",
        "submitted_factor_total",
        "details",
        "started_at",
        "updated_at",
        "completed_at",
    )
    search_help_text = "Search by session ID, username, or resource name."
    search_fields = ("=id", "user__username", "resource__name")
    fieldsets = (
        ("Session", {"fields": ("resource", "user", "policy")}),
        ("State", {"fields": ("status", "decision", "current_step")}),
        ("Progress", {"fields": ("progress_display", "submitted_factor_total", "details")}),
        ("Timestamps", {"fields": ("started_at", "completed_at", "updated_at")}),
    )

    @admin.display(description="Progress")
    def progress_display(self, obj):
        return f"{obj.accepted_factor_count}/{obj.required_factor_count}"

    @admin.display(description="Submitted")
    def submitted_factor_total(self, obj):
        return len(obj.submitted_factors)


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "severity", "event_type", "user", "session", "short_message")
    list_filter = ("severity", "event_type")
    list_select_related = ("user", "session")
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    autocomplete_fields = ("user", "session")
    readonly_fields = ("timestamp",)
    search_help_text = "Search by event type, message, or username."
    search_fields = ("event_type", "message", "user__username")
    fieldsets = (
        ("Event", {"fields": ("event_type", "severity", "message")}),
        ("Relations", {"fields": ("user", "session")}),
        ("Details", {"fields": ("details", "timestamp")}),
    )

    @admin.display(description="Message")
    def short_message(self, obj):
        if len(obj.message) <= 80:
            return obj.message
        return f"{obj.message[:77]}..."


admin.site.site_header = "MFA System Administration"
admin.site.site_title = "MFA Admin"
admin.site.index_title = "Backend Management"
