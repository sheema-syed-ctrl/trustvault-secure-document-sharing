"""
Centralized Role-Based Access Control (RBAC) service for TrustVault.
Provides server-side authorization checks and enforcement routines.
"""

from django.contrib.auth import get_user_model

User = get_user_model()


class RBACService:
    """
    Centralized service enforcing TrustVault's Role-Based Access Control policies.
    Guarantees:
      - Default-deny evaluation.
      - Explicit distinction between Administrator, Document Owner, and Viewer roles.
      - Administrators do NOT automatically inherit document content access.
    """

    @staticmethod
    def is_admin(user) -> bool:
        """Check if user has Administrator role or superuser privilege."""
        if not user or not user.is_authenticated:
            return False
        return user.role == User.Role.ADMIN or user.is_superuser

    @staticmethod
    def is_owner(user) -> bool:
        """Check if user has Document Owner role."""
        if not user or not user.is_authenticated:
            return False
        return user.role == User.Role.OWNER

    @staticmethod
    def is_viewer(user) -> bool:
        """Check if user has Viewer role."""
        if not user or not user.is_authenticated:
            return False
        return user.role == User.Role.VIEWER

    @staticmethod
    def can_manage_users(user) -> bool:
        """Only administrators can manage platform users and role assignments."""
        return RBACService.is_admin(user)

    @staticmethod
    def can_view_audit_logs(user) -> bool:
        """Only administrators can inspect global audit logs."""
        return RBACService.is_admin(user)

    @staticmethod
    def can_upload_documents(user) -> bool:
        """Only Document Owners can upload new documents to the vault."""
        return RBACService.is_owner(user)

    @staticmethod
    def can_register_role(requested_role: str) -> bool:
        """Public self-registration is strictly restricted to OWNER and VIEWER."""
        return requested_role in [User.Role.OWNER, User.Role.VIEWER]
