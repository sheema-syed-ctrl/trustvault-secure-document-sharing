from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    """
    Custom user model for TrustVault enforcing strict Role-Based Access Control (RBAC).
    Roles defined:
      - ADMIN: Manages users, inspects audit logs and permission changes.
      - OWNER: Uploads, manages, and shares own documents; revokes access.
      - VIEWER: Read-only or permitted access to documents explicitly shared with them.
    """

    class Role(models.TextChoices):
        ADMIN = 'ADMIN', _('Administrator')
        OWNER = 'OWNER', _('Document Owner')
        VIEWER = 'VIEWER', _('Viewer')

    role = models.CharField(
        max_length=10,
        choices=Role.choices,
        default=Role.VIEWER,
        help_text=_('Defines user role in TrustVault RBAC.')
    )

    @property
    def is_admin_role(self) -> bool:
        """Explicit check for administrator role or superuser privilege."""
        return self.role == self.Role.ADMIN or self.is_superuser

    @property
    def is_owner_role(self) -> bool:
        """Check if user has Document Owner role."""
        return self.role == self.Role.OWNER

    @property
    def is_viewer_role(self) -> bool:
        """Check if user has Viewer role."""
        return self.role == self.Role.VIEWER

    def __str__(self):
        return f"{self.username} [{self.get_role_display()}]"
