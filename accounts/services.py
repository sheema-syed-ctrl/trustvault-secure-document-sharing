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

import hashlib
import logging
from typing import Tuple
from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger('trustvault')


class LoginRateLimitService:
    """
    Production-grade rate limiter for authentication endpoints.
    Protects against credential stuffing and brute-force password guessing.
    Features:
      - Multi-factor keying: Throttles by client IP address and normalized username.
      - Default threshold: 5 failed attempts per 5-minute window (300 seconds).
      - Clears failure counter immediately on successful authentication.
      - Uniform behavior regardless of whether an account exists, mitigating user enumeration.
      - Never permanently locks users out; recovery occurs automatically once window elapses.
      - Configurable via settings.LOGIN_RATE_LIMIT_MAX_ATTEMPTS and settings.LOGIN_RATE_LIMIT_TIMEOUT.
    """
    DEFAULT_MAX_ATTEMPTS = 5
    DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes

    @classmethod
    def get_max_attempts(cls) -> int:
        return getattr(settings, 'LOGIN_RATE_LIMIT_MAX_ATTEMPTS', cls.DEFAULT_MAX_ATTEMPTS)

    @classmethod
    def get_timeout_seconds(cls) -> int:
        return getattr(settings, 'LOGIN_RATE_LIMIT_TIMEOUT', cls.DEFAULT_TIMEOUT_SECONDS)

    @staticmethod
    def get_client_ip(request) -> str:
        if not request:
            return '127.0.0.1'
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
        return ip or '127.0.0.1'

    @classmethod
    def get_cache_keys(cls, request, username: str) -> Tuple[str, str]:
        ip = cls.get_client_ip(request)
        clean_user = (username or '').strip().lower()
        ip_hash = hashlib.sha256(ip.encode('utf-8')).hexdigest()[:16]
        user_hash = hashlib.sha256(clean_user.encode('utf-8')).hexdigest()[:16]
        return f"rl:ip:{ip_hash}", f"rl:user:{user_hash}"

    @classmethod
    def is_throttled(cls, request, username: str) -> Tuple[bool, int]:
        """
        Checks if the IP or username is currently throttled.
        Returns:
            (is_blocked: bool, retry_after_seconds: int)
        """
        ip_key, user_key = cls.get_cache_keys(request, username)
        ip_attempts = cache.get(ip_key, 0)
        user_attempts = cache.get(user_key, 0)
        max_attempts = cls.get_max_attempts()

        if ip_attempts >= max_attempts or user_attempts >= max_attempts:
            timeout = cls.get_timeout_seconds()
            return True, timeout
        return False, 0

    @classmethod
    def record_failed_attempt(cls, request, username: str) -> int:
        """
        Increments failed attempt counters for client IP and username.
        Returns the new maximum attempt count.
        """
        ip_key, user_key = cls.get_cache_keys(request, username)
        timeout = cls.get_timeout_seconds()

        try:
            ip_count = cache.get(ip_key, 0) + 1
            cache.set(ip_key, ip_count, timeout=timeout)
        except Exception:
            ip_count = 1

        try:
            user_count = cache.get(user_key, 0) + 1
            cache.set(user_key, user_count, timeout=timeout)
        except Exception:
            user_count = 1

        return max(ip_count, user_count)

    @classmethod
    def clear_failed_attempts(cls, request, username: str) -> None:
        """
        Clears failed attempt counters upon successful authentication.
        """
        ip_key, user_key = cls.get_cache_keys(request, username)
        try:
            cache.delete(ip_key)
            cache.delete(user_key)
        except Exception as exc:
            logger.warning("Failed to clear login rate limit cache: %s", exc)
