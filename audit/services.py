"""
Centralized audit service for TrustVault.
Provides tamper-resistant, persistent event logging and role-governed audit inspection.
Integrates with document workflows and object-level permission lifecycle.
"""

import logging
import uuid
from typing import Optional, Dict, Any
from django.db import transaction
from django.core.exceptions import PermissionDenied, ValidationError
from django.utils import timezone
from accounts.services import RBACService
from documents.models import Document
from .models import AuditEvent, AuditEventType, AuditStatus

logger = logging.getLogger('trustvault')

# Sensitive keys that must NEVER be written to audit metadata
SENSITIVE_METADATA_KEYS = {
    'password', 'password_hash', 'token', 'access_token', 'refresh_token',
    'secret', 'secret_key', 'session_id', 'sessionid', 'csrftoken',
    'csrf_token', 'cookie', 'cookies', 'authorization', 'auth',
    'private_key', 'api_key', 'file_path', 'storage_path', 'absolute_path'
}


class AuditLoggingError(Exception):
    """Raised when persistent audit event creation fails."""
    pass


class AuditService:
    """
    Centralized, server-side audit service for TrustVault.
    Guarantees:
      - Mandatory persistence to database-backed AuditEvent model.
      - Input validation and metadata sanitization.
      - Never allows client-controlled actor spoofing.
      - Transactional integrity with business operations.
      - Strict role separation for audit event inspection.
    """

    @staticmethod
    def get_client_ip(request) -> Optional[str]:
        """Extracts and returns the sanitized client IP address from a request."""
        if not request:
            return None
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        # Simple length and sanity check for IP address
        if ip and len(ip) <= 45:
            return ip
        return None

    @staticmethod
    def get_user_agent(request) -> str:
        """Extracts and truncates client user agent string."""
        if not request:
            return ''
        ua = request.META.get('HTTP_USER_AGENT', '')
        return ua[:512] if ua else ''

    @classmethod
    def sanitize_metadata(cls, raw_metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Deep-sanitizes metadata payload to strip sensitive credentials, tokens, and storage paths.
        """
        if not raw_metadata or not isinstance(raw_metadata, dict):
            return {}

        clean_dict = {}
        for key, val in raw_metadata.items():
            key_str = str(key).lower().strip()
            # Omit sensitive keys
            if any(sensitive in key_str for sensitive in SENSITIVE_METADATA_KEYS):
                continue

            # Ensure value is JSON serializable and does not expose file paths
            if isinstance(val, (str, int, float, bool)) or val is None:
                val_str = str(val).lower()
                # Redact local system drive letters or directory structures
                if any(ind in val_str for ind in ['f:\\', 'c:\\', '/var/', '/etc/', '/tmp/']):  # nosec B108
                    continue
                clean_dict[str(key)] = val
            elif isinstance(val, dict):
                clean_dict[str(key)] = cls.sanitize_metadata(val)
            elif isinstance(val, (list, tuple)):
                clean_dict[str(key)] = [
                    v for v in val if isinstance(v, (str, int, float, bool))
                ]
        return clean_dict

    @classmethod
    def log_event(
        cls,
        event_type: str,
        actor=None,
        target_document: Optional[Document] = None,
        target_document_id: Optional[int] = None,
        target_document_name: Optional[str] = None,
        target_user=None,
        previous_permission: str = '',
        new_permission: str = '',
        status: str = AuditStatus.SUCCESS,
        request=None,
        correlation_id: str = '',
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """
        Primary factory for recording a persistent audit event.
        Validates event type and parameters, extracts request context,
        sanitizes metadata, and writes append-only record to database.
        """
        if event_type not in AuditEventType.values:
            raise ValidationError(f"Invalid audit event type: '{event_type}'.")

        if status not in AuditStatus.values:
            raise ValidationError(f"Invalid audit status: '{status}'.")

        # Derive actor details
        actor_user = None
        actor_username = ''
        if actor and getattr(actor, 'is_authenticated', False):
            actor_user = actor
            actor_username = actor.username
        elif request and getattr(request, 'user', None) and request.user.is_authenticated:
            actor_user = request.user
            actor_username = request.user.username

        # Derive target document details and historical snapshots
        doc_instance = target_document
        doc_id_snapshot = target_document_id
        doc_name_snapshot = target_document_name or ''
        if doc_instance:
            doc_id_snapshot = doc_instance.pk
            doc_name_snapshot = doc_instance.name

        # Derive target user details and historical snapshots
        target_user_instance = target_user
        target_username_snapshot = ''
        if target_user_instance:
            target_username_snapshot = getattr(target_user_instance, 'username', '')

        # Network and request metadata
        ip_addr = cls.get_client_ip(request)
        ua = cls.get_user_agent(request)
        clean_meta = cls.sanitize_metadata(metadata)

        try:
            event = AuditEvent.objects.create(
                event_type=event_type,
                status=status,
                actor=actor_user,
                actor_username=actor_username,
                target_document=doc_instance,
                target_document_id_snapshot=doc_id_snapshot,
                target_document_name_snapshot=doc_name_snapshot,
                target_user=target_user_instance,
                target_username=target_username_snapshot,
                previous_permission=previous_permission or '',
                new_permission=new_permission or '',
                ip_address=ip_addr,
                user_agent=ua,
                correlation_id=correlation_id or '',
                metadata=clean_meta,
                timestamp=timezone.now()
            )
            return event
        except Exception as exc:
            logger.error(f"CRITICAL: Failed to write persistent audit event '{event_type}': {exc}", exc_info=True)
            raise AuditLoggingError(f"Audit log recording failed: {exc}") from exc

    # -------------------------------------------------------------------------
    # High-level domain activity loggers
    # -------------------------------------------------------------------------

    @classmethod
    def log_document_uploaded(cls, actor, document: Document, request=None, metadata: Optional[Dict] = None) -> AuditEvent:
        """Records a successful document upload."""
        meta = metadata or {}
        meta.update({
            'original_filename': document.original_filename,
            'file_size': document.file_size,
            'mime_type': document.mime_type,
            'category': document.category,
        })
        return cls.log_event(
            event_type=AuditEventType.DOCUMENT_UPLOADED,
            actor=actor,
            target_document=document,
            request=request,
            metadata=meta
        )

    @classmethod
    def log_document_downloaded(cls, actor, document: Document, request=None, metadata: Optional[Dict] = None) -> AuditEvent:
        """Records an authorized document streaming/download initiation."""
        meta = metadata or {}
        meta.update({
            'original_filename': document.original_filename,
            'file_size': document.file_size,
            'mime_type': document.mime_type,
        })
        return cls.log_event(
            event_type=AuditEventType.DOCUMENT_DOWNLOADED,
            actor=actor,
            target_document=document,
            request=request,
            metadata=meta
        )

    @classmethod
    def log_document_updated(cls, actor, document: Document, request=None, metadata: Optional[Dict] = None) -> AuditEvent:
        """Records a document metadata update."""
        meta = metadata or {}
        meta.update({
            'category': document.category,
            'updated_name': document.name,
        })
        return cls.log_event(
            event_type=AuditEventType.DOCUMENT_UPDATED,
            actor=actor,
            target_document=document,
            request=request,
            metadata=meta
        )

    @classmethod
    def log_document_deleted(cls, actor, document_id: int, document_name: str, request=None, metadata: Optional[Dict] = None) -> AuditEvent:
        """Records a document deletion with permanent historical snapshots."""
        return cls.log_event(
            event_type=AuditEventType.DOCUMENT_DELETED,
            actor=actor,
            target_document=None,
            target_document_id=document_id,
            target_document_name=document_name,
            request=request,
            metadata=metadata
        )

    @classmethod
    def log_permission_granted(
        cls,
        actor,
        document: Document,
        recipient,
        permission_type: str,
        request=None,
        metadata: Optional[Dict] = None
    ) -> AuditEvent:
        """Records granting of object-level document access to a recipient."""
        return cls.log_event(
            event_type=AuditEventType.PERMISSION_GRANTED,
            actor=actor,
            target_document=document,
            target_user=recipient,
            new_permission=permission_type,
            request=request,
            metadata=metadata
        )

    @classmethod
    def log_permission_updated(
        cls,
        actor,
        document: Document,
        recipient,
        previous_permission: str,
        new_permission: str,
        request=None,
        metadata: Optional[Dict] = None
    ) -> AuditEvent:
        """Records modification of an existing recipient's permission level."""
        return cls.log_event(
            event_type=AuditEventType.PERMISSION_UPDATED,
            actor=actor,
            target_document=document,
            target_user=recipient,
            previous_permission=previous_permission,
            new_permission=new_permission,
            request=request,
            metadata=metadata
        )

    @classmethod
    def log_permission_revoked(
        cls,
        actor,
        document: Document,
        recipient,
        previous_permission: str,
        request=None,
        metadata: Optional[Dict] = None
    ) -> AuditEvent:
        """Records revocation of access on a document."""
        return cls.log_event(
            event_type=AuditEventType.PERMISSION_REVOKED,
            actor=actor,
            target_document=document,
            target_user=recipient,
            previous_permission=previous_permission,
            request=request,
            metadata=metadata
        )

    @classmethod
    def log_access_denied(
        cls,
        actor,
        event_type: str,
        document: Optional[Document] = None,
        reason: str = '',
        request=None,
        metadata: Optional[Dict] = None
    ) -> AuditEvent:
        """Records unauthorized access attempts and security denials."""
        meta = metadata or {}
        if reason:
            meta['reason'] = str(reason)[:255]
        return cls.log_event(
            event_type=AuditEventType.SECURITY_ACCESS_DENIED,
            actor=actor,
            target_document=document,
            status=AuditStatus.FAILURE,
            request=request,
            metadata=meta
        )

    # -------------------------------------------------------------------------
    # Retrieval & Query authorization
    # -------------------------------------------------------------------------

    @classmethod
    def get_global_audit_trail(cls, user, event_type: str = '', actor_query: str = '', date_from=None, date_to=None):
        """
        Retrieves global audit trail records.
        Strictly restricted to users with Administrator privileges.
        """
        if not RBACService.can_view_audit_logs(user):
            logger.warning(
                f"Unauthorized global audit trail access attempt: User '{getattr(user, 'username', 'anon')}' "
                f"(ID: {getattr(user, 'pk', None)}, Role: {getattr(user, 'role', 'None')}) denied."
            )
            raise PermissionDenied("Access denied: Only Administrators are authorized to view the global audit trail.")

        queryset = AuditEvent.objects.all().select_related('actor', 'target_document', 'target_user')

        if event_type:
            queryset = queryset.filter(event_type=event_type)
        if actor_query:
            queryset = queryset.filter(actor_username__icontains=actor_query)
        if date_from:
            queryset = queryset.filter(timestamp__date__gte=date_from)
        if date_to:
            queryset = queryset.filter(timestamp__date__lte=date_to)

        return queryset.order_by('-timestamp')

    @classmethod
    def get_document_audit_trail(cls, user, document: Document):
        """
        Retrieves activity history for a specific document.
        Strictly restricted to the authentic Document Owner.
        """
        if not user or not user.is_authenticated:
            raise PermissionDenied("Authentication required to access document activity.")

        if document.owner_id != user.pk:
            logger.warning(
                f"Unauthorized document activity view attempt: User '{user.username}' (ID: {user.pk}) "
                f"attempted to view activity for document {document.pk} owned by '{document.owner.username}'."
            )
            raise PermissionDenied("Access denied: Only the document owner can inspect activity for this document.")

        return AuditEvent.objects.filter(
            target_document=document
        ).select_related('actor', 'target_user').order_by('-timestamp')
