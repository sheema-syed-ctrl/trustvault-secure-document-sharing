"""
Forms for document sharing and permission management in TrustVault.
Enforces validation for recipient existence, active status, role constraints,
and prohibited self-sharing.
"""

from django import forms
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _
from .models import PermissionType

User = get_user_model()


class DocumentShareForm(forms.Form):
    """
    Form for granting or updating document access to a registered user.
    """
    recipient_username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter recipient username...',
            'autocomplete': 'off',
            'id': 'recipientUsernameInput'
        }),
        help_text=_('Username of the registered user to receive access.')
    )
    permission_type = forms.ChoiceField(
        choices=PermissionType.choices,
        initial=PermissionType.READ,
        widget=forms.Select(attrs={
            'class': 'form-select',
            'id': 'permissionTypeSelect'
        }),
        help_text=_('Access level: READ allows viewing and downloading; EDIT allows modifying metadata.')
    )

    def __init__(self, *args, document=None, actor=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.document = document
        self.actor = actor
        self.recipient_user = None

    def clean_recipient_username(self):
        username = self.cleaned_data.get('recipient_username', '').strip()
        if not username:
            raise forms.ValidationError(_("Recipient username is required."))

        try:
            recipient = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError(_(f"User '{username}' does not exist."))

        if not recipient.is_active:
            raise forms.ValidationError(_(f"User '{username}' is inactive and cannot receive access."))

        if self.document and recipient.pk == self.document.owner_id:
            raise forms.ValidationError(_("You cannot share a document with yourself."))

        if self.actor and recipient.pk == self.actor.pk:
            raise forms.ValidationError(_("You cannot share a document with yourself."))

        self.recipient_user = recipient
        return username

    def clean_permission_type(self):
        perm_type = self.cleaned_data.get('permission_type')
        if perm_type not in PermissionType.values:
            raise forms.ValidationError(_(f"Invalid permission level: '{perm_type}'."))
        return perm_type


class DocumentPermissionUpdateForm(forms.Form):
    """
    Form for updating an existing recipient's permission between READ and EDIT.
    """
    permission_type = forms.ChoiceField(
        choices=PermissionType.choices,
        widget=forms.Select(attrs={'class': 'form-select form-select-sm'})
    )

    def clean_permission_type(self):
        perm_type = self.cleaned_data.get('permission_type')
        if perm_type not in PermissionType.values:
            raise forms.ValidationError(_(f"Invalid permission level: '{perm_type}'."))
        return perm_type
