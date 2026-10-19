"""
Forms for authentication, user self-registration, and administrative user management.
Enforces role validation, password validation, and prevents privilege escalation.
"""

from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError
from .services import RBACService

User = get_user_model()


class UserLoginForm(AuthenticationForm):
    """Secure login form with Bootstrap UI widgets."""

    username = forms.CharField(
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your username',
            'autocomplete': 'username',
            'autofocus': True,
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter your password',
            'autocomplete': 'current-password',
        })
    )


class UserRegistrationForm(UserCreationForm):
    """
    Public user registration form.
    CRITICAL SECURITY RULE:
    Self-registration is strictly restricted to OWNER or VIEWER roles.
    Users cannot register themselves as ADMINISTRATOR.
    """

    PUBLIC_ROLE_CHOICES = [
        (User.Role.OWNER, 'Document Owner (Can upload and share documents)'),
        (User.Role.VIEWER, 'Viewer (Can view and access shared documents)'),
    ]

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'name@example.com',
            'autocomplete': 'email',
        })
    )
    role = forms.ChoiceField(
        choices=PUBLIC_ROLE_CHOICES,
        initial=User.Role.VIEWER,
        widget=forms.Select(attrs={'class': 'form-select'}),
        help_text='Select your role within TrustVault.'
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'role')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Choose a unique username',
            'autocomplete': 'username',
        })
        self.fields['password1'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Create a strong password (min 8 characters)',
            'autocomplete': 'new-password',
        })
        self.fields['password2'].widget.attrs.update({
            'class': 'form-control',
            'placeholder': 'Confirm your password',
            'autocomplete': 'new-password',
        })

    def clean_role(self):
        """Server-side defense against privilege escalation via parameter tampering."""
        role = self.cleaned_data.get('role')
        if not RBACService.can_register_role(role):
            raise ValidationError("Privilege escalation detected: Public self-registration as Administrator is strictly prohibited.")
        return role

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError("A user with this email address already exists.")
        return email


class AdminUserCreationForm(UserCreationForm):
    """Form used exclusively by administrators to provision any account role."""

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    role = forms.ChoiceField(
        choices=User.Role.choices,
        widget=forms.Select(attrs={'class': 'form-select'})
    )

    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'role', 'is_active')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in ['username', 'first_name', 'last_name']:
            self.fields[field].widget.attrs.update({'class': 'form-control'})


class AdminUserUpdateForm(forms.ModelForm):
    """
    Form for administrators to update an existing user's role and status.
    Enforces rules preventing self-lockout or accidental self-demotion.
    """

    class Meta:
        model = User
        fields = ('role', 'is_active', 'first_name', 'last_name', 'email')
        widgets = {
            'role': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'first_name': forms.TextInput(attrs={'class': 'form-control'}),
            'last_name': forms.TextInput(attrs={'class': 'form-control'}),
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, current_admin=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.current_admin = current_admin

    def clean(self):
        cleaned_data = super().clean()
        target_user = self.instance
        new_role = cleaned_data.get('role')
        is_active = cleaned_data.get('is_active')

        # Prevent admin from deactivating or demoting themselves
        if self.current_admin and target_user.pk == self.current_admin.pk:
            if new_role != User.Role.ADMIN:
                raise ValidationError("Self-demotion prevented: Administrators cannot remove their own administrator role.")
            if is_active is False:
                raise ValidationError("Self-deactivation prevented: You cannot deactivate your own administrative account.")

        return cleaned_data
