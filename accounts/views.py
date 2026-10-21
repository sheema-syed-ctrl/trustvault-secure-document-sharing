"""
Authentication and user management views for TrustVault.
Implements secure login, POST-only logout, self-registration with role limits,
and administrative user management.
"""

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login as auth_login, logout as auth_logout, get_user_model
from django.contrib import messages
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST, require_http_methods
from django.core.paginator import Paginator
from .forms import UserLoginForm, UserRegistrationForm, AdminUserCreationForm, AdminUserUpdateForm
from .decorators import admin_required

User = get_user_model()


def login_view(request):
    """
    Secure user authentication endpoint.
    Enforces login rate limiting against brute-force attacks and credential stuffing.
    Rotates session key on success to prevent session fixation attacks.
    Validates redirect target against allowed hosts to prevent open redirects.
    """
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        raw_username = request.POST.get('username', '').strip()
        from .services import LoginRateLimitService

        is_blocked, retry_after = LoginRateLimitService.is_throttled(request, raw_username)
        if is_blocked:
            minutes = max(1, (retry_after + 59) // 60)
            messages.error(
                request,
                f"Too many failed login attempts. For security, login is temporarily throttled. "
                f"Please wait {minutes} minutes before trying again."
            )
            form = UserLoginForm(request, data=request.POST)
            return render(request, 'accounts/login.html', {'form': form}, status=429)

        form = UserLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            LoginRateLimitService.clear_failed_attempts(request, user.username)
            auth_login(request, user)
            messages.success(request, f"Welcome back, {user.username}! Signed in as {user.get_role_display()}.")

            # Safe redirect validation
            next_url = request.GET.get('next') or request.POST.get('next')
            if next_url and url_has_allowed_host_and_scheme(
                next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
            ):
                return redirect(next_url)
            return redirect('dashboard:index')
        else:
            LoginRateLimitService.record_failed_attempt(request, raw_username)
            messages.error(request, "Invalid username or password. Please verify your credentials.")
    else:
        form = UserLoginForm(request)

    return render(request, 'accounts/login.html', {'form': form})


@require_POST
def logout_view(request):
    """
    Secure logout endpoint.
    Restricted strictly to POST requests to prevent CSRF-induced logout attacks.
    Flushes session state and invalidates session cookie.
    """
    if request.user.is_authenticated:
        username = request.user.username
        auth_logout(request)
        messages.info(request, f"User {username} has been securely logged out.")
    return redirect('accounts:login')


def register_view(request):
    """
    Public registration endpoint.
    Permits registration only for OWNER or VIEWER roles.
    Rejects any unauthorized attempts to claim administrative privileges.
    """
    if request.user.is_authenticated:
        return redirect('dashboard:index')

    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(
                request,
                f"Account successfully created for {user.username} as {user.get_role_display()}! You may now sign in."
            )
            return redirect('accounts:login')
    else:
        form = UserRegistrationForm()

    return render(request, 'accounts/register.html', {'form': form})


@admin_required
def user_list_view(request):
    """
    Administrative directory of all registered users.
    Restricted strictly to platform administrators.
    """
    users_qs = User.objects.all().order_by('-date_joined')
    paginator = Paginator(users_qs, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'accounts/user_list.html', {
        'page_obj': page_obj,
        'total_users': users_qs.count(),
    })


@admin_required
def user_create_view(request):
    """
    Administrative user provisioning view.
    Allows administrators to explicitly create accounts with any role (ADMIN, OWNER, VIEWER).
    """
    if request.method == 'POST':
        form = AdminUserCreationForm(request.POST)
        if form.is_valid():
            new_user = form.save()
            messages.success(
                request,
                f"Successfully created user {new_user.username} with role {new_user.get_role_display()}."
            )
            return redirect('accounts:user_list')
    else:
        form = AdminUserCreationForm()

    return render(request, 'accounts/user_create.html', {'form': form})


@admin_required
def user_edit_role_view(request, user_id):
    """
    Administrative role modification and user status management.
    Prevents self-demotion or self-deactivation.
    """
    target_user = get_object_or_404(User, pk=user_id)

    if request.method == 'POST':
        form = AdminUserUpdateForm(request.POST, instance=target_user, current_admin=request.user)
        if form.is_valid():
            updated_user = form.save()
            messages.success(
                request,
                f"Updated user '{updated_user.username}': Role is now {updated_user.get_role_display()}."
            )
            return redirect('accounts:user_list')
    else:
        form = AdminUserUpdateForm(instance=target_user, current_admin=request.user)

    return render(request, 'accounts/user_edit.html', {
        'form': form,
        'target_user': target_user,
    })
