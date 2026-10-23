"""
Django settings for TrustVault project.
Built for the Snovasys Fresher Hiring Challenge 2026.
Secure Document Sharing Platform with a Real Audit Trail.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Load environment variables from .env file if it exists
load_dotenv(BASE_DIR / '.env')

# Deployment environment detection
_is_vercel = os.getenv('VERCEL') == '1' or bool(os.getenv('VERCEL_ENV'))
_is_production = (
    _is_vercel
    or os.getenv('DJANGO_ENV', '').lower() == 'production'
    or os.getenv('RENDER') == 'true'
)
_is_testing = 'test' in sys.argv or 'pytest' in sys.modules or os.getenv('DJANGO_TESTING') == '1'

# Debug mode:
# Set DEBUG=False for production to prevent public exposure of technical debug pages or request metadata.
# In local development, defaults to True unless overridden via environment variable.
if _is_production:
    DEBUG = False
else:
    DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 'yes')

# Secret key strictly loaded from environment; fallback provided for serverless builds
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = 'django-insecure-dev-fallback-key-for-local-development-only'  # nosec B105
    else:
        SECRET_KEY = os.getenv(
            'SECRET_KEY_FALLBACK',
            'django-insecure-trustvault-production-cloud-key-fallback-2026'
        )  # nosec B105

# Host validation configuration:
# 1. Base loopback hosts always permitted for local development, internal routing, and health checks.
# 2. Production Vercel deployment domains (sheema-ivory.vercel.app, .vercel.app) always guaranteed.
# 3. Dynamic Vercel environment domains (VERCEL_URL, VERCEL_PROJECT_PRODUCTION_URL).
# 4. Safely parse comma-separated hostnames from ALLOWED_HOSTS env var, trimming whitespace.
# 5. Wildcard '*' is strictly prohibited to prevent HTTP Host header poisoning.
_base_hosts = ['127.0.0.1', 'localhost', '[::1]']
_production_hosts = ['sheema-ivory.vercel.app', '.vercel.app']

_vercel_url = os.getenv('VERCEL_URL', '').strip()
if _vercel_url:
    _production_hosts.append(_vercel_url)
_vercel_prod_url = os.getenv('VERCEL_PROJECT_PRODUCTION_URL', '').strip()
if _vercel_prod_url:
    _production_hosts.append(_vercel_prod_url)

_env_hosts = [
    host.strip()
    for host in os.getenv('ALLOWED_HOSTS', '').split(',')
    if host.strip()
]

_all_hosts = _base_hosts + _production_hosts + _env_hosts
ALLOWED_HOSTS = []
for host in _all_hosts:
    if host != '*' and host not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(host)


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # TrustVault domain apps
    'core.apps.CoreConfig',
    'accounts.apps.AccountsConfig',
    'documents.apps.DocumentsConfig',
    'permissions.apps.PermissionsConfig',
    'audit.apps.AuditConfig',
    'dashboard.apps.DashboardConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'trustvault.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'trustvault.wsgi.application'


# Custom User Model
AUTH_USER_MODEL = 'accounts.User'


# Database Configuration:
# - SQLite for local development when DATABASE_URL is not configured
# - PostgreSQL via DATABASE_URL in production (Neon serverless with PgBouncer connection pooling)
# - Silent fallback to SQLite is strictly forbidden in production to prevent read-only filesystem errors and data loss
DATABASE_URL = os.getenv('DATABASE_URL')
DB_ENGINE = os.getenv('DB_ENGINE', 'sqlite').lower()

if DATABASE_URL:
    import dj_database_url
    # In serverless environments (e.g. Vercel Lambda), persistent connections cause pool exhaustion.
    # Default to 0 in production so connections close after each request, or respect CONN_MAX_AGE env var.
    _default_conn_max_age = 0 if _is_production else 600
    _conn_max_age = int(os.getenv('CONN_MAX_AGE', str(_default_conn_max_age)))
    DATABASES = {
        'default': dj_database_url.config(
            default=DATABASE_URL,
            conn_max_age=_conn_max_age,
            conn_health_checks=False if _conn_max_age == 0 else True,
            ssl_require=True,
            disable_server_side_cursors=True,
        )
    }
    # Neon PgBouncer transaction pooling requires disabling server-side cursors
    DATABASES['default']['DISABLE_SERVER_SIDE_CURSORS'] = True
    if 'OPTIONS' not in DATABASES['default']:
        DATABASES['default']['OPTIONS'] = {}
    DATABASES['default']['OPTIONS'].setdefault('sslmode', 'require')

elif DB_ENGINE == 'postgresql':
    _default_conn_max_age = 0 if _is_production else 600
    _conn_max_age = int(os.getenv('CONN_MAX_AGE', str(_default_conn_max_age)))
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'trustvault_db'),
            'USER': os.getenv('DB_USER', 'trustvault_user'),
            'PASSWORD': os.getenv('DB_PASSWORD', ''),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
            'CONN_MAX_AGE': _conn_max_age,
            'DISABLE_SERVER_SIDE_CURSORS': True,
            'OPTIONS': {
                'sslmode': os.getenv('DB_SSLMODE', 'require' if _is_production else 'prefer'),
            },
        }
    }

elif _is_production:
    if 'collectstatic' in sys.argv or 'check' in sys.argv:
        # Allow static file collection or preflight checks during container build
        # without requiring an active live database network connection.
        DATABASES = {
            'default': {
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': ':memory:',
            }
        }
    else:
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            "DATABASE_URL must be configured in production environments. "
            "PostgreSQL (Neon) is required for persistent data storage; "
            "silent fallback to SQLite is prohibited in production to prevent read-only filesystem errors and data loss."
        )

else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8},
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
if _is_vercel:
    import tempfile
    STATIC_ROOT = Path(tempfile.gettempdir()) / 'staticfiles'
else:
    STATIC_ROOT = BASE_DIR / 'staticfiles'

# Safe directory creation: avoid startup failure in read-only environments (e.g. Vercel serverless)
try:
    STATIC_ROOT.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

# When WhiteNoise is enabled, fallback gracefully if unmanifested static files are referenced
WHITENOISE_USE_FINDERS = True
WHITENOISE_MANIFEST_STRICT = os.getenv('WHITENOISE_MANIFEST_STRICT', 'False').lower() in ('true', '1')

# Static Files Storage Configuration (WhiteNoise in production)
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage" if not DEBUG else "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}


# PROTECTED FILE STORAGE
# Crucial Security Rule: Protected documents MUST NEVER be stored in public MEDIA_ROOT
# or served directly via web server static handlers.
# All document access MUST flow through authenticated, authorized controller endpoints.
_protected_media_env = os.getenv('PROTECTED_MEDIA_DIR', 'protected_media')
if os.path.isabs(_protected_media_env):
    PROTECTED_MEDIA_ROOT = Path(_protected_media_env)
else:
    PROTECTED_MEDIA_ROOT = BASE_DIR / _protected_media_env

# Safe directory creation: avoid startup failure if storage root is read-only
try:
    PROTECTED_MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
except OSError:
    pass

# Maximum file upload size (default 25 MB)
MAX_UPLOAD_SIZE_BYTES = int(os.getenv('MAX_UPLOAD_SIZE_MB', '25')) * 1024 * 1024

# Permitted upload MIME types & extensions
PERMITTED_FILE_TYPES = {
    'application/pdf': ['.pdf'],
    'image/png': ['.png'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'text/plain': ['.txt'],
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/msword': ['.doc'],
}


# Neon Object Storage (S3-Compatible) Configuration:
# - Configured exclusively via environment variables
# - Private bucket storage for confidential document binaries (.bin)
# - Direct public access and pre-signed public URLs are strictly forbidden
AWS_ENDPOINT_URL_S3 = os.getenv('AWS_ENDPOINT_URL_S3') or os.getenv('AWS_ENDPOINT_URL')
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME')

_has_s3_config = bool(
    AWS_STORAGE_BUCKET_NAME
    and AWS_ACCESS_KEY_ID
    and AWS_SECRET_ACCESS_KEY
    and AWS_ENDPOINT_URL_S3
)

# Storage backend selection:
# - 's3': Neon Object Storage (required in production, default when credentials configured)
# - 'local': Local filesystem storage (PROTECTED_MEDIA_ROOT, for offline dev and local tests)
_storage_backend_env = os.getenv('DOCUMENTS_STORAGE_BACKEND', '').lower()

if _storage_backend_env in ('s3', 'local'):
    DOCUMENTS_STORAGE_BACKEND = _storage_backend_env
elif _is_production or (_has_s3_config and not _is_testing):
    DOCUMENTS_STORAGE_BACKEND = 's3'
else:
    DOCUMENTS_STORAGE_BACKEND = 'local'

# Production Storage Safeguards:
# Local filesystem storage in production serverless is strictly prohibited.
if _is_production and not ('collectstatic' in sys.argv or 'check' in sys.argv):
    if DOCUMENTS_STORAGE_BACKEND != 's3':
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            "DOCUMENTS_STORAGE_BACKEND cannot be 'local' in production. "
            "Neon Object Storage (S3) is required for persistent document storage; "
            "silent fallback to local filesystem is prohibited to prevent read-only filesystem errors and data loss."
        )
    if not _has_s3_config:
        from django.core.exceptions import ImproperlyConfigured
        raise ImproperlyConfigured(
            "Neon Object Storage credentials (AWS_STORAGE_BUCKET_NAME, AWS_ACCESS_KEY_ID, "
            "AWS_SECRET_ACCESS_KEY, AWS_ENDPOINT_URL_S3) must be configured in production environments. "
            "Silent fallback to local filesystem storage is strictly prohibited."
        )


# Authentication and Authorization Redirects
LOGIN_URL = 'accounts:login'
LOGIN_REDIRECT_URL = 'dashboard:index'
LOGOUT_REDIRECT_URL = 'accounts:login'


# Security Headers & Cookie Policies
X_FRAME_OPTIONS = 'DENY'
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 3600 * 4  # 4 hours idle session
SESSION_SAVE_EVERY_REQUEST = True

CSRF_COOKIE_HTTPONLY = False  # Allows JS to read token if needed for AJAX, but standard forms use {% csrf_token %}
CSRF_COOKIE_SAMESITE = 'Lax'

# CSRF Trusted Origins for reverse proxies and PaaS providers (e.g. Render, Railway, Vercel)
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv('CSRF_TRUSTED_ORIGINS', '').split(',')
    if origin.strip()
]

# Ensure Vercel production domains are always trusted for HTTPS CSRF verification
_trusted_defaults = [
    'https://sheema-ivory.vercel.app',
    'https://*.vercel.app',
]
for _origin in _trusted_defaults:
    if _origin not in CSRF_TRUSTED_ORIGINS:
        CSRF_TRUSTED_ORIGINS.append(_origin)

if _vercel_url and f'https://{_vercel_url}' not in CSRF_TRUSTED_ORIGINS:
    CSRF_TRUSTED_ORIGINS.append(f'https://{_vercel_url}')
if _vercel_prod_url and f'https://{_vercel_prod_url}' not in CSRF_TRUSTED_ORIGINS:
    CSRF_TRUSTED_ORIGINS.append(f'https://{_vercel_prod_url}')

# Reverse Proxy SSL Header detection (enabled via env or automatically in Vercel)
if (
    os.getenv('SECURE_PROXY_SSL_HEADER', 'False').lower() in ('true', '1')
    or _is_vercel
):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Production SSL flags (default False in local dev, enabled via .env in production)
SECURE_SSL_REDIRECT = os.getenv('SECURE_SSL_REDIRECT', 'False').lower() in ('true', '1')
SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')
CSRF_COOKIE_SECURE = os.getenv('CSRF_COOKIE_SECURE', 'False').lower() in ('true', '1')

# HTTP Strict Transport Security (HSTS)
SECURE_HSTS_SECONDS = int(os.getenv('SECURE_HSTS_SECONDS', '0'))
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.getenv('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'False').lower() in ('true', '1')
SECURE_HSTS_PRELOAD = os.getenv('SECURE_HSTS_PRELOAD', 'False').lower() in ('true', '1')


# Logging Configuration
# In serverless/read-only environments (e.g. Vercel), write runtime logs to temporary directory
if _is_vercel:
    import tempfile
    LOG_DIR = Path(tempfile.gettempdir()) / 'logs'
else:
    LOG_DIR = Path(os.getenv('LOG_DIR', BASE_DIR / 'logs'))

try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
except OSError:
    import tempfile
    LOG_DIR = Path(tempfile.gettempdir()) / 'trustvault_logs'
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{asctime}] [{levelname}] [{name}:{lineno}] {message}',
            'style': '{',
        },
        'security': {
            'format': '[{asctime}] [SECURITY-{levelname}] {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
        'security_file': {
            'class': 'logging.FileHandler',
            'filename': LOG_DIR / 'security.log',
            'formatter': 'security',
        },
    },
    'loggers': {
        'django.security': {
            'handlers': ['console', 'security_file'],
            'level': 'WARNING',
            'propagate': False,
        },
        'trustvault': {
            'handlers': ['console', 'security_file'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
