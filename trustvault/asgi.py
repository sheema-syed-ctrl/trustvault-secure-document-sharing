"""
ASGI config for trustvault project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

import os
import sys
from pathlib import Path

# Add project root to sys.path so apps and root settings package resolve cleanly
# whether executed from the repository root or the trustvault subdirectory
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustvault.settings')

from django.core.asgi import get_asgi_application

application = get_asgi_application()
app = application
