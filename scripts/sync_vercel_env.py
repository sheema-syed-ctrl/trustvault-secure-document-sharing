import os
import json
import urllib.request
from dotenv import load_dotenv

load_dotenv()

# Read auth token
with open(r'C:\Users\abdul\AppData\Roaming\xdg.data\com.vercel.cli\auth.json') as f:
    token = json.load(f)['token']

# Read project config
with open(r'.vercel\project.json') as f:
    proj = json.load(f)
    project_id = proj['projectId']
    team_id = proj['orgId']

headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json',
}

# 1. Fetch existing env vars
req = urllib.request.Request(
    f'https://api.vercel.com/v9/projects/{project_id}/env?teamId={team_id}',
    headers=headers
)
with urllib.request.urlopen(req) as res:
    existing = json.loads(res.read()).get('envs', [])
    existing_keys = {e['key']: e['id'] for e in existing}

print(f"Existing Vercel env keys: {list(existing_keys.keys())}")

# 2. Variables to sync
vars_to_sync = {
    'DATABASE_URL': os.environ.get('DATABASE_URL'),
    'AWS_ENDPOINT_URL_S3': os.environ.get('AWS_ENDPOINT_URL_S3'),
    'AWS_ACCESS_KEY_ID': os.environ.get('AWS_ACCESS_KEY_ID'),
    'AWS_SECRET_ACCESS_KEY': os.environ.get('AWS_SECRET_ACCESS_KEY'),
    'AWS_REGION': os.environ.get('AWS_REGION', 'us-east-2'),
    'AWS_STORAGE_BUCKET_NAME': os.environ.get('AWS_STORAGE_BUCKET_NAME', 'trustvault-documents'),
    'DOCUMENTS_STORAGE_BACKEND': 's3',
    'SECRET_KEY': os.environ.get('SECRET_KEY'),
    'DEBUG': 'False',
    'ALLOWED_HOSTS': '127.0.0.1,localhost,[::1],.vercel.app,sheema-ivory.vercel.app',
    'CSRF_TRUSTED_ORIGINS': 'https://*.vercel.app,https://sheema-ivory.vercel.app',
    'CONN_MAX_AGE': '0',
    'DJANGO_SETTINGS_MODULE': 'trustvault.settings',
}

for k, val in vars_to_sync.items():
    if not val:
        print(f"Skipping {k} (no value in local .env)")
        continue

    # Delete if exists to cleanly replace
    if k in existing_keys:
        env_id = existing_keys[k]
        del_req = urllib.request.Request(
            f'https://api.vercel.com/v9/projects/{project_id}/env/{env_id}?teamId={team_id}',
            headers=headers,
            method='DELETE'
        )
        try:
            with urllib.request.urlopen(del_req) as del_res:
                pass
        except Exception as e:
            print(f"Note deleting {k}: {e}")

    # Create new
    payload = json.dumps({
        'key': k,
        'value': val,
        'type': 'encrypted' if any(s in k for s in ['SECRET', 'KEY', 'URL', 'PASSWORD']) else 'plain',
        'target': ['production', 'preview', 'development'],
    }).encode('utf-8')

    add_req = urllib.request.Request(
        f'https://api.vercel.com/v10/projects/{project_id}/env?teamId={team_id}',
        data=payload,
        headers=headers,
        method='POST'
    )
    with urllib.request.urlopen(add_req) as add_res:
        print(f"  [OK] Successfully configured {k}")

print("\nAll Vercel production environment variables synced successfully!")
