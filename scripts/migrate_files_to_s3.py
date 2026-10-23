#!/usr/bin/env python3
"""
S3 Document Migration Script
Uploads the 4 active document binary files from local protected_media to Neon S3 bucket.
Validates SHA-256 before upload and after downloading from S3.
Leaves local protected_media intact.
"""

import os
import sys
import hashlib
import boto3
import psycopg2
from dotenv import load_dotenv

def migrate_files():
    load_dotenv()
    db_url = os.environ.get('DATABASE_URL')
    s3_endpoint = os.environ.get('AWS_ENDPOINT_URL_S3')
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_REGION', 'us-east-2')
    bucket_name = os.environ.get('AWS_STORAGE_BUCKET_NAME', 'trustvault-documents')

    if not all([db_url, s3_endpoint, aws_access_key, aws_secret_key, bucket_name]):
        print("ERROR: Missing required S3 or database environment variables.")
        sys.exit(1)

    print(f"Connecting to Neon S3 (Bucket: {bucket_name}, Region: {aws_region})...")
    s3_client = boto3.client(
        's3',
        endpoint_url=s3_endpoint,
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region,
    )

    print("Fetching active documents from Neon PostgreSQL...")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, original_filename, storage_filename, file_size, mime_type, sha256_hash 
        FROM documents_document 
        ORDER BY id ASC;
    """)
    docs = cur.fetchall()
    conn.close()

    print(f"Found {len(docs)} documents to migrate to S3.")
    protected_media_dir = os.path.join(os.getcwd(), 'protected_media')

    for doc in docs:
        doc_id, orig_name, storage_fn, file_size, mime_type, expected_hash = doc
        print(f"\nProcessing Document ID {doc_id} ('{orig_name}'):")
        print(f"  Storage filename: {storage_fn}")
        print(f"  Expected size: {file_size} bytes")
        print(f"  Expected SHA-256: {expected_hash}")

        local_path = os.path.join(protected_media_dir, storage_fn)
        if not os.path.exists(local_path):
            raise FileNotFoundError(f"Local file not found: {local_path}")

        # 1. Compute local hash
        with open(local_path, 'rb') as f:
            local_bytes = f.read()

        local_hash = hashlib.sha256(local_bytes).hexdigest()
        assert local_hash == expected_hash, f"Local hash mismatch for doc {doc_id}! Expected {expected_hash}, got {local_hash}"
        assert len(local_bytes) == file_size, f"Local size mismatch for doc {doc_id}! Expected {file_size}, got {len(local_bytes)}"
        print(f"  [OK] Local file validated ({len(local_bytes)} bytes, hash match)")

        # 2. Upload to S3
        print(f"  Uploading to S3 key '{storage_fn}'...")
        extra_args = {}
        if mime_type:
            extra_args['ContentType'] = mime_type

        s3_client.put_object(
            Bucket=bucket_name,
            Key=storage_fn,
            Body=local_bytes,
            **extra_args
        )
        print("  [OK] Uploaded to S3")

        # 3. Read back from S3 and verify parity
        print("  Verifying download from S3...")
        response = s3_client.get_object(Bucket=bucket_name, Key=storage_fn)
        s3_bytes = response['Body'].read()
        s3_hash = hashlib.sha256(s3_bytes).hexdigest()

        assert s3_hash == expected_hash, f"S3 hash mismatch for doc {doc_id}! Expected {expected_hash}, got {s3_hash}"
        assert len(s3_bytes) == file_size, f"S3 size mismatch for doc {doc_id}! Expected {file_size}, got {len(s3_bytes)}"
        print(f"  [OK] S3 object verified: {len(s3_bytes)} bytes, SHA-256 matched exactly!")

    print("\nSUCCESS: All 4 document binaries migrated to Neon S3 and verified with 100% hash parity!")

if __name__ == '__main__':
    migrate_files()
