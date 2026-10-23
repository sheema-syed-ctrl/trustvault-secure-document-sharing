"""
Neon Object Storage (S3-Compatible) integration layer for TrustVault.
Provides a reusable, thread-safe boto3 S3 client configured exclusively from environment variables,
with strict path traversal and key validation, streaming file delivery, and atomic transaction cleanup.
"""

import logging
import os
import re
from typing import BinaryIO
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from django.conf import settings
from django.core.exceptions import PermissionDenied

logger = logging.getLogger('trustvault')

# Strict regex for safe storage keys: only alphanumeric, hyphen, underscore, and dot
# Excludes directory separators, traversal dots, null bytes, and shell/URI metacharacters
SAFE_STORAGE_KEY_REGEX = re.compile(r'^[a-zA-Z0-9_\-.]+$')


def validate_storage_key(storage_filename: str) -> str:
    """
    Validates storage filename/object key to strictly prevent directory traversal,
    null byte injection, control character abuse, and relative/absolute path escapement.

    Raises:
        PermissionDenied: If any traversal sequence, path separator, null byte,
                          or disallowed character is detected.
    """
    if not storage_filename or not isinstance(storage_filename, str):
        raise PermissionDenied("Security violation: Invalid storage key.")

    clean_key = storage_filename.strip()
    if not clean_key:
        raise PermissionDenied("Security violation: Storage key cannot be empty.")

    # Guard against traversal sequences, path separators, and null/control characters
    if (
        '..' in clean_key
        or '/' in clean_key
        or '\\' in clean_key
        or '\0' in clean_key
        or '\r' in clean_key
        or '\n' in clean_key
    ):
        raise PermissionDenied("Security violation: Path traversal or invalid characters detected in storage key.")

    # Whitelist character validation
    if not SAFE_STORAGE_KEY_REGEX.match(clean_key):
        raise PermissionDenied("Security violation: Disallowed characters in storage key.")

    return clean_key


class S3StorageService:
    """
    Reusable, thread-safe S3 storage client for Neon Object Storage.
    Configured exclusively from environment variables:
      - AWS_ENDPOINT_URL_S3 (or AWS_ENDPOINT_URL)
      - AWS_ACCESS_KEY_ID
      - AWS_SECRET_ACCESS_KEY
      - AWS_REGION
      - AWS_STORAGE_BUCKET_NAME
    """

    _client = None

    @classmethod
    def get_client(cls):
        """
        Returns a reusable boto3 S3 client configured exclusively from environment variables.
        Thread-safe and pooled across requests.
        """
        if cls._client is None:
            endpoint_url = os.getenv('AWS_ENDPOINT_URL_S3') or os.getenv('AWS_ENDPOINT_URL')
            access_key = os.getenv('AWS_ACCESS_KEY_ID')
            secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            region = os.getenv('AWS_REGION', 'us-east-1')

            if not (access_key and secret_key):
                raise ValueError("Neon Object Storage credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY) are not configured.")

            client_kwargs = {
                'service_name': 's3',
                'aws_access_key_id': access_key,
                'aws_secret_access_key': secret_key,
                'region_name': region,
                'config': Config(
                    signature_version='s3v4',
                    retries={'max_attempts': 3, 'mode': 'standard'},
                    connect_timeout=5,
                    read_timeout=30,
                )
            }
            if endpoint_url:
                client_kwargs['endpoint_url'] = endpoint_url

            cls._client = boto3.client(**client_kwargs)
        return cls._client

    @classmethod
    def reset_client(cls):
        """Resets cached client instance (used for testing and credential rotation)."""
        cls._client = None

    @classmethod
    def get_bucket_name(cls) -> str:
        """Returns configured bucket name from environment."""
        bucket = os.getenv('AWS_STORAGE_BUCKET_NAME')
        if not bucket:
            raise ValueError("AWS_STORAGE_BUCKET_NAME is not configured in environment.")
        return bucket

    @classmethod
    def upload_file(cls, storage_filename: str, file_obj: BinaryIO, content_type: str = 'application/octet-stream') -> None:
        """
        Streams binary data to private Neon Object Storage bucket.
        Validates storage key before transmission.
        """
        key = validate_storage_key(storage_filename)
        bucket = cls.get_bucket_name()
        s3 = cls.get_client()

        if hasattr(file_obj, 'seek') and callable(file_obj.seek):
            file_obj.seek(0)

        extra_args = {'ContentType': content_type}
        s3.upload_fileobj(file_obj, bucket, key, ExtraArgs=extra_args)
        logger.info(f"Successfully uploaded object {key} to Neon bucket {bucket}.")

    @classmethod
    def open_file(cls, storage_filename: str):
        """
        Retrieves a streaming body from Neon Object Storage for authorized document download.
        Validates storage key before dispatching request.

        Returns:
            botocore.response.StreamingBody: Streamable file body for FileResponse.

        Raises:
            FileNotFoundError: If the object does not exist in the bucket.
            PermissionDenied: If storage key fails validation.
        """
        key = validate_storage_key(storage_filename)
        bucket = cls.get_bucket_name()
        s3 = cls.get_client()

        try:
            response = s3.get_object(Bucket=bucket, Key=key)
            return response['Body']
        except ClientError as exc:
            error_code = exc.response.get('Error', {}).get('Code', '')
            if error_code in ('NoSuchKey', '404', 'NotFound'):
                logger.error(f"S3 object missing in bucket {bucket}: key {key}")
                raise FileNotFoundError(f"Storage object '{key}' could not be located in secure vault.")
            logger.error(f"S3 get_object failed for key {key} in bucket {bucket}: {exc}")
            raise

    @classmethod
    def delete_file(cls, storage_filename: str) -> bool:
        """
        Permanently purges an object from the private Neon Object Storage bucket.
        Validates storage key before dispatching request.
        """
        key = validate_storage_key(storage_filename)
        bucket = cls.get_bucket_name()
        s3 = cls.get_client()

        try:
            s3.delete_object(Bucket=bucket, Key=key)
            logger.info(f"Purged object {key} from Neon bucket {bucket}.")
            return True
        except ClientError as exc:
            logger.error(f"CRITICAL: Failed to delete S3 object {key} from bucket {bucket}: {exc}")
            raise

    @classmethod
    def file_exists(cls, storage_filename: str) -> bool:
        """Checks whether an object exists in the private bucket."""
        key = validate_storage_key(storage_filename)
        bucket = cls.get_bucket_name()
        s3 = cls.get_client()

        try:
            s3.head_object(Bucket=bucket, Key=key)
            return True
        except ClientError as exc:
            error_code = exc.response.get('Error', {}).get('Code', '')
            if error_code in ('NoSuchKey', '404', 'NotFound'):
                return False
            raise
