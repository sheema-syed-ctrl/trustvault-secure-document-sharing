"""
Binary file validation and signature inspection service for TrustVault.
Enforces size limits, permitted extensions, and magic-byte signature matching.
Never trusts browser-supplied MIME types or filenames.
"""

import os
import hashlib
import filetype
from pathlib import Path
from django.conf import settings
from django.core.exceptions import ValidationError


def sanitize_filename(filename: str) -> str:
    """
    Strips path traversal sequences and dangerous characters from user filenames.
    Returns a safe base filename.
    """
    base = os.path.basename(filename.replace('\\', '/'))
    # Clean whitespace and strip dangerous characters
    safe_chars = [c for c in base if c.isalnum() or c in '._- ']
    sanitized = "".join(safe_chars).strip()
    return sanitized or "document"


def validate_file_upload(uploaded_file) -> dict:
    """
    Comprehensive file verification:
      1. Size verification against MAX_UPLOAD_SIZE_BYTES.
      2. Extension verification against PERMITTED_FILE_TYPES.
      3. Magic-byte signature verification (never trusting Content-Type header).
      4. Cryptographic SHA-256 calculation.

    Returns:
        dict: {'mime_type': str, 'sha256': str, 'file_size': int, 'clean_filename': str}
    Raises:
        ValidationError: If the file is oversized, unsupported, or signature mismatch occurs.
    """
    clean_name = sanitize_filename(uploaded_file.name)
    ext = Path(clean_name).suffix.lower()

    if not ext:
        raise ValidationError("File rejected: Missing file extension.")

    # 1. Size Verification
    file_size = uploaded_file.size
    max_size = getattr(settings, 'MAX_UPLOAD_SIZE_BYTES', 25 * 1024 * 1024)
    if file_size > max_size:
        max_mb = max_size // (1024 * 1024)
        curr_mb = file_size / (1024 * 1024)
        raise ValidationError(f"File rejected: Size ({curr_mb:.2f} MB) exceeds maximum limit of {max_mb} MB.")

    if file_size == 0:
        raise ValidationError("File rejected: Empty files (0 bytes) are not permitted.")

    # 2. Extension Check
    permitted_types = getattr(settings, 'PERMITTED_FILE_TYPES', {})
    permitted_extensions = {ext for exts in permitted_types.values() for ext in exts}

    if ext not in permitted_extensions:
        allowed_list = ", ".join(sorted(permitted_extensions))
        raise ValidationError(f"File rejected: Extension '{ext}' is not permitted. Allowed: {allowed_list}")

    # 3. Read Header & Binary Signature Verification
    uploaded_file.seek(0)
    header_chunk = uploaded_file.read(4096)
    uploaded_file.seek(0)

    detected_mime = None

    # Handle Plain Text files (.txt)
    if ext == '.txt':
        try:
            # Plain text must decode cleanly as UTF-8 or ASCII without null bytes
            decoded = header_chunk.decode('utf-8')
            if '\x00' in decoded:
                raise ValidationError("File rejected: Binary null bytes detected in plain text file.")
            detected_mime = 'text/plain'
        except UnicodeDecodeError:
            raise ValidationError("File rejected: Content is not valid plain text (UTF-8 encoding failure).")
    else:
        # Binary magic-byte detection via filetype
        kind = filetype.guess(header_chunk)
        if kind is not None:
            detected_mime = kind.mime
        else:
            # Fallback for old MS Word binary (.doc) OLE Compound File header
            if ext == '.doc' and header_chunk.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
                detected_mime = 'application/msword'
            elif ext == '.docx' and header_chunk.startswith(b'PK\x03\x04'):
                detected_mime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            else:
                raise ValidationError(
                    f"File rejected: Binary file signature could not be verified for '{ext}'."
                )

    # 4. Verify Signature aligns with Permitted Extensions
    expected_extensions = permitted_types.get(detected_mime, [])
    if ext not in expected_extensions:
        # Cross-extension spoofing detected (e.g. executable or PNG renamed as .pdf)
        raise ValidationError(
            f"Security Alert: Signature mismatch detected. "
            f"File extension '{ext}' does not match actual content type '{detected_mime}'."
        )

    # 5. Compute Full SHA-256 Checksum
    hasher = hashlib.sha256()
    uploaded_file.seek(0)
    for chunk in uploaded_file.chunks():
        hasher.update(chunk)
    sha256_digest = hasher.hexdigest()
    uploaded_file.seek(0)

    return {
        'mime_type': detected_mime,
        'sha256': sha256_digest,
        'file_size': file_size,
        'clean_filename': clean_name,
    }
