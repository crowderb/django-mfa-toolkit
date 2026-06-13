# MFA Secret Storage

Status: accepted MVP primitive
Date: 2026-06-13

## Storage Boundary

MFA secret material must cross persistence boundaries only through `django_mfa_toolkit.secret_storage`.

The module returns a versioned string with this shape:

```text
v1:<key-id>:<fernet-token>
```

Application models should persist that serialized value, not the raw secret. TOTP and HOTP enrollment services will use this boundary before writing device records.

## Settings

Configure encryption keys in Django settings:

```python
DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS = {
    "local-dev": "FERNET_KEY_FROM_KEY_MANAGEMENT_OR_GENERATED_FOR_LOCAL_DEV"
}
DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID = "local-dev"
```

The example value is a placeholder. Do not commit real Fernet keys, OTP seeds, recovery codes, API keys, or production credentials.

For local development, generate a pseudo key at runtime or keep it in an ignored `.env` file loaded by local settings:

```python
from django_mfa_toolkit.secret_storage import generate_encryption_key

print(generate_encryption_key())
```

Production deployments should load keys from the deployment's secret manager or another approved key-management system.

## Key Rotation

The persisted value includes a key ID. New encryption uses `DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID`; decryption uses the key ID embedded in the stored value.

To rotate keys:

1. Add the new key to `DJANGO_MFA_TOOLKIT_SECRET_ENCRYPTION_KEYS`.
2. Set `DJANGO_MFA_TOOLKIT_PRIMARY_SECRET_ENCRYPTION_KEY_ID` to the new key ID.
3. Keep old keys configured until all old encrypted values are re-encrypted or expired.

## Security Assumptions

- Fernet from `cryptography` provides authenticated encryption for stored MFA secret material.
- Raw MFA secrets must not be stored in models, migrations, fixtures, logs, examples, or documentation.
- Invalid or tampered ciphertext fails closed and is not decrypted.
- Missing or invalid key configuration raises configuration errors instead of falling back to plaintext.
- This primitive only encrypts storage values. Replay prevention, throttling, audit logging, and factor-specific verification are implemented by later TOTP and HOTP service tasks.
