# Open PKI

A Django app that allows issuing, managing and validating certificates.

Features:
- Generate and revoke certificates
- Self-service portal to generate client certificates and download device profiles for iOS/macOS
- Multi-site
- OCSP endpoint to validate the issued certificates

## Configuration

### Settings
```python

INSTALLED_APPS = [
    ...
    'pki',
    ...
]

# Sign the iOS/macOS device profiles using SMIME
SIGN_PROFILES = True
# Generate a new user certificate when a user is assigned to a site
GENERATE_CERT_ON_CREATE = True
```
