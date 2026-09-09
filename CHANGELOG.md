# Changelog

This file records version-specific changes. The README remains the implementation and operations guide.

## v2.0

### Security

- Replaced plaintext inbound API-key Function configuration with Vault-backed `API_KEY_SECRET_OCID`.
- Reused the cached Vault secret reader for the inbound API key and OIC OAuth client secret.
- Kept API-key comparison constant-time and ensured sensitive values are not written to logs.

### API Gateway and OCI Functions

- Added API Gateway-to-Functions IAM policy guidance, including the API Gateway dynamic group required to invoke the authorizer.
- Documented the separate Functions permission required by developers who configure the authorizer in the OCI Console.

### Documentation

- Expanded the README with the scenario, architecture, prerequisites, Vault/IAM setup, Function configuration, Gateway setup, runtime flow, and troubleshooting guidance.
- Added a production-use notice for the sample.

## v1.0

- Initial OCI API Gateway authorizer implementation.
- Validated an inbound API key from Function configuration and generated an OIC OAuth access token using a Vault-backed client secret.
