# OCI API Gateway to OIC Event Bridge

An OCI API Gateway multi-argument authorizer function for securely delivering unauthenticated Event Hub events to an OIC REST endpoint.

The authorizer validates the inbound API key, retrieves the OIC OAuth client secret from OCI Vault, obtains an OIC access token, and returns that token only in API Gateway authorizer context. API Gateway then forwards the original event body directly to the OIC HTTP backend.

## Function configuration

| Variable | Required | Description |
| --- | --- | --- |
| `EXPECTED_API_KEY` | Yes | Inbound API key. `API_KEY` and `INBOUND_API_KEY` are supported aliases. |
| `CLIENT_ID` | Yes | OIC OAuth confidential application client ID. |
| `CLIENT_SECRET_OCID` | Yes | Vault secret OCID containing the OIC OAuth client secret. |
| `TOKEN_URL` | Yes | OCI IAM Identity Domain token endpoint. |
| `OIC_SCOPE` | Yes | Scope granted to the OIC OAuth client. |
| `AUTHORIZED_SCOPE` | No | Gateway route scope; defaults to `oic.invoke`. |
| `SECRET_CACHE_TTL_SECONDS` | No | Vault secret cache duration; defaults to `300`. |
| `TOKEN_EXPIRY_SKEW_SECONDS` | No | Token safety margin; defaults to `60`. |

The function needs dynamic-group permissions to read the secret OCID. Do not place the OAuth client secret in function configuration.

## API Gateway deployment design

Configure a **multi-argument authorizer** and pass:

```text
request.query[api_key] → api_key
```

Configure the OIC REST trigger as an HTTP backend. Add request-header transformations:

```text
Authorization: Bearer ${request.auth[oic_access_token]}
X-API-Key: ${request.query[api_key]}
```

Use the second transformation only when OIC requires the inbound API key. Require `oic.invoke` as the route authorization scope. API Gateway forwards the incoming body directly; the authorizer never logs it.

## Logging

JSON logs include authorization decisions and token timing/status. API keys are masked; OAuth tokens, Vault content, client secrets, authorization headers, and event bodies are never logged.
