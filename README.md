# OCI API Gateway to OIC Event Bridge

Secure an unauthenticated event source before delivering its events to Oracle Integration Cloud (OIC).

This sample uses an OCI API Gateway multi-argument authorizer implemented as an OCI Function. The authorizer validates an inbound API key stored in OCI Vault, retrieves an OAuth client secret from OCI Vault, obtains an OIC access token, and returns that token only to API Gateway as authorizer context. API Gateway then forwards the original event body directly to an OIC REST trigger.

> Note: This repository contains sample code that demonstrates how to use an API-key-secured event source to call Oracle Integration Cloud through OCI API Gateway and an OCI Functions custom authorizer. Review, test, and adapt the code for your own environment, security requirements, operational standards, and compliance guidelines before using it in production.

## Scenario

An event source cannot perform OAuth authentication but can append a shared API key to its webhook URL. OIC requires OAuth authentication and may also require an API key.

This solution keeps both the inbound API key and OIC OAuth client secret in OCI Vault. The event source calls API Gateway, API Gateway asks the Function to authenticate the API key, and a successful Function response enables API Gateway to call OIC with a short-lived OAuth token.

## Architecture

```text
Event source
  │ POST body + ?api_key=...
  ▼
OCI API Gateway
  │ invokes authorizer with api_key
  ▼
OCI Functions custom authorizer
  │ reads inbound API key + OAuth client secret from Vault
  │ requests OIC OAuth token
  ▼
OCI API Gateway HTTP backend
  │ forwards original body with Bearer token
  ▼
Oracle Integration Cloud REST trigger
```

The authorizer does not forward or log the event body. API Gateway retains the original request and sends it to the OIC HTTP backend only after authorization succeeds.

## Before you begin

You need:

- An OCI Functions application and an OCIR repository configured in the active Fn context.
- An OIC REST trigger and an OAuth confidential application that is allowed to request the OIC scope.
- Two OCI Vault secrets:
  - the inbound API key shared with the event source
  - the OIC OAuth client secret
- An OCI Function dynamic group with permission to read both secret bundles.
- An API Gateway deployment that can invoke the authorizer Function and reach the OIC endpoint.

For the complete OCI Function build and deployment process, follow Oracle's [Creating and Deploying Functions guide](https://docs.oracle.com/en-us/iaas/Content/Functions/Tasks/functionsuploading.htm).

## Step 1: Create Vault secrets

Create an OCI Vault secret for the inbound API key and a separate secret for the OIC OAuth client secret. Copy each secret OCID.

Do not save either plaintext secret in source control, Function configuration, API Gateway transformations, or logs.

## Step 2: Grant the Function access to Vault

Create or use a dynamic group matching the Function, then grant it access in the compartment containing the Vault secrets:

```text
Allow dynamic-group <function-dynamic-group> to read secret-bundles in compartment <vault-compartment>
```

Adapt the policy to your tenancy's least-privilege standards.

## Step 3: Deploy the Function

Deploy the project to your OCI Functions application. The Function name comes from `func.yaml`.

```bash
fn deploy --app <functions-application-name>
```

Confirm that the Function appears in the application:

```bash
fn list functions <functions-application-name>
```

## Step 4: Configure the Function

Set the following Function configuration values after deployment:

| Variable | Required | Description |
| --- | --- | --- |
| `API_KEY_SECRET_OCID` | Yes | Vault secret OCID containing the API key sent by the event source. |
| `CLIENT_ID` | Yes | OIC OAuth confidential application client ID. |
| `CLIENT_SECRET_OCID` | Yes | Vault secret OCID containing the OAuth client secret. |
| `TOKEN_URL` | Yes | OCI IAM Identity Domain token endpoint. |
| `OIC_SCOPE` | Yes | Scope granted to the OAuth client for the OIC endpoint. |
| `AUTHORIZED_SCOPE` | No | API Gateway route scope; defaults to `oic.invoke`. |
| `SECRET_CACHE_TTL_SECONDS` | No | Vault secret cache duration; defaults to `300` seconds. |
| `TOKEN_EXPIRY_SKEW_SECONDS` | No | Token refresh safety margin; defaults to `60` seconds. |
| `LOG_LEVEL` | No | Python log level; defaults to `INFO`. |

Example:

```bash
fn config function <functions-application-name> oci-apigw-oic-event-bridge API_KEY_SECRET_OCID <api-key-secret-ocid>
fn config function <functions-application-name> oci-apigw-oic-event-bridge CLIENT_SECRET_OCID <client-secret-ocid>
```

`EXPECTED_API_KEY`, `API_KEY`, and `INBOUND_API_KEY` are intentionally not supported.

## Step 5: Configure API Gateway authentication

Create a deployment with a **multi-argument authorizer** pointing to this Function. Pass the event source's query parameter to the Function:

```text
request.query[api_key] → api_key
```

Configure the route authorization policy to require the `oic.invoke` scope, or the value supplied in `AUTHORIZED_SCOPE`.

For an absent or invalid key, the Function returns `active: false`; API Gateway rejects the request. For a valid key, it returns the scope and an OIC access token in private `request.auth` context.

## Step 6: Configure the OIC HTTP backend

Set the OIC REST trigger URL as the API Gateway route's HTTP backend.

Add this request-header transformation:

```text
Authorization: Bearer ${request.auth[oic_access_token]}
```

If OIC also requires the event source API key, add its required header name and pass the original query value, for example:

```text
X-API-Key: ${request.query[api_key]}
```

Only add this second transformation when the OIC REST trigger explicitly requires it. API Gateway forwards the original request body to OIC.

## Runtime behavior

1. API Gateway sends `api_key` to the authorizer Function.
2. The Function reads the expected API key from `API_KEY_SECRET_OCID` using OCI resource principals.
3. It compares supplied and expected values with constant-time comparison.
4. For a valid key, it obtains the OAuth client secret from Vault.
5. It requests an OIC access token using `client_credentials` and `OIC_SCOPE`.
6. It returns `active: true`, `oic.invoke`, and the token in authorizer context.
7. API Gateway adds the Bearer token and invokes OIC.

Vault secrets and OAuth tokens are cached only in the warm Function container to reduce latency and Vault/token-endpoint calls.

## Logging and troubleshooting

The Function emits structured JSON logs for authorization decisions and token request status/timing. It masks inbound API keys and never logs:

- raw event bodies
- API keys
- Vault secret content or OCIDs
- OAuth client secrets
- access tokens
- Authorization headers

Use API Gateway execution logs and Function logs together. Start with the request/correlation information available in your gateway logs, then check whether the failure occurred during API-key validation, Vault access, token acquisition, or the OIC backend call.
