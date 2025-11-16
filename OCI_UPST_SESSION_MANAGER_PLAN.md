# OCI UPST Session Manager – Plan

Goal: Replace device-code flow with Authorization Code flow to obtain Access and Refresh tokens, exchange the Access Token for a UPST, persist credentials in the OCI profile, and keep the UPST current using the Refresh Token on a fixed interval (no `oci session refresh` calls).

## Summary
- Interactive init (foreground):
  - Run Authorization Code flow via local redirect (PKCE), obtain Access Token (AT) and Refresh Token (RT).
  - Generate RSA keypair; exchange AT → UPST (security token) using token exchange endpoint and public key.
  - Persist: UPST to `security_token_file`, private key to `key_file`, RT to a sidecar file near the token.
  - Ensure OCI config profile (`~/.oci/config` or custom) has `region`, `key_file`, `security_token_file` (and optionally `auth=security_token`).
- Refresh loop (foreground):
  - On a fixed schedule (default 45m; accepts 45, 45m, 1h; clamp to 60), use RT → new AT → exchange → new UPST; write files; rotate RT if provided.
  - Logs successes/failures and next scheduled refresh time.

## CLI (proposed)
- Profile/OCI config:
  - `--profile-name <name>` (required): profile to create/update.
  - `--region <region-id>` (required if not already in profile): e.g., `us-ashburn-1`.
  - `--config-file <path>` (default: `~/.oci/config`).
- OAuth/AuthZ:
  - `--authz-base-url <url>` (e.g., `https://login.us-ashburn-1.oraclecloud.com`).
  - `--token-url <url>` (default: `<authz>/oauth2/v1/token`).
  - `--client-id <id>` (required), `--client-secret <secret>` (optional depending on app type).
  - `--scope <scopes>` (must include offline_access to get RT).
  - `--redirect-port <port>` (default: 8181), callback path `/callback`.
- Token exchange:
  - `--token-exchange-url <url>` (default: `--token-url`).
- Keys/crypto:
  - `--key-bits 2048` (default 2048).
- Scheduling/Logging:
  - `--refresh-interval 45|45m|1h` (default 45; bare numbers = minutes; clamp at 60).
  - `--log-level INFO|DEBUG|...` (default INFO).

## Flow details
1) Launch local HTTP server on `http://127.0.0.1:<port>/callback` and generate PKCE (S256).
2) Build and open the auth URL with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`.
3) Receive `?code&state` on the callback, validate `state`.
4) Exchange code → AT/RT at `token_url` using `grant_type=authorization_code` (+ `client_secret` if supplied) and `code_verifier`.
5) Generate RSA keypair; base64url-encode DER SubjectPublicKeyInfo.
6) Token exchange (AT → UPST) at `token-exchange-url`:
   - `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`
   - `requested_token_type=urn:oci:token-type:oci-upst`
   - `public_key=<b64 DER>`
   - `subject_token=<AT>`
   - `subject_token_type=jwt`
   - `Authorization: Basic base64(client_id:client_secret)`
7) Persist files (0600) and directories (0700):
   - `key_file` (PEM), `security_token_file` (UPST), `refresh_token` (sidecar file).
   - Update `[profile-name]` in OCI config with `region`, `key_file`, `security_token_file` (and optionally `auth=security_token`).
8) Refresh loop:
   - Every interval: RT → new AT (handle RT rotation) → token exchange → new UPST → overwrite token file.
   - Log success/failure and next run. Stop on SIGINT/SIGTERM.

## Security & robustness
- Never log AT/RT/UPST contents.
- Restrictive file perms (0600) and directory perms (0700).
- Handle network/HTTP errors with clear logs; simple retry on next interval.
- Optional enhancement (later): backoff on failures, file locking to avoid concurrent writers, metrics hook.

## Deliverables
- `oci_upst_session_manager.py` (combined script).
- `requirements.txt` (`requests`, `cryptography`, `toml`).
- Usage in this repo README or a short section below.

## Example
```
python3 oci_upst_session_manager.py \
  --profile-name test1 \
  --region us-ashburn-1 \
  --authz-base-url https://login.us-ashburn-1.oraclecloud.com \
  --client-id <CLIENT_ID> \
  --client-secret <CLIENT_SECRET> \
  --scope "openid offline_access" \
  --refresh-interval 45
```

