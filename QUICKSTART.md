# WOCI Session Manager Quick Start

Wraps the OCI CLI to transparently obtain and refresh a security token (UPST) via:
1. OAuth 2.0 Authorization Code + PKCE (interactive, first use)
2. Refresh Token grant (silent renew of access token)
3. RFC 8693 Token Exchange (access token -> OCI UPST)
4. Optional background refresh loop (disabled by default: interval=0)

## Install

Prerequisites:
- Python 3.9+
- OCI CLI installed (`oci` on PATH)
- Dependencies: `pip install -r requirements.txt`

### Option 1: Symlink directly to the script (simple, uses system Python)
```bash
chmod +x oci_upst_session_manager.py
ln -sf "$(pwd)/oci_upst_session_manager.py" /usr/local/bin/woci
which woci
```

### Option 3: Self-contained installer script (recommended)
Creates an isolated virtualenv under `~/.local/share/oci-upst-manager` and a launcher in `~/.local/bin`.
```bash
chmod +x install.sh
./install.sh
~/.local/bin/oci-upst-session-manager --help
```
Optional convenience alias "woci":
```bash
ln -sf "$HOME/.local/bin/oci-upst-session-manager" "$HOME/.local/bin/woci"
which woci
```
If `~/.local/bin` is not on your PATH (bash):
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile
source ~/.bash_profile
```
Notes:
- The installer creates a venv and installs `requests` and `cryptography` inside it.
- The launcher name is `oci-upst-session-manager`; adding the `woci` alias keeps examples below consistent.

## Configuration Files

OCI CLI config (standard): `~/.oci/config`
WOCI manager config (auto-discovered): `~/.oci/woci_manager.ini` OR same directory as any `--config-file` you pass.
Default auto-discovery filename: `woci_manager.ini`.

Sample `woci_manager.ini`:
```ini
[myprofile]
authz_base_url = https://idcs-tenant.identity.oraclecloud.com/oauth2/v1/authorize
token_url = https://idcs-tenant.identity.oraclecloud.com/oauth2/v1/token
client_id = YOUR_CLIENT_ID
client_secret = YOUR_CLIENT_SECRET
scope = openid offline_access
refresh_interval = 0
```

You can define multiple sections. CLI flags always override values from the selected section.

## Profile Resolution Semantics
Effective profile name (used for OCI profile and session artifact paths) is chosen by precedence:
1. `--profile-name` (wrapper flag)
2. Passthrough `--profile` (OCI CLI flag in the remaining args)
3. Selected manager config section name (see below)
   - Section resolution order: explicit `--manager-config-section`, section matching `--profile-name`, section matching passthrough `--profile`, DEFAULT pseudo-section (values only), first real section.
4. Failure: exit with error if no profile determined.

Artifacts stored under: `~/.oci/sessions/<profile>/`:
- `token` (UPST)
- `private_key.pem`
- `refresh_token` (optionally encrypted)

OCI config is updated (created if absent) with:
- `key_file`
- `security_token_file`
- `region` (if provided)

## Required Runtime Values
Must be provided via CLI or manager config: `authz_base_url`, `token_url`, `client_id`, `client_secret`, `scope`.
`client_secret` is mandatory for OCI IAM token exchange.

## Encryption (Optional)
Provide a passphrase to encrypt the refresh token file:
- `--refresh-token-passphrase-env VAR_NAME` (VAR_NAME must be set in environment)
- `--refresh-token-passphrase-prompt` (interactive prompt)
Algorithm: AES-GCM + PBKDF2 (200k iterations) + random salt/nonce.

## First Run Flow
1. Launch `woci` with an OCI command.
2. If no valid UPST & refresh token: browser opens Authorization Code flow (PKCE).
3. Exchange code -> access + refresh tokens.
4. Exchange access token -> UPST; store artifacts; update OCI config.
5. Forward original OCI command.

Subsequent runs:
- If UPST still valid (>60s remaining) => reuse.
- Else if refresh token exists => refresh + exchange silently.
- Else fallback to interactive flow again.

## Usage Examples

Interactive cluster token generation:
```bash
woci \
  --profile-name myprofile \
  --authz-base-url https://idcs-tenant.identity.oraclecloud.com/oauth2/v1/authorize \
  --token-url https://idcs-tenant.identity.oraclecloud.com/oauth2/v1/token \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --scope "openid offline_access" \
  ce cluster generate-token --cluster-id OCID
```
(Region may be inferred from OCI config; add `--region us-ashburn-1` if needed.)

Using manager config only (auto-discovered):
```bash
woci ce cluster generate-token --cluster-id OCID --profile myprofile
```

Background refresh every 45 minutes:
```bash
woci --refresh-interval 45m ... <OCI COMMAND>
```

Encrypt refresh token (env var method):
```bash
export WOCI_RT_PASSPHRASE="StrongPassphrase"
woci --refresh-token-passphrase-env WOCI_RT_PASSPHRASE ... <OCI COMMAND>
```

## Kubeconfig Exec Integration
Example user exec block:
```yaml
exec:
  apiVersion: client.authentication.k8s.io/v1beta1
  command: woci
  args:
    - --profile-name
    - myprofile
    - ce
    - cluster
    - generate-token
    - --cluster-id
    - OCID
    - --auth
    - security_token
```
First call triggers interactive login; subsequent calls refresh silently.

## Troubleshooting
- Browser not opening: copy logged Auth URL manually; on macOS the script attempts `open` fallback.
- "Missing required options": ensure values present via CLI or config section.
- "Could not determine profile name": provide `--profile-name` or `--profile` or add a named section.
- Token not refreshing: check presence/permissions of `~/.oci/sessions/<profile>/refresh_token`.
- Encrypted refresh token but no passphrase supplied: provide env var or prompt flag.

## Security Notes
- Refresh token is sensitive; prefer encryption at rest.
- Session token lifetime capped at 60 minutes; refresh loop clamps interval.
- Passphrase derivation uses PBKDF2-HMAC-SHA256 (200k iterations) for a balanced cost.

## Exit Codes
- 0 success after passthrough command
- 1 runtime/refresh/exchange failure
- 2 argument / configuration error
- 127 OCI CLI not found

## Unattended / Headless
Use an initial interactive run to create artifacts, then rely on refresh token afterward. For truly headless environments ensure you can manually visit the Auth URL from a workstation and copy the redirected code if necessary.

## Updating
Edit constants (e.g., `REFRESH_TOKEN_KDF_ITERATIONS`) directly in the script if you need to tune; no CLI flag provided to reduce complexity.

---
For feature requests (OIDC discovery, configurable callback path, non-browser device flow fallback), extend the script where noted in comments.
