# OCI UPST Session Manager (WOCI)

> [!NOTE]
> **About the `woci` command**: Throughout this documentation, `woci` is used as a convenient example alias for the `oci_upst_session_manager.py` script. This is not a binary name; you can define your own alias (e.g. `alias woci='python3 /path/to/oci_upst_session_manager.py'`) or invoke the script directly.

This repository contains a small wrapper around the OCI CLI that transparently manages **OCI User Principal Session Tokens (UPSTs)** using OAuth/OIDC and OCI Workload Identity Federation.

Instead of manually running `oci session authenticate` on a schedule, you:

- Sign in once via your identity provider (Okta, IDCS, Azure AD, etc.).
- Receive a long-lived **refresh token** and a short-lived **access token**.
- The wrapper exchanges the access token for an **OCI UPST** and writes it into the standard OCI session layout.
- On subsequent runs, the wrapper refreshes tokens **offline** (from the stored refresh token) until the refresh token itself expires or becomes invalid.
- **Auto-Refresh Thread** (`--auto-refresh`): Runs *inside* the wrapper process. Keeps the session valid for the duration of a long-running script or job, then exits. Ideal for CI/CD or batch jobs.
- **Daemon Mode** (`--daemon`): Spawns a detached background process that keeps the session valid indefinitely (until stopped or refresh token expires). Ideal for local development (Terraform, IDEs, multiple terminals).
- The OCI CLI always runs against a **security_token** profile, but you never have to manage the UPST by hand.

For detailed installation, configuration, and usage examples, see **[`QUICKSTART.md`](./QUICKSTART.md)**.

---

## High-level workflow

At a high level, the tool enables this flow:

1. **First use / no session present**
   - You invoke the wrapper as `woci <OCI args>` or via the `oci_upst_session_manager.py` script.
   - The wrapper checks for an existing UPST for the chosen profile.
   - If no valid UPST or refresh token exists, it starts an **Authorization Code + PKCE** flow:
     - Opens your browser to the OIDC provider’s sign-in page.
     - You authenticate and consent.
     - The identity provider redirects back to a local callback (e.g. `http://127.0.0.1:8181/callback`).
   - The wrapper exchanges the authorization code for:
     - An **access token** (short-lived, JWT).
     - A **refresh token** (longer-lived, often non-JWT or with longer TTL).
   - It then executes an **OCI Workload Identity Federation token exchange**:
     - `access token → OCI UPST` (using OCI’s OAuth 2.0 token-exchange endpoint).
   - The wrapper stores:
     - The UPST under `~/.oci/sessions/<profile>/token`.
     - The private key used in the exchange.
     - The refresh token (optionally encrypted).
   - It updates your `~/.oci/config` profile to use `key_file` + `security_token_file`.
   - Finally, it forwards your original `oci` command using `--auth security_token`.

2. **Subsequent calls (while refresh token is valid)**
   - On every invocation, the wrapper:
     - Decodes the UPST (JWT) from `~/.oci/sessions/<profile>/token`.
     - Checks its `exp` and whether it’s expiring within the next ~60 seconds.
   - If the UPST is still valid, it **does nothing** and simply runs `oci` with `--auth security_token`.
    - If the UPST is expired or near expiry but a refresh token is present:
      - It performs a **Refresh Token** grant at the OIDC token endpoint.
     - Receives a fresh access token (and possibly a rotated refresh token).
     - Exchanges the access token for a **new UPST** via OCI’s token exchange endpoint.
     - Updates the UPST and refresh token files on disk.
    - All of this happens **offline** from the user’s perspective (no browser interaction) as long as the refresh token remains valid.

    - Optional: **Auto-refresh background thread**
      - If enabled, the wrapper will refresh the UPST in the background ~10 minutes before expiry.
      - This is useful for long-running `oci` commands or clients that keep a process alive.
    - Optional: **Daemon mode**
      - `--daemon` starts a background refresh process and the CLI exits.
      - Use `--daemon-status` and `--stop-daemon` to manage it.

3. **When the refresh token expires or becomes invalid**
   - If the refresh attempt fails (e.g. refresh token expired, revoked, or otherwise unusable):
     - The wrapper logs the failure.
     - It automatically falls back to the **interactive Authorization Code flow** again, just like first use.
   - You authenticate in the browser once more.
   - New access/refresh tokens are issued, a new UPST is exchanged, and the cycle repeats.

---

## Why this matters: controlling OCI session lifetime

By using an **OIDC refresh token** as the durable credential and treating the OCI UPST as a short-lived, derived session token, you get:

- **Fine-grained control over OCI session lifetime**:
  - The effective life of a user’s OCI session is bounded by the **refresh token TTL** configured in your identity provider.
  - You can centrally control how long a human can continue to obtain new UPSTs without re-authenticating by adjusting the refresh token TTL and policies.

- **Minimized re-authentication friction**:
  - Users typically sign in **once per refresh token lifetime**.
  - As long as the refresh token is valid, they can issue OCI CLI commands (including interactive `oci` features) without being prompted to log in again.

- **Security-aligned behavior**:
  - The wrapper uses the access token (not the ID token) as the **subject token** for OCI’s token exchange, which is aligned with OAuth2/OIDC guidance: access tokens are for API/token exchange, ID tokens are for sign-in.
  - The resulting UPST is stored and used only in the context of the OCI CLI (`--auth security_token`).

---

## Token model used by the wrapper

The wrapper distinguishes between four different token types and uses each for its intended purpose:

1. **ID token (OIDC)**
   - Proves that a user authenticated to your client (RP).
   - Not used directly by this tool to call any API or as a bearer credential.

2. **Access token (OIDC)**
   - Short-lived bearer token issued by your OIDC provider.
   - Used by the wrapper as the **subject token** in the OCI token exchange:
     - `subject_token_type = "jwt"`
     - `requested_token_type = "urn:oci:token-type:oci-upst"`
   - Never stored long-term; only used in memory during exchange.

3. **Refresh token (OIDC)**
   - Long(er)-lived credential, often non-JWT or with different TTLs.
   - Stored on disk (optionally encrypted) under the profile’s session directory.
   - Used to silently obtain new access tokens and thus new UPSTs.
   - Its TTL and rotation policy effectively define **how long a user can continue to get fresh OCI sessions without re-authenticating**.

4. **UPST (OCI User Principal Session Token)**
   - JWT issued by OCI IAM via token exchange, representing an OCI user principal session.
   - Stored under `~/.oci/sessions/<profile>/token`.
   - Used by the OCI CLI via `--auth security_token`.
   - Short-lived by design; the wrapper replaces it when necessary using the refresh token.

---

## Wrapper assumptions and behavior

- The wrapper always **assumes** that for the managed profile, you intend to use **OCI session tokens** (UPST) rather than API keys.
- It will:
  - Ensure a valid UPST exists (refreshing or re-authenticating if needed).
  - Update the `~/.oci/config` profile to use `key_file` + `security_token_file`.
  - Invoke `oci` with `--auth security_token` unless the call already supplies an explicit `--auth` flag.
- If no valid UPST can be generated from the stored refresh token (e.g. refresh token expired), it will trigger a **browser-based sign-in** again.

From the user’s perspective, this means:

- First time: run `woci ...` → browser login → OCI command executes.
- Thereafter: run `woci ...` → UPST refreshed as needed, no login prompt, until the refresh token TTL/policies require you to login again.

---

## Security and Operational Notes

- **Refresh token sensitivity**: The refresh token is the long-lived credential. Prefer encryption at rest (`encrypt_refresh_token = true`) if your environment supports password entry or secure env var injection.
- **Session token lifetime**: Capped at 60 minutes (OCI limit). The wrapper automatically renews it via the refresh token before running commands.
- **Encryption details**: Passphrase derivation uses PBKDF2-HMAC-SHA256 (200k iterations) for a balanced cost.
- **Secrets management**: Avoid committing `woci_manager.ini` if it contains a `client_secret`.
- **Logging**: Tokens are never logged; only the authorization URL is printed.
- **Rotation**: Supports refresh token rotation; if the provider returns a new refresh token, the script updates the stored file.

---

## Where to go next

For full configuration details, including:

- Manager INI format and examples
- Profile resolution semantics
- Environment variables (`WOCI_MANAGER_CONFIG`, refresh token encryption options)
- Kubeconfig exec integration, examples, and troubleshooting

refer to **[`QUICKSTART.md`](./QUICKSTART.md)**.

## Releases and versioning

- Versioning follows Semantic Versioning and is automated via `python-semantic-release`.
- Commit messages must follow Conventional Commits (e.g., `feat: add oauth flow`, `fix: handle missing scope`, `chore!: drop py38`).
- Releases are produced from the `main` branch; the pipeline tags `v<major.minor.patch>`, updates the changelog, and creates a GitHub release.
- The pipeline also maintains floating tags `latest` and `v<major>` that always point to the most recent release.
- Run `semantic-release publish --noop --verbosity=DEBUG` locally to dry-run if you need to validate changes before merging to `main`.
