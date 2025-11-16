#!/usr/bin/env bash
# Self-bootstrapping installer (Option 3): create a local venv and launcher for oci_upst_session_manager.py
# Installs into: ~/.local/share/oci-upst-manager
# Launch command: oci-upst-session-manager (in ~/.local/bin)
set -euo pipefail

APP_NAME="oci-upst-session-manager"
APP_DIR="${HOME}/.local/share/oci-upst-manager"
BIN_DIR="${HOME}/.local/bin"
PYTHON_BIN="${PYTHON:-python3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/oci_upst_session_manager.py"

if [ ! -f "${SCRIPT_PATH}" ]; then
  echo "Error: cannot find oci_upst_session_manager.py next to install.sh (looked at ${SCRIPT_PATH})" >&2
  exit 1
fi

mkdir -p "${APP_DIR}" "${BIN_DIR}"

# Create venv if missing
if [ ! -d "${APP_DIR}/venv" ]; then
  echo "Creating virtualenv at ${APP_DIR}/venv"
  "${PYTHON_BIN}" -m venv "${APP_DIR}/venv"
fi

# Install/upgrade deps
"${APP_DIR}/venv/bin/pip" install --upgrade pip >/dev/null
"${APP_DIR}/venv/bin/pip" install requests cryptography >/dev/null

# Create launcher
LAUNCHER="${BIN_DIR}/${APP_NAME}"
cat > "${LAUNCHER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
EXEC_PY="$HOME/.local/share/oci-upst-manager/venv/bin/python"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# Use installed script path relative to install location captured at install time
SCRIPT_PATH="REPLACED_AT_INSTALL"
if [ ! -f "$SCRIPT_PATH" ]; then
  # fallback: try next to launcher (useful if moved together)
  SCRIPT_PATH="$(dirname "$0")/oci_upst_session_manager.py"
fi
exec "$EXEC_PY" "$SCRIPT_PATH" "$@"
EOF

# Persist original absolute script path into launcher
# Replace placeholder so launcher knows where the manager script lives
ESCAPED_SCRIPT_PATH=$(printf '%s
' "$SCRIPT_PATH" | sed -e 's/[\/&]/\\&/g')
sed -i '' -e "s|REPLACED_AT_INSTALL|$ESCAPED_SCRIPT_PATH|" "$LAUNCHER" 2>/dev/null || \
  sed -i -e "s|REPLACED_AT_INSTALL|$ESCAPED_SCRIPT_PATH|" "$LAUNCHER"

chmod +x "${LAUNCHER}"

# Final notes
case ":$PATH:" in
  *":${BIN_DIR}:"*) ;;
  *) echo "NOTE: Add ${BIN_DIR} to your PATH to use '${APP_NAME}' directly." ;;
 esac

echo "Installed ${APP_NAME}. Try:"
echo "  ${APP_NAME} --help"
