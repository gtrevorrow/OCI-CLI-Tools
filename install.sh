#!/usr/bin/env bash
# MIT License
# Copyright (c) 2025 Gordon Trevorrow
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# Author: Gordon Trevorrow
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
if [ -f "${SCRIPT_DIR}/requirements.txt" ]; then
  "${APP_DIR}/venv/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt" >/dev/null
else
  "${APP_DIR}/venv/bin/pip" install requests cryptography >/dev/null
fi

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

# Create a convenient alias launcher
WOCI_LAUNCHER="${BIN_DIR}/woci"
ln -sf "${LAUNCHER}" "${WOCI_LAUNCHER}"

# Final notes
case ":$PATH:" in
  *":${BIN_DIR}:"*) ;;
  *) echo "NOTE: Add ${BIN_DIR} to your PATH to use '${APP_NAME}' directly." ;;
 esac

echo "Installed ${APP_NAME}. Try:"
echo "  ${APP_NAME} --help"
echo "  woci --help"
