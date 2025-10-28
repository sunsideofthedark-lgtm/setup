#!/usr/bin/env bash
#
# Universal Linux Server Setup - Quick Installer
#
# Lädt das Setup-Script direkt aus dem GitHub-Repository und führt es aus.
#
# Verwendung:
#   curl -fsSL https://raw.githubusercontent.com/sunsideofthedark-lgtm/setup/claude/universal-linux-server-setup-011CUW7zdaGyhroSxEM7xPom/install.sh | bash
#
#   # Mit Parametern:
#   curl -fsSL https://raw.githubusercontent.com/sunsideofthedark-lgtm/setup/claude/universal-linux-server-setup-011CUW7zdaGyhroSxEM7xPom/install.sh | bash -s -- --tailscale-key "tskey-xxx" --yes
#
#   # Anderen Branch verwenden:
#   BRANCH=other-branch curl -fsSL https://raw.githubusercontent.com/sunsideofthedark-lgtm/setup/BRANCH/install.sh | bash

set -euo pipefail

# Farben
C_RESET='\033[0m'
C_GREEN='\033[32m'
C_BLUE='\033[34m'
C_YELLOW='\033[33m'
C_RED='\033[31m'
C_CYAN='\033[36m'

# Repository-Informationen
REPO_USER="sunsideofthedark-lgtm"
REPO_NAME="setup"
DEFAULT_BRANCH="${BRANCH:-claude/universal-linux-server-setup-011CUW7zdaGyhroSxEM7xPom}"
SCRIPT_NAME="setup.sh"

# URLs
RAW_URL="https://raw.githubusercontent.com/${REPO_USER}/${REPO_NAME}/${DEFAULT_BRANCH}/${SCRIPT_NAME}"
REPO_URL="https://github.com/${REPO_USER}/${REPO_NAME}"

# Funktionen
info() {
    echo -e "${C_BLUE}[INFO]${C_RESET} $*"
}

success() {
    echo -e "${C_GREEN}[OK]${C_RESET} $*"
}

error() {
    echo -e "${C_RED}[ERROR]${C_RESET} $*" >&2
}

# Banner
echo ""
echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_GREEN}Universal Linux Server Setup - Quick Installer${C_RESET}     ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╠════════════════════════════════════════════════════════════╣${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  Repository: ${REPO_URL}  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  Branch:     ${DEFAULT_BRANCH}  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""

# Prüfe Root-Rechte
if [[ $EUID -ne 0 ]]; then
    error "Dieses Script muss als root ausgeführt werden!"
    echo "Verwendung: sudo bash -c \"\$(curl -fsSL ${RAW_URL})\""
    exit 1
fi

# Prüfe Internet-Verbindung
info "Prüfe Internet-Verbindung..."
if ! curl -s --max-time 5 https://www.google.com > /dev/null 2>&1; then
    error "Keine Internet-Verbindung!"
    exit 1
fi
success "Internet-Verbindung OK"

# Erstelle temporäres Verzeichnis
TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

info "Lade Setup-Script von GitHub..."
info "URL: ${RAW_URL}"

# Download mit curl oder wget
if command -v curl >/dev/null 2>&1; then
    if ! curl -fsSL "${RAW_URL}" -o "${TEMP_DIR}/setup.sh"; then
        error "Download fehlgeschlagen!"
        error "Prüfe, ob der Branch '${DEFAULT_BRANCH}' existiert."
        exit 1
    fi
elif command -v wget >/dev/null 2>&1; then
    if ! wget -qO "${TEMP_DIR}/setup.sh" "${RAW_URL}"; then
        error "Download fehlgeschlagen!"
        error "Prüfe, ob der Branch '${DEFAULT_BRANCH}' existiert."
        exit 1
    fi
else
    error "Weder curl noch wget gefunden!"
    exit 1
fi

success "Setup-Script heruntergeladen"

# Mache Script ausführbar
chmod +x "${TEMP_DIR}/setup.sh"

# Zeige Script-Info
SCRIPT_VERSION=$(grep -E "^# Version:" "${TEMP_DIR}/setup.sh" | head -1 | cut -d: -f2 | xargs || echo "unknown")
info "Script-Version: ${SCRIPT_VERSION}"

echo ""
info "Starte Setup-Script..."
info "Alle Argumente werden an das Script weitergereicht: $*"
echo ""
echo -e "${C_YELLOW}═══════════════════════════════════════════════════════════${C_RESET}"
echo ""

# Führe Setup-Script aus mit allen übergebenen Parametern
cd "${TEMP_DIR}"
exec bash setup.sh "$@"
