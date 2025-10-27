#!/bin/bash

# ==============================================================================
# Starter-Script für das universelle Linux Server-Setup
# ==============================================================================
#
# Einfacher Wrapper zum Starten des Setup-Skripts
#
# Verwendung:
#   ./start.sh          # Normal ausführen
#   ./start.sh debug    # Mit Debug-Ausgabe
#   ./start.sh dry-run  # Test-Modus (keine Änderungen)
# ==============================================================================

set -e

# Farben
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_RESET='\033[0m'

# Prüfe ob als root ausgeführt
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_RED}[ERROR] Dieses Skript muss mit sudo ausgeführt werden${C_RESET}"
    echo ""
    echo "Verwendung:"
    echo "  sudo ./start.sh          # Normal"
    echo "  sudo ./start.sh debug    # Mit Debug-Ausgabe"
    echo "  sudo ./start.sh dry-run  # Test-Modus"
    exit 1
fi

# Skript-Verzeichnis ermitteln
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETUP_SCRIPT="$SCRIPT_DIR/setup.sh"

# Prüfe ob setup.sh existiert
if [ ! -f "$SETUP_SCRIPT" ]; then
    echo -e "${C_RED}[ERROR] setup.sh nicht gefunden in: $SCRIPT_DIR${C_RESET}"
    exit 1
fi

# Prüfe ob setup.sh ausführbar ist
if [ ! -x "$SETUP_SCRIPT" ]; then
    echo -e "${C_YELLOW}[WARNING] setup.sh ist nicht ausführbar, mache es ausführbar...${C_RESET}"
    chmod +x "$SETUP_SCRIPT"
fi

# Parameter verarbeiten
MODE="${1:-normal}"

case "$MODE" in
    debug)
        echo -e "${C_BLUE}[INFO] Starte Setup im DEBUG-Modus...${C_RESET}"
        DEBUG=1 bash "$SETUP_SCRIPT"
        ;;
    dry-run|dryrun|test)
        echo -e "${C_YELLOW}[INFO] Starte Setup im DRY-RUN-Modus (keine Änderungen)...${C_RESET}"
        DRY_RUN=1 bash "$SETUP_SCRIPT"
        ;;
    normal|*)
        echo -e "${C_GREEN}[INFO] Starte Setup...${C_RESET}"
        bash "$SETUP_SCRIPT"
        ;;
esac

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo -e "${C_GREEN}✅ Setup erfolgreich abgeschlossen!${C_RESET}"
else
    echo ""
    echo -e "${C_RED}❌ Setup mit Fehlercode $EXIT_CODE beendet${C_RESET}"
fi

exit $EXIT_CODE
