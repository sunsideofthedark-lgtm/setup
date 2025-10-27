#!/bin/bash

# ==============================================================================
# Universelles Server-Setup-Skript für Linux-Distributionen (Version 3.0)
# ==============================================================================
# 
# Neue Features v3.0:
# - Tailscale VPN Integration mit Auth-Key Support
# - Komodo Periphery Auto-Setup mit Docker Compose  
# - Moderne CLI-Tools (bat, exa, fzf, ripgrep, fd)
# - Oh-My-Zsh Installation
# - Dry-Run Modus für sichere Tests
# - Verbesserte Idempotenz und Error-Recovery
# - IP-Adressen Anzeige (public IPv4/IPv6, Tailscale)
# - Hostname wird IMMER vor Tailscale konfiguriert
#
# Ausführung:
#   sudo ./setup.sh                                    # Normal
#   DEBUG=1 sudo ./setup.sh                           # Mit Debug-Ausgabe
#   DRY_RUN=1 sudo ./setup.sh                         # Test-Modus (keine Änderungen)
#   TAILSCALE_KEY=tskey-... sudo ./setup.sh          # Mit Tailscale-Key
#   KOMODO_PATH=/srv/komodo sudo ./setup.sh          # Eigener Komodo-Pfad
# ==============================================================================

# --- Globale Variablen ---
C_RESET='\033[0m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_MAGENTA='\033[35m'
C_CYAN='\033[36m'

DEBUG=${DEBUG:-0}
DRY_RUN=${DRY_RUN:-0}
LOGFILE="/var/log/server-setup.log"

# Konfigurierbare Variablen (können via ENV oder Command-line gesetzt werden)
TAILSCALE_KEY=${TAILSCALE_KEY:-}           # Tailscale Auth-Key (optional)
KOMODO_PATH=${KOMODO_PATH:-/opt/komodo}    # Komodo Installation Path (default: /opt/komodo)
HOSTNAME_SET=${HOSTNAME_SET:-}             # Server Hostname (optional)
SSH_PORT_SET=${SSH_PORT_SET:-}             # SSH Port (optional)
SKIP_INTERACTIVE=${SKIP_INTERACTIVE:-0}    # Skip interactive prompts (0=false, 1=true)

# --- Hilfsfunktionen ---

# Help-Funktion
show_help() {
    cat << 'HELPEOF'
Verwendung: ./setup.sh [OPTIONEN]

Universelles Linux Server-Setup-Skript v3.0

OPTIONEN:
  -h, --help                    Diese Hilfe anzeigen
  -d, --debug                   Debug-Modus aktivieren
  -n, --dry-run                 Test-Modus (keine Änderungen)
  -t, --tailscale-key KEY       Tailscale Auth-Key
  -k, --komodo-path PATH        Komodo Installationspfad (Standard: /opt/komodo)
  -H, --hostname NAME           Server Hostname
  -p, --ssh-port PORT           SSH Port (1024-65535)
  -y, --yes                     Automatisch "ja" zu allen Fragen (non-interactive)

UMGEBUNGSVARIABLEN:
  DEBUG=1                       Debug-Modus
  DRY_RUN=1                     Test-Modus
  TAILSCALE_KEY=tskey-...      Tailscale Auth-Key
  KOMODO_PATH=/path            Komodo Installationspfad
  HOSTNAME_SET=myserver        Server Hostname
  SSH_PORT_SET=2222            SSH Port
  SKIP_INTERACTIVE=1           Non-interactive Modus

BEISPIELE:
  # Interaktives Setup
  sudo ./setup.sh

  # Vollautomatisches Setup
  sudo ./setup.sh --tailscale-key tskey-auth-XXX --komodo-path /srv/komodo --yes

  # Mit allen Optionen
  sudo ./setup.sh \
    --tailscale-key tskey-auth-k1234567CNTRL-ABCD \
    --komodo-path /srv/komodo \
    --hostname myserver \
    --ssh-port 2222 \
    --yes

  # Dry-Run zum Testen
  sudo ./setup.sh --dry-run --tailscale-key tskey-auth-XXX

  # Mit Umgebungsvariablen
  TAILSCALE_KEY=tskey-auth-XXX KOMODO_PATH=/srv/komodo sudo ./setup.sh

HELPEOF
    exit 0
}

# Command-line Arguments parsen
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                ;;
            -d|--debug)
                DEBUG=1
                shift
                ;;
            -n|--dry-run)
                DRY_RUN=1
                shift
                ;;
            -t|--tailscale-key)
                TAILSCALE_KEY="$2"
                shift 2
                ;;
            -k|--komodo-path)
                KOMODO_PATH="$2"
                shift 2
                ;;
            -H|--hostname)
                HOSTNAME_SET="$2"
                shift 2
                ;;
            -p|--ssh-port)
                SSH_PORT_SET="$2"
                shift 2
                ;;
            -y|--yes|--skip-interactive)
                SKIP_INTERACTIVE=1
                shift
                ;;
            *)
                echo "Unbekannte Option: $1"
                echo "Verwenden Sie --help für Hilfe"
                exit 1
                ;;
        esac
    done
}

dry_run() {
    local cmd="$@"
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${C_MAGENTA}[DRY-RUN] Would execute: $cmd${C_RESET}"
        log_action "DRY-RUN" "$cmd"
        return 0
    else
        eval "$cmd"
        return $?
    fi
}

setup_logging() {
    if [ ! -f "$LOGFILE" ]; then
        touch "$LOGFILE"
        chmod 600 "$LOGFILE"
    fi
    echo "=== Server Setup gestartet am $(date) ===" >> "$LOGFILE"
    echo "Skript: $0" >> "$LOGFILE"
    echo "Benutzer: $(whoami)" >> "$LOGFILE"
    echo "OS: $(uname -a)" >> "$LOGFILE"
    [ "$DRY_RUN" = "1" ] && echo "MODE: DRY-RUN" >> "$LOGFILE"
    echo "=========================================" >> "$LOGFILE"
}

debug() {
    local message="[DEBUG $(date '+%H:%M:%S')] $1"
    [ "$DEBUG" = "1" ] && echo -e "${C_MAGENTA}$message${C_RESET}" >&2
    echo "$message" >> "$LOGFILE" 2>/dev/null || true
}

log_action() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" >> "$LOGFILE" 2>/dev/null || true
}

info() {
    echo -e "${C_BLUE}[INFO] $1${C_RESET}"
    log_action "INFO" "$1"
}

success() {
    echo -e "${C_GREEN}[SUCCESS] $1${C_RESET}"
    log_action "SUCCESS" "$1"
}

warning() {
    echo -e "${C_YELLOW}[WARNING] $1${C_RESET}"
    log_action "WARNING" "$1"
}

error() {
    echo -e "${C_RED}[ERROR] $1${C_RESET}" >&2
    log_action "ERROR" "$1"
}

confirm() {
    if [ "$DRY_RUN" = "1" ]; then
        echo -e "${C_MAGENTA}[DRY-RUN] Auto-confirming: $1${C_RESET}"
        return 0
    fi
    if [ "$SKIP_INTERACTIVE" = "1" ]; then
        echo -e "${C_GREEN}[AUTO] $1 → yes${C_RESET}"
        return 0
    fi
    while true; do
        echo -e "${C_CYAN}$1 [y/N]: ${C_RESET}" >&2
        read -r yn
        debug "Benutzer-Eingabe für '$1': '$yn'"
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* | "" ) return 1;;
            * ) echo "Bitte mit y (Ja) oder n (Nein) antworten.";;
        esac
    done
}

create_backup() {
    local file="$1"
    local backup_dir="/var/backups/server-setup"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    if [ -f "$file" ]; then
        [ "$DRY_RUN" = "1" ] && debug "[DRY-RUN] Would backup: $file" && return 0
        mkdir -p "$backup_dir"
        cp "$file" "$backup_dir/$(basename $file).backup.$timestamp"
        log_action "BACKUP" "Created backup of $file"
        find "$backup_dir" -name "$(basename $file).backup.*" -type f | sort -r | tail -n +11 | xargs -r rm
    fi
}

validate_hostname() {
    local hostname="$1"
    [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && return 1
    [ ${#hostname} -gt 63 ] && return 1
    return 0
}

validate_username() {
    local username="$1"
    [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] && return 1
    [ ${#username} -gt 32 ] && return 1
    local reserved_names="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve messagebus systemd-timesync syslog"
    for reserved in $reserved_names; do
        [ "$username" = "$reserved" ] && return 1
    done
    return 0
}

validate_port() {
    local port="$1"
    [[ ! "$port" =~ ^[0-9]+$ ]] && return 1
    [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ] && return 1
    local reserved_ports="1080 3128 8080 8888 9050 9051"
    for reserved_port in $reserved_ports; do
        [ "$port" = "$reserved_port" ] && return 1
    done
    return 0
}

check_network() {
    debug "Prüfe Netzwerk-Konnektivität"
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        warning "Keine Internet-Verbindung erkannt."
        return 1
    fi
    return 0
}

# --- OS-Erkennung ---

detect_os() {
    info "Erkenne Betriebssystem..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_NAME=$(cat /etc/redhat-release)
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_NAME="Debian $(cat /etc/debian_version)"
    else
        error "Betriebssystem konnte nicht erkannt werden"
        exit 1
    fi

    case "$OS_ID" in
        ubuntu|debian)
            PKG_MANAGER="apt"
            PKG_UPDATE="apt update"
            PKG_UPGRADE="apt upgrade -y"
            PKG_INSTALL="apt install -y"
            PKG_AUTOREMOVE="apt autoremove -y"
            SERVICE_MANAGER="systemctl"
            FIREWALL_CMD="ufw"
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="ssh"
            ;;
        centos|rhel|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
                PKG_UPDATE="dnf check-update || true"
                PKG_UPGRADE="dnf upgrade -y"
                PKG_INSTALL="dnf install -y"
                PKG_AUTOREMOVE="dnf autoremove -y"
            else
                PKG_MANAGER="yum"
                PKG_UPDATE="yum check-update || true"
                PKG_UPGRADE="yum update -y"
                PKG_INSTALL="yum install -y"
                PKG_AUTOREMOVE="yum autoremove -y"
            fi
            SERVICE_MANAGER="systemctl"
            FIREWALL_CMD="firewall-cmd"
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="sshd"
            ;;
        fedora)
            PKG_MANAGER="dnf"
            PKG_UPDATE="dnf check-update || true"
            PKG_UPGRADE="dnf upgrade -y"
            PKG_INSTALL="dnf install -y"
            PKG_AUTOREMOVE="dnf autoremove -y"
            SERVICE_MANAGER="systemctl"
            FIREWALL_CMD="firewall-cmd"
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="sshd"
            ;;
        opensuse*|sles)
            PKG_MANAGER="zypper"
            PKG_UPDATE="zypper refresh"
            PKG_UPGRADE="zypper update -y"
            PKG_INSTALL="zypper install -y"
            PKG_AUTOREMOVE="zypper remove --clean-deps -y"
            SERVICE_MANAGER="systemctl"
            FIREWALL_CMD="firewall-cmd"
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="sshd"
            ;;
        arch)
            PKG_MANAGER="pacman"
            PKG_UPDATE="pacman -Sy"
            PKG_UPGRADE="pacman -Syu --noconfirm"
            PKG_INSTALL="pacman -S --noconfirm"
            PKG_AUTOREMOVE="pacman -Rs --noconfirm"
            SERVICE_MANAGER="systemctl"
            FIREWALL_CMD="ufw"
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="sshd"
            ;;
        *)
            error "Nicht unterstützte Distribution: $OS_ID"
            exit 1
            ;;
    esac

    debug "Paketmanager: $PKG_MANAGER"
    debug "Service-Manager: $SERVICE_MANAGER"
    debug "Firewall: $FIREWALL_CMD"
}

# --- Paket-Management ---

is_package_installed() {
    local package="$1"
    local alternative_check="$2"
    debug "Prüfe Installation von: $package"
    case "$PKG_MANAGER" in
        apt)
            dpkg -l | grep -q "^ii.*$package " && return 0
            ;;
        yum|dnf)
            $PKG_MANAGER list installed "$package" >/dev/null 2>&1 && return 0
            ;;
        zypper)
            zypper se -i "$package" | grep -q "^i " && return 0
            ;;
        pacman)
            pacman -Q "$package" >/dev/null 2>&1 && return 0
            ;;
    esac
    [ -n "$alternative_check" ] && command -v "$alternative_check" >/dev/null 2>&1 && return 0
    return 1
}

install_package() {
    local package="$1"
    local max_retries=3
    local retry_count=0
    debug "Installiere Paket: $package"
    is_package_installed "$package" && success "Paket '$package' bereits installiert" && return 0
    while [ $retry_count -lt $max_retries ]; do
        if dry_run "$PKG_INSTALL $package"; then
            log_action "INSTALL" "Successfully installed: $package"
            return 0
        fi
        retry_count=$((retry_count + 1))
        [ $retry_count -lt $max_retries ] && warning "Retry $retry_count/$max_retries..." && sleep 2
    done
    error "Installation von $package fehlgeschlagen"
    return 1
}

# --- Service-Management ---

manage_service() {
    local action=$1
    local service=$2
    case "$SERVICE_MANAGER" in
        systemctl)
            dry_run "systemctl $action $service"
            ;;
        service)
            dry_run "service $service $action"
            ;;
    esac
}

# --- Firewall ---

setup_firewall() {
    local ssh_port=$1
    case "$FIREWALL_CMD" in
        ufw)
            info "Konfiguriere UFW-Firewall"
            [ -f /etc/default/ufw ] && dry_run "sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw"
            dry_run "ufw default deny incoming"
            dry_run "ufw default allow outgoing"
            dry_run "ufw allow $ssh_port/tcp"
            dry_run "ufw deny 22/tcp"
            dry_run "ufw allow 80/tcp"
            dry_run "ufw allow 443/tcp"
            dry_run "ufw allow 41641/udp"  # Tailscale
            dry_run "ufw allow 51820/udp"  # WireGuard

            # Tailscale-Interface komplett öffnen (alle Ports)
            info "Öffne Tailscale-Interface komplett (alle Ports für Docker-Kommunikation)"
            dry_run "ufw allow in on tailscale0"
            dry_run "ufw allow out on tailscale0"

            [ "$DRY_RUN" != "1" ] && echo "y" | ufw enable || debug "[DRY-RUN] Would enable UFW"
            ;;
        firewall-cmd)
            info "Konfiguriere firewalld"
            dry_run "systemctl enable firewalld"
            dry_run "systemctl start firewalld"
            dry_run "firewall-cmd --permanent --remove-service=ssh"
            dry_run "firewall-cmd --permanent --add-port=$ssh_port/tcp"
            dry_run "firewall-cmd --permanent --add-service=http"
            dry_run "firewall-cmd --permanent --add-service=https"
            dry_run "firewall-cmd --permanent --add-port=41641/udp"
            dry_run "firewall-cmd --permanent --add-port=51820/udp"

            # Tailscale-Interface komplett öffnen
            info "Öffne Tailscale-Interface komplett (alle Ports für Docker-Kommunikation)"
            dry_run "firewall-cmd --permanent --zone=trusted --add-interface=tailscale0"

            dry_run "firewall-cmd --reload"
            ;;
    esac
}

# --- IP-Adressen Anzeige ---

show_ip_addresses() {
    echo ""
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_CYAN}           📡 NETZWERK-INFORMATIONEN             ${C_RESET}"
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    echo -e "${C_BLUE}🌐 Öffentliche IPv4-Adresse:${C_RESET}"
    local public_ipv4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || echo "Nicht verfügbar")
    echo -e "   ${C_GREEN}$public_ipv4${C_RESET}"
    echo ""
    
    echo -e "${C_BLUE}🌐 Öffentliche IPv6-Adresse:${C_RESET}"
    local public_ipv6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null || echo "Nicht verfügbar")
    echo -e "   ${C_GREEN}$public_ipv6${C_RESET}"
    echo ""
    
    if command -v tailscale >/dev/null 2>&1; then
        echo -e "${C_BLUE}🔐 Tailscale VPN-Adresse:${C_RESET}"
        local tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "Nicht verbunden")
        local tailscale_ipv6=$(tailscale ip -6 2>/dev/null || echo "Nicht verfügbar")
        echo -e "   IPv4: ${C_GREEN}$tailscale_ip${C_RESET}"
        echo -e "   IPv6: ${C_GREEN}$tailscale_ipv6${C_RESET}"
        echo ""
    fi
    
    echo -e "${C_BLUE}🔌 Lokale Netzwerk-Interfaces:${C_RESET}"
    ip -br addr | grep -v "^lo" | while read line; do
        echo -e "   ${C_YELLOW}$line${C_RESET}"
    done
    echo ""
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo ""
    
    log_action "NETWORK" "Public IPv4: $public_ipv4"
    log_action "NETWORK" "Public IPv6: $public_ipv6"
    command -v tailscale >/dev/null 2>&1 && log_action "NETWORK" "Tailscale IPv4: $tailscale_ip"
}

# --- Tailscale Installation ---

install_tailscale() {
    info "📦 Installiere Tailscale VPN..."
    
    if command -v tailscale >/dev/null 2>&1; then
        success "Tailscale ist bereits installiert: $(tailscale version)"
        tailscale status >/dev/null 2>&1 && info "Tailscale ist bereits verbunden." && return 0
        warning "Tailscale ist installiert aber nicht verbunden."
    else
        case "$OS_ID" in
            ubuntu|debian)
                info "Installiere Tailscale über offizielles Repository..."
                if [ "$DRY_RUN" != "1" ]; then
                    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.noarmor.gpg | tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
                    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/focal.tailscale-keyring.list | tee /etc/apt/sources.list.d/tailscale.list
                    eval $PKG_UPDATE
                fi
                install_package "tailscale"
                ;;
            centos|rhel|rocky|almalinux|fedora)
                info "Installiere Tailscale über offizielles Repository..."
                [ "$DRY_RUN" != "1" ] && (dnf config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/9/tailscale.repo 2>/dev/null || yum-config-manager --add-repo https://pkgs.tailscale.com/stable/rhel/9/tailscale.repo)
                install_package "tailscale"
                ;;
            *)
                error "Tailscale-Installation für $OS_ID nicht implementiert"
                warning "Besuche https://tailscale.com/download/linux"
                return 1
                ;;
        esac
        manage_service enable tailscaled
        manage_service start tailscaled
        success "Tailscale installiert!"
    fi
    
    info "Öffne Firewall-Port für Tailscale..."
    case "$FIREWALL_CMD" in
        ufw) dry_run "ufw allow 41641/udp comment 'Tailscale VPN'" ;;
        firewall-cmd) dry_run "firewall-cmd --permanent --add-port=41641/udp" && dry_run "firewall-cmd --reload" ;;
    esac
    
    echo ""
    echo -e "${C_YELLOW}═══════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_YELLOW}  🔑 TAILSCALE AUTHENTIFIZIERUNG                  ${C_RESET}"
    echo -e "${C_YELLOW}═══════════════════════════════════════════════════${C_RESET}"
    echo ""

    # Prüfe ob Key bereits als Umgebungsvariable gesetzt ist
    if [ -n "$TAILSCALE_KEY" ]; then
        info "Tailscale-Key aus Umgebungsvariable erkannt"
        info "Key: ${TAILSCALE_KEY:0:20}..." # Zeige nur die ersten 20 Zeichen
    else
        info "Erstellen Sie einen Auth-Key unter: https://login.tailscale.com/admin/settings/keys"
        echo ""
        info "Empfohlene Einstellungen:"
        echo "  • Reusable: Ja"
        echo "  • Ephemeral: Nein"
        echo "  • Pre-authorized: Ja"
        echo ""

        [ "$DRY_RUN" = "1" ] && warning "[DRY-RUN] Überspringe Tailscale-Authentifizierung" && return 0

        read -p "Tailscale Auth-Key eingeben (oder Enter zum Überspringen): " TAILSCALE_KEY
    fi

    if [ -n "$TAILSCALE_KEY" ]; then
        info "Verbinde mit Tailscale-Netzwerk..."
        TAILSCALE_EXIT_NODE=""
        TAILSCALE_SSH=""
        confirm "Als Exit-Node konfigurieren?" && TAILSCALE_EXIT_NODE="--advertise-exit-node"
        confirm "SSH über Tailscale aktivieren?" && TAILSCALE_SSH="--ssh"
        
        if tailscale up --authkey="$TAILSCALE_KEY" $TAILSCALE_EXIT_NODE $TAILSCALE_SSH --accept-routes; then
            success "✅ Tailscale erfolgreich verbunden!"
            sleep 2
            show_ip_addresses
        else
            error "Tailscale-Verbindung fehlgeschlagen"
            warning "Versuchen Sie: tailscale up --authkey=<IHR_KEY>"
            return 1
        fi
    else
        warning "Tailscale-Authentifizierung übersprungen."
        info "Später verbinden mit: sudo tailscale up --authkey=<IHR_KEY>"
    fi
    return 0
}

# --- Komodo Periphery Setup ---

setup_komodo_periphery() {
    info "🦎 Richte Komodo Periphery ein..."

    if ! command -v docker >/dev/null 2>&1; then
        error "Docker ist nicht installiert. Bitte installiere Docker zuerst."
        return 1
    fi

    # Zeige konfigurierten Pfad an
    info "Komodo Installationspfad: $KOMODO_PATH"

    # Frage nach eigenem Pfad, falls nicht über Umgebungsvariable gesetzt
    if [ "$KOMODO_PATH" = "/opt/komodo" ] && [ "$DRY_RUN" != "1" ]; then
        echo ""
        if confirm "Möchten Sie einen anderen Installationspfad verwenden?"; then
            read -p "Komodo Installationspfad eingeben [Standard: /opt/komodo]: " CUSTOM_KOMODO_PATH
            if [ -n "$CUSTOM_KOMODO_PATH" ]; then
                KOMODO_PATH="$CUSTOM_KOMODO_PATH"
                info "Verwende benutzerdefinierten Pfad: $KOMODO_PATH"
            fi
        fi
    fi

    if [ -f "$KOMODO_PATH/docker-compose.yml" ]; then
        warning "Komodo Periphery ist bereits konfiguriert in: $KOMODO_PATH"
        confirm "Konfiguration überschreiben?" || return 0
    fi

    info "Erstelle Komodo-Verzeichnis: $KOMODO_PATH"
    [ "$DRY_RUN" != "1" ] && mkdir -p "$KOMODO_PATH" && chmod 755 "$KOMODO_PATH" || debug "[DRY-RUN] Would create $KOMODO_PATH"
    
    local tailscale_ip=""
    if command -v tailscale >/dev/null 2>&1; then
        tailscale_ip=$(tailscale ip -4 2>/dev/null || echo "")
        [ -n "$tailscale_ip" ] && info "Verwende Tailscale-IP: $tailscale_ip"
    fi
    [ -z "$tailscale_ip" ] && warning "Keine Tailscale-IP. Verwende 0.0.0.0" && tailscale_ip="0.0.0.0"
    
    local passkey=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
    
    info "Erstelle docker-compose.yml..."
    if [ "$DRY_RUN" != "1" ]; then
        cat > "$KOMODO_PATH/docker-compose.yml" << EOF
# docker-compose.yml - Komodo Periphery

services:
  periphery:
    image: ghcr.io/moghtech/komodo-periphery:\${COMPOSE_KOMODO_IMAGE_TAG:-latest}
    container_name: komodo-periphery
    restart: unless-stopped
    labels:
      komodo.skip:
    ports:
      - "${tailscale_ip}:8120:8120"
    env_file:
      - .env
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /proc:/proc
      - \${PERIPHERY_ROOT_DIRECTORY}:\${PERIPHERY_ROOT_DIRECTORY}
EOF
        success "docker-compose.yml erstellt"
    else
        debug "[DRY-RUN] Would create docker-compose.yml"
    fi

    info "Erstelle .env Konfiguration..."
    if [ "$DRY_RUN" != "1" ]; then
        cat > "$KOMODO_PATH/.env" << EOF
# .env - Komodo Periphery Konfiguration

COMPOSE_KOMODO_IMAGE_TAG=latest
PERIPHERY_ROOT_DIRECTORY=$KOMODO_PATH
PERIPHERY_PASSKEYS=${passkey}
PERIPHERY_SSL_ENABLED=true
PERIPHERY_DISABLE_TERMINALS=false
EOF
        chmod 600 "$KOMODO_PATH/.env"
        success ".env Konfiguration erstellt"
    else
        debug "[DRY-RUN] Would create .env"
    fi

    echo ""
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo -e "${C_CYAN}    🦎 KOMODO PERIPHERY KONFIGURATION           ${C_RESET}"
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo ""
    echo -e "${C_BLUE}📁 Installation:${C_RESET} $KOMODO_PATH/"
    echo -e "${C_BLUE}🔌 Port:${C_RESET} ${tailscale_ip}:8120"
    echo -e "${C_BLUE}🔑 Passkey:${C_RESET} ${C_GREEN}${passkey}${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}⚠️  WICHTIG: Notieren Sie das Passkey!${C_RESET}"
    echo ""
    echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
    echo ""

    log_action "KOMODO" "Periphery configured at $KOMODO_PATH/"
    log_action "KOMODO" "Passkey: ${passkey}"

    if confirm "Komodo Periphery jetzt starten?"; then
        info "Starte Komodo Periphery..."
        if [ "$DRY_RUN" != "1" ]; then
            cd "$KOMODO_PATH"
            docker compose pull
            docker compose up -d
            sleep 3
            docker ps | grep -q "komodo-periphery" && success "✅ Komodo Periphery läuft!" || error "Start fehlgeschlagen"
        else
            debug "[DRY-RUN] Would start Komodo"
        fi
    else
        info "Später starten mit: cd $KOMODO_PATH && docker compose up -d"
    fi
    
    return 0
}

# --- Moderne CLI-Tools ---

install_modern_cli_tools() {
    info "🛠️ Installiere moderne CLI-Tools..."
    
    # bat
    if ! command -v bat >/dev/null 2>&1 && ! command -v batcat >/dev/null 2>&1; then
        install_package "bat"
        if [ "$DRY_RUN" != "1" ] && [ -f /usr/bin/batcat ] && [ ! -f /usr/local/bin/bat ]; then
            ln -s /usr/bin/batcat /usr/local/bin/bat 2>/dev/null || true
        fi
    fi
    
    # exa
    command -v exa >/dev/null 2>&1 || install_package "exa"
    
    # fzf
    command -v fzf >/dev/null 2>&1 || install_package "fzf"
    
    # ripgrep
    command -v rg >/dev/null 2>&1 || install_package "ripgrep"
    
    # fd
    if ! command -v fd >/dev/null 2>&1; then
        case "$OS_ID" in
            ubuntu|debian)
                install_package "fd-find"
                [ "$DRY_RUN" != "1" ] && [ -f /usr/bin/fdfind ] && ln -s /usr/bin/fdfind /usr/local/bin/fd 2>/dev/null || true
                ;;
            *)
                install_package "fd"
                ;;
        esac
    fi
    
    success "Moderne CLI-Tools installiert!"
    return 0
}

# Oh-My-Zsh Installation
install_oh_my_zsh() {
    info "🎨 Installiere Oh-My-Zsh..."
    
    command -v zsh >/dev/null 2>&1 || install_package "zsh"
    
    if [ -n "$NEW_USER" ]; then
        local user_home=$(eval echo ~$NEW_USER)
        [ -d "$user_home/.oh-my-zsh" ] && success "Oh-My-Zsh bereits installiert" && return 0
        [ "$DRY_RUN" = "1" ] && debug "[DRY-RUN] Would install Oh-My-Zsh" && return 0
        
        info "Installiere Oh-My-Zsh für $NEW_USER..."
        sudo -u "$NEW_USER" bash -c 'sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended'
        
        if confirm "Powerlevel10k Theme installieren?"; then
            sudo -u "$NEW_USER" git clone --depth=1 https://github.com/romkatv/powerlevel10k.git "$user_home/.oh-my-zsh/custom/themes/powerlevel10k"
            sudo -u "$NEW_USER" sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="powerlevel10k\/powerlevel10k"/' "$user_home/.zshrc"
        fi
        
        sudo -u "$NEW_USER" sed -i 's/plugins=(git)/plugins=(git docker sudo history fzf)/' "$user_home/.zshrc"
        
        cat >> "$user_home/.zshrc" << 'ZSHEOF'

# === Moderne CLI-Tools Aliase ===
command -v bat >/dev/null 2>&1 && alias cat='bat --paging=never' && alias less='bat'
command -v batcat >/dev/null 2>&1 && alias cat='batcat --paging=never' && alias less='batcat'
command -v exa >/dev/null 2>&1 && alias ls='exa --icons' && alias ll='exa -l --icons --git' && alias la='exa -la --icons --git'
command -v rg >/dev/null 2>&1 && alias grep='rg'
command -v fd >/dev/null 2>&1 && alias find='fd'

alias dps='docker ps'
alias dcup='docker compose up -d'
alias dcdown='docker compose down'
alias myip='curl ifconfig.me'
ZSHEOF
        
        chown "$NEW_USER:$NEW_USER" "$user_home/.zshrc"
        
        confirm "zsh als Standard-Shell für $NEW_USER setzen?" && chsh -s $(which zsh) "$NEW_USER"
        success "✅ Oh-My-Zsh installiert!"
    fi
    return 0
}

# --- HAUPTSKRIPT ---

# Pers Command-line Arguments (must be before setup_logging)
parse_arguments "$@"

setup_logging
detect_os

[ "$DEBUG" = "1" ] && debug "Debug-Modus aktiv"
[ "$DRY_RUN" = "1" ] && warning "DRY-RUN MODUS - Keine echten Änderungen!"
[ "$SKIP_INTERACTIVE" = "1" ] && info "Non-Interactive Modus aktiviert (--yes)"

# Zeige erkannte Parameter
if [ -n "$TAILSCALE_KEY" ]; then
    debug "Tailscale-Key erkannt: ${TAILSCALE_KEY:0:20}..."
fi
if [ "$KOMODO_PATH" != "/opt/komodo" ]; then
    debug "Komodo-Pfad: $KOMODO_PATH"
fi
if [ -n "$HOSTNAME_SET" ]; then
    debug "Hostname: $HOSTNAME_SET"
fi
if [ -n "$SSH_PORT_SET" ]; then
    debug "SSH-Port: $SSH_PORT_SET"
fi

if [ "$(id -u)" -ne 0 ]; then
    error "Dieses Skript muss mit root-Rechten (sudo) ausgeführt werden."
    exit 1
fi

check_network

clear
echo -e "${C_BLUE}=====================================================${C_RESET}"
echo -e "${C_BLUE}  Universelles Linux Server-Setup-Skript v3.0${C_RESET}"
echo -e "${C_BLUE}=====================================================${C_RESET}"
echo ""
info "Erkanntes System: $OS_NAME"
info "Paketmanager: $PKG_MANAGER"
echo ""

echo "Dies ist eine verkürzte Demo-Version des Setup-Skripts."
echo "Für die vollständige Version siehe: https://github.com/..."
echo ""

info "Verfügbare Module:"
echo "  1. System Update"
echo "  2. Hostname konfigurieren (IMMER VOR Tailscale!)"
echo "  3. Tailscale VPN installieren + IP-Anzeige"
echo "  4. Komodo Periphery Setup"
echo "  5. Moderne CLI-Tools installieren"
echo "  6. Oh-My-Zsh installieren"
echo ""

if confirm "System-Update durchführen?"; then
    info "Aktualisiere System..."
    dry_run "$PKG_UPDATE"
    dry_run "$PKG_UPGRADE"
    success "System aktualisiert"
fi

if confirm "Hostname konfigurieren?"; then
    CURRENT_HOSTNAME=$(hostname)
    info "Aktueller Hostname: $CURRENT_HOSTNAME"
    read -p "Neuer Hostname: " NEW_HOSTNAME
    if [ -n "$NEW_HOSTNAME" ] && validate_hostname "$NEW_HOSTNAME"; then
        dry_run "hostnamectl set-hostname $NEW_HOSTNAME"
        success "Hostname auf $NEW_HOSTNAME gesetzt"
    fi
fi

confirm "Tailscale VPN installieren?" && install_tailscale

confirm "Komodo Periphery einrichten?" && setup_komodo_periphery

confirm "Moderne CLI-Tools installieren?" && install_modern_cli_tools

echo ""
info "Netzwerk-Informationen:"
show_ip_addresses

echo ""
success "Setup abgeschlossen!"
info "Log-Datei: $LOGFILE"

[ "$DRY_RUN" = "1" ] && warning "DRY-RUN Modus war aktiv - keine Änderungen vorgenommen!"

# Ende des Skripts
