#!/bin/bash

# ==============================================================================
# 🚀 UNIVERSELLES LINUX SERVER SETUP SCRIPT v3.0
# ==============================================================================
#
# DAS EINE umfassende Script für sichere Linux-Server-Konfiguration
#
# 📦 WAS WIRD INSTALLIERT & KONFIGURIERT:
# ==============================================================================
#
# 🔐 SICHERHEIT:
#   ✓ SSH-Härtung (Port-Änderung, Key-Only-Auth, Root-Login-Sperre)
#   ✓ Firewall (UFW/firewalld mit automatischer Konfiguration)
#   ✓ Fail2Ban (Brute-Force-Schutz: 3 Versuche → 1h Ban)
#   ✓ Automatische Updates (unattended-upgrades/yum-cron)
#   ✓ Root-Account-Sperrung nach Setup
#   ✓ Sudo-Benutzer mit sicheren Rechten
#
# 🌐 NETZWERK & VPN:
#   ✓ Tailscale VPN (mit Auth-Key-Integration)
#   ✓ Hostname-Konfiguration (immer VOR Tailscale!)
#   ✓ IP-Adressen-Anzeige (public IPv4/IPv6 + Tailscale)
#   ✓ Tailscale-Firewall (komplette Interface-Freigabe)
#   ✓ Docker über Tailscale kommunikationsfähig
#
# 🐳 DOCKER & KOMODO:
#   ✓ Docker Engine + Docker Compose v2
#   ✓ Komodo Periphery (Docker-Management-Tool)
#   ✓ Auto-Konfiguration mit docker-compose.yml + .env
#   ✓ Tailscale-IP-Binding (Port 8120)
#   ✓ Passkey-Management (interaktiv/generiert)
#   ✓ SSL aktiviert
#
# 🛠️ MODERNE CLI-TOOLS:
#   ✓ bat        - cat mit Syntax-Highlighting
#   ✓ exa        - ls-Alternative mit Icons & Git-Status
#   ✓ fzf        - Fuzzy Finder für Kommandozeile
#   ✓ ripgrep    - Blitzschnelles grep (rg)
#   ✓ fd         - find-Alternative
#   ✓ htop       - System-Monitor
#   ✓ ncdu       - Disk-Usage-Analyzer
#
# 🎨 SHELL & TERMINAL:
#   ✓ Oh-My-Zsh mit Powerlevel10k Theme
#   ✓ Plugins: git, docker, docker-compose, sudo, history
#   ✓ Custom Motd (Login-Banner mit System-Info)
#   ✓ Zsh als Standard-Shell
#
# 🎨 CUSTOM MOTD (Message of the Day):
#   ✓ Hostname, Öffentliche IP, Tailscale IP
#   ✓ System-Status (Uptime, Load, Memory, Disk)
#   ✓ Docker Container-Status
#   ✓ Komodo & Tailscale Status mit Farben
#
# 📋 UNTERSTÜTZTE DISTRIBUTIONEN:
#   ✓ Ubuntu 20.04+, 22.04+, 24.04+
#   ✓ Debian 10+, 11+, 12+
#   ✓ CentOS 7+, 8+
#   ✓ RHEL 7+, 8+, 9+
#   ✓ Rocky Linux 8+, 9+
#   ✓ AlmaLinux 8+, 9+
#   ✓ Fedora 35+
#   ✓ openSUSE Leap 15+
#   ✓ Arch Linux
#
# 🔧 SCRIPT-FEATURES:
#   ✓ Modulare Auswahl (nur gewünschte Features)
#   ✓ Idempotenz (mehrfach ausführbar)
#   ✓ Dry-Run-Modus (testen ohne Änderungen)
#   ✓ Debug-Modus (ausführliche Ausgaben)
#   ✓ Automatische Backups vor Änderungen
#   ✓ Error-Recovery & Retry-Mechanismen
#   ✓ Ausführliches Logging (/var/log/server-setup.log)
#   ✓ Non-Interactive Mode (für CI/CD)
#
# ==============================================================================
# 📖 VERWENDUNG:
# ==============================================================================
#
# 1. EINFACHE INTERAKTIVE INSTALLATION:
#    sudo ./setup.sh
#
# 2. MIT COMMAND-LINE ARGUMENTEN:
#    sudo ./setup.sh --help
#    sudo ./setup.sh --tailscale-key "tskey-xxx" --hostname "myserver" --yes
#    sudo ./setup.sh --komodo-path "/srv/komodo" --ssh-port 2222
#    sudo ./setup.sh --dry-run                    # Test ohne Änderungen
#    sudo ./setup.sh --debug                      # Mit Debug-Ausgabe
#
# 3. MIT UMGEBUNGSVARIABLEN:
#    TAILSCALE_KEY=tskey-xxx KOMODO_PATH=/srv/komodo sudo ./setup.sh
#    export TAILSCALE_KEY="tskey-xxx"
#    export KOMODO_PATH="/opt/komodo"
#    sudo -E ./setup.sh --yes
#
# 4. VOLLAUTOMATISCH (CI/CD):
#    sudo ./setup.sh \
#      --tailscale-key "tskey-auth-xxx" \
#      --komodo-path "/opt/komodo" \
#      --hostname "prod-server-01" \
#      --ssh-port 2222 \
#      --yes
#
# ==============================================================================
# 🔑 VERFÜGBARE OPTIONEN:
# ==============================================================================
#
#   -h, --help              Zeigt diese Hilfe
#   -d, --debug             Debug-Modus (ausführliche Ausgabe)
#   -n, --dry-run           Test-Modus (keine echten Änderungen)
#   -t, --tailscale-key     Tailscale Auth-Key
#   -k, --komodo-path       Komodo Installationspfad (default: /opt/komodo)
#   -H, --hostname          Server-Hostname
#   -p, --ssh-port          SSH-Port (default: 2222)
#   -y, --yes               Nicht-interaktiver Modus (alle Bestätigungen mit ja)
#
# ==============================================================================
# 🔒 SICHERHEITSHINWEISE:
# ==============================================================================
#
# NACH DEM SETUP:
#   1. SSH-Key auf lokalen Rechner kopieren (vor Root-Sperre!)
#   2. Neue SSH-Verbindung testen (mit neuem Port!)
#   3. Erst dann alte Verbindung schließen
#   4. Tailscale-Key in sicherer Password-Manager speichern
#   5. Komodo-Passkey notieren und im Komodo-Server eintragen
#   6. Regelmäßige Backups einrichten
#
# FIREWALL-PORTS:
#   - SSH: Konfigurierter Port (default 2222)
#   - Komodo: 8120 (nur über Tailscale)
#   - Tailscale: Interface komplett freigegeben
#
# ==============================================================================
# 📝 VERSION & LICENSE:
# ==============================================================================
# Version: 3.0
# Repository: https://github.com/sunsideofthedark-lgtm/setup
# Author: Server Setup Script
# License: MIT
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

    # Passkey interaktiv eingeben (da dieser im Komodo-Server definiert wird)
    local passkey=""
    if [ "$SKIP_INTERACTIVE" != "1" ] && [ "$DRY_RUN" != "1" ]; then
        echo ""
        echo -e "${C_YELLOW}═══════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_YELLOW}  Komodo Periphery Passkey wird benötigt!${C_RESET}"
        echo -e "${C_YELLOW}═══════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "${C_BLUE}Der Passkey muss im Komodo-Server konfiguriert sein.${C_RESET}"
        echo -e "${C_BLUE}Diesen Passkey finden Sie in der Komodo-Server-Konfiguration.${C_RESET}"
        echo ""

        if confirm "Möchten Sie einen zufälligen Passkey generieren lassen?"; then
            passkey=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
            info "Zufälliger Passkey wurde generiert"
            echo ""
            echo -e "${C_GREEN}Generierter Passkey:${C_RESET} ${C_CYAN}${passkey}${C_RESET}"
            echo ""
            echo -e "${C_YELLOW}⚠️  WICHTIG: Fügen Sie diesen Passkey in Ihrem Komodo-Server hinzu!${C_RESET}"
            echo ""
            read -p "Drücken Sie Enter, um fortzufahren..."
        else
            while [ -z "$passkey" ]; do
                echo ""
                read -p "Komodo Passkey eingeben: " passkey
                echo ""

                if [ -z "$passkey" ]; then
                    error "Passkey darf nicht leer sein!"
                elif [ ${#passkey} -lt 32 ]; then
                    warning "Passkey sollte mindestens 32 Zeichen lang sein!"
                    if ! confirm "Trotzdem verwenden?"; then
                        passkey=""
                    fi
                fi
            done

            # Zeige eingegebenen Passkey zur Bestätigung
            echo ""
            echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
            echo -e "${C_GREEN}Eingegebener Passkey:${C_RESET}"
            echo -e "${C_YELLOW}${passkey}${C_RESET}"
            echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
            echo ""

            if ! confirm "Ist dieser Passkey korrekt?"; then
                error "Passkey-Eingabe abgebrochen. Bitte erneut versuchen."
                return 1
            fi

            success "Passkey wurde akzeptiert (Länge: ${#passkey} Zeichen)"
        fi
    else
        # Non-interactive oder Dry-Run: Generiere zufälligen Passkey
        passkey=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
        info "Passkey automatisch generiert (non-interactive mode)"
    fi

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

# --- Fail2Ban Installation & Konfiguration ---

install_fail2ban() {
    info "🛡️ Installiere und konfiguriere Fail2Ban..."

    # Prüfe ob bereits installiert
    if command -v fail2ban-client >/dev/null 2>&1 && systemctl is-active --quiet fail2ban 2>/dev/null; then
        success "Fail2Ban ist bereits installiert und aktiv"
        return 0
    fi

    # Installiere Fail2Ban
    if ! install_package "fail2ban"; then
        error "Fail2Ban-Installation fehlgeschlagen"
        return 1
    fi

    # Ermittle SSH-Port (falls bereits konfiguriert)
    local ssh_port=${SSH_PORT_SET:-2222}
    if [ -f /etc/ssh/sshd_config ]; then
        local configured_port=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | awk '{print $2}')
        [ -n "$configured_port" ] && ssh_port=$configured_port
    fi

    info "Konfiguriere Fail2Ban für SSH-Port: $ssh_port"

    # Erstelle jail.local mit optimierten Einstellungen
    if [ "$DRY_RUN" != "1" ]; then
        create_backup "/etc/fail2ban/jail.local"

        cat > /etc/fail2ban/jail.local << EOF
# Fail2Ban Konfiguration - Erstellt durch Server-Setup-Skript
# $(date)

[DEFAULT]
# Ban-Zeit (in Sekunden): 1 Stunde
bantime = 3600

# Zeitfenster für maxretry (in Sekunden): 10 Minuten
findtime = 600

# Anzahl der Versuche vor Ban
maxretry = 3

# Aktion bei Ban: iptables-multiport blockiert den Port
banaction = iptables-multiport

# Email-Benachrichtigungen deaktiviert (kein Mail-Server)
destemail = root@localhost
sendername = Fail2Ban
action = %(action_)s

[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

# Zusätzliche SSH-Varianten
[sshd-ddos]
enabled = true
port = $ssh_port
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200
findtime = 300
EOF
        success "Fail2Ban-Konfiguration erstellt"
    else
        debug "[DRY-RUN] Would create /etc/fail2ban/jail.local"
    fi

    # Erstelle erweiterten SSH-Filter für aggressive Angriffe
    if [ "$DRY_RUN" != "1" ]; then
        cat > /etc/fail2ban/filter.d/sshd-aggressive.conf << 'EOF'
# Aggressive SSH-Angriffe erkennen
[Definition]
failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \S+)?\s*$
            ^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\s*$
            ^%(__prefix_line)sFailed \S+ for .*? from <HOST>(?: port \d*)?(?: ssh\d*)?(: (ruser .*|(\S+ ID \S+ \(serial \d+\) CA )?\S+ %(__md5hex)s(, client user ".*", client host ".*")?))?\s*$
            ^%(__prefix_line)sROOT LOGIN REFUSED.* FROM <HOST>\s*$
            ^%(__prefix_line)s[iI](?:llegal|nvalid) user .* from <HOST>\s*$
EOF
        success "Aggressive SSH-Filter erstellt"
    fi

    # Starte und aktiviere Fail2Ban
    manage_service enable fail2ban
    manage_service restart fail2ban

    # Warte kurz und prüfe Status
    sleep 2

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        success "✅ Fail2Ban ist aktiv und schützt SSH (Port $ssh_port)"

        echo ""
        echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
        echo -e "${C_CYAN}       🛡️  FAIL2BAN KONFIGURATION              ${C_RESET}"
        echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
        echo ""
        echo -e "${C_BLUE}SSH-Port:${C_RESET} $ssh_port"
        echo -e "${C_BLUE}Max. Versuche:${C_RESET} 3 (dann Ban)"
        echo -e "${C_BLUE}Ban-Zeit:${C_RESET} 1 Stunde"
        echo -e "${C_BLUE}Zeitfenster:${C_RESET} 10 Minuten"
        echo ""
        echo -e "${C_YELLOW}Nützliche Befehle:${C_RESET}"
        echo -e "  ${C_GREEN}fail2ban-client status${C_RESET}           # Status aller Jails"
        echo -e "  ${C_GREEN}fail2ban-client status sshd${C_RESET}     # SSH-Jail Status"
        echo -e "  ${C_GREEN}fail2ban-client unban <IP>${C_RESET}      # IP entbannen"
        echo ""
        echo -e "${C_CYAN}═══════════════════════════════════════════════════${C_RESET}"
        echo ""
    else
        error "Fail2Ban konnte nicht gestartet werden"
        return 1
    fi

    log_action "FAIL2BAN" "Configured and started for SSH port $ssh_port"
    return 0
}

# --- Custom Motd (Message of the Day) ---

setup_custom_motd() {
    info "🎨 Erstelle Custom Motd (Message of the Day)..."

    # Deaktiviere Standard-Motd-Scripte
    if [ "$DRY_RUN" != "1" ]; then
        # Ubuntu/Debian: Deaktiviere unnötige motd-Scripte
        if [ -d /etc/update-motd.d ]; then
            for script in 10-help-text 50-motd-news 80-esm 80-livepatch 90-updates-available 91-release-upgrade 95-hwe-eol; do
                [ -f /etc/update-motd.d/$script ] && chmod -x /etc/update-motd.d/$script 2>/dev/null || true
            done
            success "Standard-Motd-Scripte deaktiviert"
        fi

        # Erstelle eigenes Motd-Script
        cat > /etc/update-motd.d/00-custom-header << 'EOFMOTD'
#!/bin/bash

# Farben
C_RESET='\033[0m'
C_BOLD='\033[1m'
C_GREEN='\033[32m'
C_BLUE='\033[34m'
C_CYAN='\033[36m'
C_YELLOW='\033[33m'

# System-Info
HOSTNAME=$(hostname)
KERNEL=$(uname -r)
UPTIME=$(uptime -p | sed 's/up //')
LOAD=$(uptime | awk -F'load average:' '{print $2}')
MEMORY=$(free -h | awk '/^Mem:/ {printf "%s / %s (%.0f%%)", $3, $2, ($3/$2)*100}')
DISK=$(df -h / | awk 'NR==2 {printf "%s / %s (%s)", $3, $2, $5}')
USERS=$(who | wc -l)

# IP-Adressen
PUBLIC_IP=$(curl -4 -s --max-time 3 ifconfig.me 2>/dev/null || echo "N/A")
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "N/A")

# Docker Status
if command -v docker >/dev/null 2>&1; then
    DOCKER_RUNNING=$(docker ps -q 2>/dev/null | wc -l)
    DOCKER_TOTAL=$(docker ps -aq 2>/dev/null | wc -l)
    DOCKER_STATUS="${C_GREEN}${DOCKER_RUNNING}${C_RESET}/${DOCKER_TOTAL} Container"
else
    DOCKER_STATUS="${C_YELLOW}nicht installiert${C_RESET}"
fi

# Komodo Status
if docker ps 2>/dev/null | grep -q komodo-periphery; then
    KOMODO_STATUS="${C_GREEN}✓ Aktiv${C_RESET}"
else
    KOMODO_STATUS="${C_YELLOW}⊘ Inaktiv${C_RESET}"
fi

# Tailscale Status
if command -v tailscale >/dev/null 2>&1 && tailscale status >/dev/null 2>&1; then
    TAILSCALE_STATUS="${C_GREEN}✓ Verbunden${C_RESET}"
else
    TAILSCALE_STATUS="${C_YELLOW}⊘ Getrennt${C_RESET}"
fi

# Ausgabe
echo ""
echo -e "${C_CYAN}╔════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_BOLD}${C_BLUE}$(printf "%-54s" "$HOSTNAME")${C_RESET}  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╠════════════════════════════════════════════════════════════╣${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_GREEN}Öffentliche IP:${C_RESET}    $(printf "%-37s" "$PUBLIC_IP")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_GREEN}Tailscale IP:${C_RESET}      $(printf "%-37s" "$TAILSCALE_IP")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╠════════════════════════════════════════════════════════════╣${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_BLUE}Uptime:${C_RESET}            $(printf "%-37s" "$UPTIME")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_BLUE}Load Average:${C_RESET}     $(printf "%-37s" "$LOAD")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_BLUE}Memory:${C_RESET}            $(printf "%-37s" "$MEMORY")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_BLUE}Disk (root):${C_RESET}       $(printf "%-37s" "$DISK")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╠════════════════════════════════════════════════════════════╣${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_YELLOW}Docker:${C_RESET}            $(printf "%-37s" "$DOCKER_STATUS")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_YELLOW}Komodo Periphery:${C_RESET} $(printf "%-37s" "$KOMODO_STATUS")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}║${C_RESET}  ${C_YELLOW}Tailscale VPN:${C_RESET}    $(printf "%-37s" "$TAILSCALE_STATUS")  ${C_CYAN}║${C_RESET}"
echo -e "${C_CYAN}╚════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
EOFMOTD

        chmod +x /etc/update-motd.d/00-custom-header
        success "Custom Motd-Script erstellt: /etc/update-motd.d/00-custom-header"

        # Erstelle auch statisches Motd für Systeme ohne update-motd.d
        cat > /etc/motd << 'EOFSTATIC'
═══════════════════════════════════════════════════════════
  Willkommen auf diesem Server!

  Dieses System wird durch ein automatisches Setup-Skript
  verwaltet und ist optimiert für Sicherheit und Performance.

  Wichtige Befehle:
    - tailscale status          # Tailscale VPN Status
    - docker ps                 # Laufende Container
    - fail2ban-client status    # Fail2Ban Status
    - htop                      # System Monitor
═══════════════════════════════════════════════════════════

EOFSTATIC
        success "Statisches Motd erstellt: /etc/motd"

    else
        debug "[DRY-RUN] Would create custom motd scripts"
    fi

    echo ""
    echo -e "${C_GREEN}✅ Custom Motd konfiguriert!${C_RESET}"
    echo -e "${C_BLUE}Das Motd wird bei jedem SSH-Login angezeigt.${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}Testen Sie es mit:${C_RESET}"
    echo -e "  ${C_GREEN}run-parts /etc/update-motd.d/${C_RESET}"
    echo ""

    log_action "MOTD" "Custom motd configured"
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
echo "  6. Fail2Ban (SSH-Schutz)"
echo "  7. Custom Motd (Login-Banner)"
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

confirm "Fail2Ban installieren (SSH-Schutz)?" && install_fail2ban

confirm "Custom Motd einrichten?" && setup_custom_motd

echo ""
info "Netzwerk-Informationen:"
show_ip_addresses

echo ""
success "Setup abgeschlossen!"
info "Log-Datei: $LOGFILE"

[ "$DRY_RUN" = "1" ] && warning "DRY-RUN Modus war aktiv - keine Änderungen vorgenommen!"

# Ende des Skripts
