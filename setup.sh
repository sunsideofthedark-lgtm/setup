#!/bin/bash

# ==============================================================================
# Universelles Server-Setup-Skript für Linux-Distributionen (Version 2.1)
# ==============================================================================
# Dieses Skript führt den Administrator durch die grundlegenden Schritte zur
# Absicherung eines neuen Servers. Jeder kritische Schritt erfordert eine
# explizite Bestätigung.
#
# Hinzugefügte Features v2.1:
# - Menü für optionale Software erlaubt nun die Auswahl mehrerer Pakete nacheinander.
# - Zusätzliche optionale Software: NGINX, Prometheus Node Exporter, ncdu, tmux, DB-Clients.
#
# Hinzugefügte Features v2.0:
# - MTU-Konfiguration für Docker, um Netzwerkprobleme in VPN/Overlay-Umgebungen zu vermeiden.
# - IPv6-Unterstützung für Firewall und Docker-Netzwerke.
# - Netzwerkname von 'newt-talk' auf 'newt_talk' (Standardkonvention) geändert.
#
# Unterstützte Distributionen: Ubuntu, Debian, CentOS, RHEL, Fedora, SUSE, Arch
# Ausführung: sudo bash ./setup_server.sh
# Debug-Modus: DEBUG=1 sudo bash ./setup_server.sh
# ==============================================================================

# --- OS-Erkennung und Kompatibilität ---

# Betriebssystem und Distribution erkennen
detect_os() {
    info "Erkenne Betriebssystem..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID="$ID"
        OS_VERSION="$VERSION_ID"
        OS_NAME="$PRETTY_NAME"
        debug "OS erkannt über /etc/os-release: $OS_NAME"
    elif [ -f /etc/redhat-release ]; then
        OS_ID="rhel"
        OS_NAME=$(cat /etc/redhat-release)
        debug "OS erkannt über /etc/redhat-release: $OS_NAME"
    elif [ -f /etc/debian_version ]; then
        OS_ID="debian"
        OS_NAME="Debian $(cat /etc/debian_version)"
        debug "OS erkannt über /etc/debian_version: $OS_NAME"
    else
        error "Betriebssystem konnte nicht erkannt werden"
        log_action "FATAL" "OS detection failed"
        exit 1
    fi
    
    # Paketmanager bestimmen
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
            PKG_MANAGER="yum"
            # Für neuere Versionen dnf verwenden
            if command -v dnf >/dev/null 2>&1; then
                PKG_MANAGER="dnf"
                PKG_UPDATE="dnf check-update || true"
                PKG_UPGRADE="dnf upgrade -y"
                PKG_INSTALL="dnf install -y"
                PKG_AUTOREMOVE="dnf autoremove -y"
            else
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
            FIREWALL_CMD="ufw"  # Arch kann ufw installieren
            SSH_CONFIG="/etc/ssh/sshd_config"
            SSH_SERVICE="sshd"
            ;;
        *)
            echo "[ERROR] Nicht unterstützte Distribution: $OS_ID"
            echo "[INFO] Unterstützte Distributionen: Ubuntu, Debian, CentOS, RHEL, Fedora, openSUSE, Arch Linux"
            exit 1
            ;;
    esac
    
    debug "Paketmanager: $PKG_MANAGER"
    debug "Service-Manager: $SERVICE_MANAGER"
    debug "Firewall: $FIREWALL_CMD"
    debug "SSH-Service: $SSH_SERVICE"
}

# Firewall-Funktionen je nach System
setup_firewall() {
    local ssh_port=$1
    
    case "$FIREWALL_CMD" in
        ufw)
            echo "[INFO] Konfiguriere UFW-Firewall"
            # IPv6-Unterstützung in UFW aktivieren
            if [ -f /etc/default/ufw ]; then
                sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
                info "IPv6-Unterstützung in UFW aktiviert."
            fi
            ufw default deny incoming
            ufw default allow outgoing
            ufw allow $ssh_port/tcp
            ufw deny 22/tcp
            ufw allow 80/tcp
            ufw allow 443/tcp
            ufw allow 51820/udp  # Pangolin VPN
            ufw allow 21820/udp  # Pangolin zusätzlich
            ufw allow 8120/tcp   # Komodo
            echo "y" | ufw enable
            ;;
        firewall-cmd)
            echo "[INFO] Konfiguriere firewalld (Regeln gelten für IPv4 & IPv6)"
            systemctl enable firewalld
            systemctl start firewalld
            firewall-cmd --permanent --remove-service=ssh  # Standard SSH entfernen
            firewall-cmd --permanent --add-port=$ssh_port/tcp
            firewall-cmd --permanent --add-service=http
            firewall-cmd --permanent --add-service=https
            firewall-cmd --permanent --add-port=51820/udp  # Pangolin VPN
            firewall-cmd --permanent --add-port=21820/udp  # Pangolin zusätzlich
            firewall-cmd --permanent --add-port=8120/tcp   # Komodo
            firewall-cmd --reload
            ;;
        *)
            echo "[WARNING] Unbekannte Firewall: $FIREWALL_CMD"
            return 1
            ;;
    esac
}

# Service-Management-Funktionen
manage_service() {
    local action=$1
    local service=$2
    
    case "$SERVICE_MANAGER" in
        systemctl)
            systemctl $action $service
            ;;
        service)
            service $service $action
            ;;
        *)
            echo "[ERROR] Unbekannter Service-Manager: $SERVICE_MANAGER"
            return 1
            ;;
    esac
}

# Prüft ob ein Software-Paket bereits installiert ist
is_package_installed() {
    local package="$1"
    local alternative_check="$2"  # Alternative Prüfmethode (z.B. command name)
    
    debug "Prüfe Installation von: $package"
    
    # Zuerst mit Paketmanager prüfen
    case "$PKG_MANAGER" in
        apt)
            if dpkg -l | grep -q "^ii.*$package "; then
                return 0
            fi
            ;;
        yum|dnf)
            if $PKG_MANAGER list installed "$package" >/dev/null 2>&1; then
                return 0
            fi
            ;;
        zypper)
            if zypper se -i "$package" | grep -q "^i "; then
                return 0
            fi
            ;;
        pacman)
            if pacman -Q "$package" >/dev/null 2>&1; then
                return 0
            fi
            ;;
    esac
    
    # Alternative Prüfung (z.B. command verfügbar)
    if [ -n "$alternative_check" ] && command -v "$alternative_check" >/dev/null 2>&1; then
        return 0
    fi
    
    return 1
}

# Paket-Installation mit OS-spezifischen Besonderheiten und Validierung
install_package() {
    local package="$1"
    local alt_package="$2"  # Alternative für verschiedene Distributionen
    local max_retries=3
    local retry_count=0
    
    debug "Installiere Paket: $package"
    log_action "INSTALL" "Starting installation of package: $package"
    
    while [ $retry_count -lt $max_retries ]; do
        case "$OS_ID" in
            ubuntu|debian)
                if eval "$PKG_INSTALL $package"; then
                    log_action "INSTALL" "Successfully installed: $package"
                    return 0
                fi
                ;;
            centos|rhel|rocky|almalinux)
                # Einige Pakete haben andere Namen in RHEL/CentOS
                case "$package" in
                    ufw)
                        warning "UFW ist nicht verfügbar. Verwende firewalld."
                        if eval "$PKG_INSTALL firewalld"; then
                            log_action "INSTALL" "Successfully installed: firewalld (instead of ufw)"
                            return 0
                        fi
                        ;;
                    unattended-upgrades)
                        if eval "$PKG_INSTALL yum-cron"; then
                            log_action "INSTALL" "Successfully installed: yum-cron (instead of unattended-upgrades)"
                            return 0
                        fi
                        ;;
                    *)
                        if eval "$PKG_INSTALL ${alt_package:-$package}"; then
                            log_action "INSTALL" "Successfully installed: ${alt_package:-$package}"
                            return 0
                        fi
                        ;;
                esac
                ;;
            fedora)
                case "$package" in
                    unattended-upgrades)
                        if eval "$PKG_INSTALL dnf-automatic"; then
                            log_action "INSTALL" "Successfully installed: dnf-automatic (instead of unattended-upgrades)"
                            return 0
                        fi
                        ;;
                    *)
                        if eval "$PKG_INSTALL ${alt_package:-$package}"; then
                            log_action "INSTALL" "Successfully installed: ${alt_package:-$package}"
                            return 0
                        fi
                        ;;
                esac
                ;;
            opensuse*|sles)
                case "$package" in
                    ufw)
                        warning "UFW ist nicht verfügbar. Verwende firewalld."
                        if eval "$PKG_INSTALL firewalld"; then
                            log_action "INSTALL" "Successfully installed: firewalld (instead of ufw)"
                            return 0
                        fi
                        ;;
                    unattended-upgrades)
                        if eval "$PKG_INSTALL yast2-online-update-configuration"; then
                            log_action "INSTALL" "Successfully installed: yast2-online-update-configuration (instead of unattended-upgrades)"
                            return 0
                        fi
                        ;;
                    *)
                        if eval "$PKG_INSTALL ${alt_package:-$package}"; then
                            log_action "INSTALL" "Successfully installed: ${alt_package:-$package}"
                            return 0
                        fi
                        ;;
                esac
                ;;
            arch)
                case "$package" in
                    unattended-upgrades)
                        warning "Automatische Updates nicht verfügbar in Arch. Überspringe."
                        return 0
                        ;;
                    *)
                        if eval "$PKG_INSTALL ${alt_package:-$package}"; then
                            log_action "INSTALL" "Successfully installed: ${alt_package:-$package}"
                            return 0
                        fi
                        ;;
                esac
                ;;
        esac
        
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            warning "Installation fehlgeschlagen. Versuche erneut ($retry_count/$max_retries)..."
            sleep 2
        fi
    done
    
    log_action "ERROR" "Failed to install package after $max_retries attempts: $package"
    return 1
}

# Erweiterte automatische Updates konfigurieren
configure_auto_updates() {
    debug "Konfiguriere automatische Updates für $OS_ID"
    log_action "AUTOUPDATE" "Configuring automatic updates for $OS_ID"
    
    case "$OS_ID" in
        ubuntu|debian)
            info "Installiere und konfiguriere unattended-upgrades..."
            
            if ! install_package "unattended-upgrades"; then
                error "Installation von unattended-upgrades fehlgeschlagen"
                return 1
            fi
            
            # Backup der bestehenden Konfiguration
            create_backup "/etc/apt/apt.conf.d/20auto-upgrades"
            
            # Erweiterte Konfiguration für automatische Updates
            debug "Erstelle erweiterte unattended-upgrades Konfiguration"
            cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
// Automatische Updates - Konfiguriert durch Server-Setup-Skript
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
            
            # Unattended-Upgrades Hauptkonfiguration anpassen
            if [ -f /etc/apt/apt.conf.d/50unattended-upgrades ]; then
                create_backup "/etc/apt/apt.conf.d/50unattended-upgrades"
                
                # Sicherheitsupdates aktivieren und Reboot-Handling konfigurieren
                debug "Konfiguriere unattended-upgrades Optionen"
                sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "false";|g' /etc/apt/apt.conf.d/50unattended-upgrades
                sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies "false";|Unattended-Upgrade::Remove-Unused-Dependencies "true";|g' /etc/apt/apt.conf.d/50unattended-upgrades
                
                # Mail-Benachrichtigungen deaktivieren (da kein Mail-Server)
                sed -i 's|//Unattended-Upgrade::Mail "";|//Unattended-Upgrade::Mail "";|g' /etc/apt/apt.conf.d/50unattended-upgrades
            fi
            
            # Service aktivieren
            systemctl enable unattended-upgrades
            systemctl start unattended-upgrades
            ;;
            
        centos|rhel|rocky|almalinux)
            info "Installiere und konfiguriere yum-cron..."
            
            if ! install_package "yum-cron"; then
                error "Installation von yum-cron fehlgeschlagen"
                return 1
            fi
            
            # yum-cron Konfiguration für automatische Sicherheitsupdates
            if [ -f /etc/yum/yum-cron.conf ]; then
                create_backup "/etc/yum/yum-cron.conf"
                
                debug "Konfiguriere yum-cron für automatische Sicherheitsupdates"
                sed -i 's|update_cmd = default|update_cmd = security|g' /etc/yum/yum-cron.conf
                sed -i 's|apply_updates = no|apply_updates = yes|g' /etc/yum/yum-cron.conf
                sed -i 's|emit_via = stdio|emit_via = stdio|g' /etc/yum/yum-cron.conf
            fi
            
            systemctl enable yum-cron
            systemctl start yum-cron
            ;;
            
        fedora)
            info "Installiere und konfiguriere dnf-automatic..."
            
            if ! install_package "dnf-automatic"; then
                error "Installation von dnf-automatic fehlgeschlagen"
                return 1
            fi
            
            # dnf-automatic Konfiguration
            if [ -f /etc/dnf/automatic.conf ]; then
                create_backup "/etc/dnf/automatic.conf"
                
                debug "Konfiguriere dnf-automatic für Sicherheitsupdates"
                sed -i 's|upgrade_type = default|upgrade_type = security|g' /etc/dnf/automatic.conf
                sed -i 's|apply_updates = no|apply_updates = yes|g' /etc/dnf/automatic.conf
            fi
            
            systemctl enable dnf-automatic.timer
            systemctl start dnf-automatic.timer
            ;;
            
        opensuse*|sles)
            info "Konfiguriere SUSE automatische Updates..."
            
            if ! install_package "yast2-online-update-configuration"; then
                warning "YaST Online-Update-Konfiguration nicht verfügbar"
            fi
            
            # Zypper auto-update konfigurieren
            debug "Konfiguriere zypper für automatische Updates"
            if command -v zypper >/dev/null 2>&1; then
                # Automatic refresh aktivieren
                zypper modifyrepo --refresh --all 2>/dev/null || true
            fi
            ;;
            
        arch)
            warning "Arch Linux: Automatische Updates werden nicht empfohlen"
            info "Grund: Rolling Release kann Breaking Changes enthalten"
            info "Empfehlung: Manuelle Updates mit 'pacman -Syu'"
            return 0
            ;;
            
        *)
            error "Automatische Updates für $OS_ID nicht implementiert"
            return 1
            ;;
    esac
    
    log_action "AUTOUPDATE" "Automatic updates configured successfully for $OS_ID"
    return 0
}

# Status der automatischen Updates überprüfen
check_auto_updates_status() {
    debug "Überprüfe Status der automatischen Updates"
    
    case "$OS_ID" in
        ubuntu|debian)
            if systemctl is-active --quiet unattended-upgrades; then
                info "✅ unattended-upgrades Service: Aktiv"
            else
                warning "⚠️  unattended-upgrades Service: Inaktiv"
            fi
            
            if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
                info "✅ Update-Konfiguration: Vorhanden"
            else
                warning "⚠️  Update-Konfiguration: Fehlt"
            fi
            ;;
            
        centos|rhel|rocky|almalinux)
            if systemctl is-active --quiet yum-cron || systemctl is-active --quiet crond; then
                info "✅ yum-cron Service: Aktiv"
            else
                warning "⚠️  yum-cron Service: Inaktiv"
            fi
            ;;
            
        fedora)
            if systemctl is-active --quiet dnf-automatic.timer; then
                info "✅ dnf-automatic Timer: Aktiv"
            else
                warning "⚠️  dnf-automatic Timer: Inaktiv"
            fi
            ;;
            
        opensuse*|sles)
            info "📋 SUSE Updates: Manuell überprüfen mit 'zypper lu'"
            ;;
            
        arch)
            info "📋 Arch Linux: Manuelle Updates empfohlen"
            ;;
    esac
}

# --- Modul-Status-Erkennung ---

# Status eines Moduls überprüfen
check_module_status() {
    local module="$1"
    debug "Überprüfe Status von Modul: $module"
    
    case "$module" in
        "system_update")
            # Prüfe wenn System vor kurzem aktualisiert wurde
            if [ -f /var/log/apt/history.log ] && grep -q "$(date +%Y-%m-%d)" /var/log/apt/history.log 2>/dev/null; then
                echo "completed"
            elif [ -f /var/log/yum.log ] && grep -q "$(date +%Y-%m-%d)" /var/log/yum.log 2>/dev/null; then
                echo "completed"
            elif [ -f /var/log/dnf.log ] && grep -q "$(date +%Y-%m-%d)" /var/log/dnf.log 2>/dev/null; then
                echo "completed"
            else
                echo "not-started"
            fi
            ;;
            
        "auto_updates")
            case "$OS_ID" in
                ubuntu|debian)
                    if systemctl is-active --quiet unattended-upgrades 2>/dev/null && [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
                        echo "completed"
                    elif [ -f /etc/apt/apt.conf.d/20auto-upgrades ] || systemctl is-enabled --quiet unattended-upgrades 2>/dev/null; then
                        echo "partial"
                    else
                        echo "not-started"
                    fi
                    ;;
                centos|rhel|rocky|almalinux)
                    if systemctl is-active --quiet yum-cron 2>/dev/null; then
                        echo "completed"
                    elif systemctl is-enabled --quiet yum-cron 2>/dev/null; then
                        echo "partial"
                    else
                        echo "not-started"
                    fi
                    ;;
                fedora)
                    if systemctl is-active --quiet dnf-automatic.timer 2>/dev/null; then
                        echo "completed"
                    elif systemctl is-enabled --quiet dnf-automatic.timer 2>/dev/null; then
                        echo "partial"
                    else
                        echo "not-started"
                    fi
                    ;;
                arch)
                    echo "not-applicable"
                    ;;
                *)
                    echo "not-started"
                    ;;
            esac
            ;;
            
        "hostname")
            # Prüfe ob Hostname vom Standard abweicht
            current_hostname=$(hostname)
            if [ "$current_hostname" != "localhost" ] && [ "$current_hostname" != "ubuntu" ] && [ "$current_hostname" != "debian" ] && [ "$current_hostname" != "centos" ]; then
                echo "completed"
            else
                echo "not-started"
            fi
            ;;
            
        "user_management")
            # Prüfe ob ein nicht-root User existiert mit sudo-Rechten
            if getent group sudo >/dev/null 2>&1; then
                sudo_users=$(getent group sudo | cut -d: -f4)
            elif getent group wheel >/dev/null 2>&1; then
                sudo_users=$(getent group wheel | cut -d: -f4)
            else
                sudo_users=""
            fi
            
            if [ -n "$sudo_users" ] && [ "$sudo_users" != "root" ]; then
                echo "completed"
            else
                echo "not-started"
            fi
            ;;
            
        "ssh_hardening")
            # Prüfe SSH-Konfiguration
            if [ -f /etc/ssh/sshd_config ]; then
                port22_disabled=$(grep -E "^Port\s+[0-9]+" /etc/ssh/sshd_config | grep -v "Port 22" | wc -l)
                password_auth_disabled=$(grep -E "^PasswordAuthentication\s+no" /etc/ssh/sshd_config | wc -l)
                root_login_disabled=$(grep -E "^PermitRootLogin\s+no" /etc/ssh/sshd_config | wc -l)
                
                if [ "$port22_disabled" -gt 0 ] && [ "$password_auth_disabled" -gt 0 ] && [ "$root_login_disabled" -gt 0 ]; then
                    echo "completed"
                elif [ "$port22_disabled" -gt 0 ] || [ "$password_auth_disabled" -gt 0 ] || [ "$root_login_disabled" -gt 0 ]; then
                    echo "partial"
                else
                    echo "not-started"
                fi
            else
                echo "not-started"
            fi
            ;;
            
        "firewall")
            # Prüfe Firewall-Status
            if command -v ufw >/dev/null 2>&1; then
                if ufw status | grep -q "Status: active"; then
                    echo "completed"
                else
                    echo "not-started"
                fi
            elif command -v firewall-cmd >/dev/null 2>&1; then
                if systemctl is-active --quiet firewalld 2>/dev/null; then
                    echo "completed"
                else
                    echo "not-started"
                fi
            else
                echo "not-started"
            fi
            ;;
            
        "optional_software")
            # Prüfe ob Docker installiert ist (als Hauptindikator)
            if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker 2>/dev/null; then
                echo "completed"
            elif command -v docker >/dev/null 2>&1; then
                echo "partial"
            else
                echo "not-started"
            fi
            ;;
            
        "system_maintenance")
            # Prüfe ob Logrotate konfiguriert ist und Cron aktiv
            if systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null; then
                if [ -f /etc/logrotate.d/rsyslog ] || [ -f /etc/logrotate.d/syslog ]; then
                    echo "completed"
                else
                    echo "partial"
                fi
            else
                echo "not-started"
            fi
            ;;
            
        "root_security")
            # Prüfe Root-Account-Status
            root_locked=$(passwd --status root 2>/dev/null | awk '{print $2}')
            if [ "$root_locked" = "L" ]; then
                echo "completed"
            else
                echo "not-started"
            fi
            ;;
            
        *)
            echo "unknown"
            ;;
    esac
}

# Status-Symbol für ein Modul generieren
get_module_display() {
    local module="$1"
    local title="$2"
    local status=$(check_module_status "$module")
    
    case "$status" in
        "completed")
            echo "✅ $title"
            ;;
        "partial")
            echo "⚠️  $title (teilweise konfiguriert)"
            ;;
        "not-applicable")
            echo "⏭️  $title (nicht anwendbar)"
            ;;
        "not-started")
            echo "❌ $title"
            ;;
        *)
            echo "❓ $title (unbekannter Status)"
            ;;
    esac
}

# --- Globale Variablen und Hilfsfunktionen ---

# Farben für die Ausgabe
C_RESET='\033[0m'
C_RED='\033[31m'
C_GREEN='\033[32m'
C_YELLOW='\033[33m'
C_BLUE='\033[34m'
C_MAGENTA='\033[35m'
C_CYAN='\033[36m'

# Debug-Modus und Logging aktivieren
DEBUG=${DEBUG:-0}
LOGFILE="/var/log/server-setup.log"

# Logging-Setup
setup_logging() {
    # Log-Datei erstellen mit korrekten Berechtigungen
    if [ ! -f "$LOGFILE" ]; then
        touch "$LOGFILE"
        chmod 600 "$LOGFILE"
    fi
    
    # Logging-Start
    echo "=== Server Setup gestartet am $(date) ===" >> "$LOGFILE"
    echo "Skript: $0" >> "$LOGFILE"
    echo "Benutzer: $(whoami)" >> "$LOGFILE"
    echo "OS: $(uname -a)" >> "$LOGFILE"
    echo "=========================================" >> "$LOGFILE"
}

# Einheitliche Debug-Logging-Funktion
debug() {
    local message="[DEBUG $(date '+%H:%M:%S')] $1"
    if [ "$DEBUG" = "1" ]; then
        echo -e "${C_MAGENTA}$message${C_RESET}" >&2
    fi
    echo "$message" >> "$LOGFILE" 2>/dev/null || true
}

# Erweiterte Logging-Funktion für alle Aktionen
log_action() {
    local level="$1"
    local message="$2"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" >> "$LOGFILE" 2>/dev/null || true
}

# Erweiterte Error-Handling-Funktion
error_with_debug() {
    local exit_code=$?
    local line_no=$1
    local command="$2"
    echo -e "${C_RED}[FEHLER] Zeile $line_no: Befehl fehlgeschlagen: $command${C_RESET}" >&2
    echo -e "${C_RED}[FEHLER] Exit-Code: $exit_code${C_RESET}" >&2
    if [ "$DEBUG" = "1" ]; then
        echo -e "${C_MAGENTA}[DEBUG] Aktuelle Variablen:${C_RESET}" >&2
        echo -e "${C_MAGENTA}  SSH_PORT: ${SSH_PORT:-nicht gesetzt}${C_RESET}" >&2
        echo -e "${C_MAGENTA}  NEW_USER: ${NEW_USER:-nicht gesetzt}${C_RESET}" >&2
        echo -e "${C_MAGENTA}  OS_ID: ${OS_ID:-nicht gesetzt}${C_RESET}" >&2
        echo -e "${C_MAGENTA}  PKG_MANAGER: ${PKG_MANAGER:-nicht gesetzt}${C_RESET}" >&2
        echo -e "${C_MAGENTA}  PWD: $(pwd)${C_RESET}" >&2
    fi
}

# Error-Trap für automatisches Debug-Logging
trap 'error_with_debug $LINENO "$BASH_COMMAND"' ERR

# Erweiterte Ausgabefunktionen mit Logging
info() {
    echo -e "${C_BLUE}[INFO] $1${C_RESET}"
    log_action "INFO" "$1"
    debug "INFO: $1"
}

success() {
    echo -e "${C_GREEN}[SUCCESS] $1${C_RESET}"
    log_action "SUCCESS" "$1"
    debug "SUCCESS: $1"
}

warning() {
    echo -e "${C_YELLOW}[WARNING] $1${C_RESET}"
    log_action "WARNING" "$1"
    debug "WARNING: $1"
}

error() {
    echo -e "${C_RED}[ERROR] $1${C_RESET}" >&2
    log_action "ERROR" "$1"
    debug "ERROR: $1"
}

# Bestätigungsfunktion
confirm() {
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

# Backup-Funktion für kritische Dateien
create_backup() {
    local file="$1"
    local backup_dir="/var/backups/server-setup"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    
    if [ -f "$file" ]; then
        mkdir -p "$backup_dir"
        cp "$file" "$backup_dir/$(basename $file).backup.$timestamp"
        log_action "BACKUP" "Created backup of $file"
        debug "Backup erstellt: $backup_dir/$(basename $file).backup.$timestamp"
    fi
}

# Validierungsfunktionen
validate_hostname() {
    local hostname="$1"
    
    # RFC 1123 Hostname-Validierung
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        return 1
    fi
    
    # Länge prüfen (max 63 Zeichen)
    if [ ${#hostname} -gt 63 ]; then
        return 1
    fi
    
    return 0
}

validate_username() {
    local username="$1"
    
    # POSIX Benutzername-Validierung
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        return 1
    fi
    
    # Länge prüfen (max 32 Zeichen)
    if [ ${#username} -gt 32 ]; then
        return 1
    fi
    
    # Reservierte Namen prüfen
    local reserved_names="root daemon bin sys sync games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve messagebus systemd-timesync syslog"
    for reserved in $reserved_names; do
        if [ "$username" = "$reserved" ]; then
            return 1
        fi
    done
    
    return 0
}

validate_port() {
    local port="$1"
    
    # Numerische Validierung
    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi
    
    # Port-Bereich validieren
    if [ "$port" -lt 1024 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi
    
    # Bekannte problematische Ports vermeiden
    local reserved_ports="1080 3128 8080 8888 9050 9051"
    for reserved_port in $reserved_ports; do
        if [ "$port" = "$reserved_port" ]; then
            return 1
        fi
    done
    
    return 0
}

# Netzwerk-Konnektivität prüfen
check_network() {
    debug "Prüfe Netzwerk-Konnektivität"
    
    if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
        warning "Keine Internet-Verbindung erkannt. Einige Features könnten nicht funktionieren."
        return 1
    fi
    
    return 0
}

# --- Skript-Start ---

# Logging initialisieren
setup_logging

# OS-Erkennung durchführen
detect_os

# Debug-Info ausgeben
if [ "$DEBUG" = "1" ]; then
    debug "Debug-Modus aktiviert"
    debug "Skript-Pfad: $0"
    debug "Argumente: $@"
    debug "Aktueller Benutzer: $(whoami)"
    debug "Aktuelle Zeit: $(date)"
    debug "Erkanntes OS: $OS_NAME"
fi

# Überprüfen, ob das Skript als root ausgeführt wird
if [ "$(id -u)" -ne 0 ]; then
    error "Dieses Skript muss mit root-Rechten (sudo) ausgeführt werden."
    debug "Aktueller Benutzer hat UID: $(id -u)"
    exit 1
fi

# Netzwerk-Konnektivität prüfen
check_network

clear
echo -e "${C_BLUE}=====================================================${C_RESET}"
echo -e "${C_BLUE}  Universelles Linux Server-Setup-Skript${C_RESET}"
echo -e "${C_BLUE}=====================================================${C_RESET}"
echo ""
info "Erkanntes System: $OS_NAME"
info "Paketmanager: $PKG_MANAGER"
info "Firewall: $FIREWALL_CMD"
echo ""
info "Dieses Skript wird Sie durch die Ersteinrichtung und Härtung Ihres Servers führen."
if [ "$DEBUG" = "1" ]; then
    warning "DEBUG-MODUS AKTIVIERT - Ausführliche Protokollierung ist eingeschaltet"
fi
echo ""

# --- Modulares Setup-Menü ---

# Setup-Module definieren
declare -A SETUP_MODULES
SETUP_MODULES["system_update"]="Systemaktualisierung"
SETUP_MODULES["auto_updates"]="Automatische Updates"
SETUP_MODULES["hostname"]="Hostname konfigurieren"
SETUP_MODULES["user_management"]="Benutzerverwaltung"
SETUP_MODULES["ssh_hardening"]="SSH-Härtung"
SETUP_MODULES["firewall"]="Firewall-Konfiguration"
SETUP_MODULES["optional_software"]="Optionale Software"
SETUP_MODULES["system_maintenance"]="System-Wartung & Optimierung"
SETUP_MODULES["root_security"]="Root-Benutzer sichern"

# Ausgewählte Module speichern
declare -A SELECTED_MODULES

show_setup_menu() {
    clear
    echo -e "${C_CYAN}=====================================================${C_RESET}"
    echo -e "${C_CYAN}  Setup-Module auswählen${C_RESET}"
    echo -e "${C_CYAN}=====================================================${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}Verfügbare Setup-Module:${C_RESET}"
    echo ""
    
    local counter=1
    local module_keys=()
    
    for key in system_update auto_updates hostname user_management ssh_hardening firewall optional_software system_maintenance root_security; do
        module_keys+=("$key")
        local selection_status=""
        local module_display=""
        
        # Auswahl-Status (ob Modul für Ausführung gewählt ist)
        if [[ "${SELECTED_MODULES[$key]}" == "1" ]]; then
            selection_status="${C_GREEN}[✓]${C_RESET}"
        else
            selection_status="${C_RED}[ ]${C_RESET}"
        fi
        
        # Modul-Status mit Display-Text (ob bereits konfiguriert)
        module_display=$(get_module_display "$key" "${SETUP_MODULES[$key]}")
        
        printf "    %s %2d. %s\n" "$selection_status" "$counter" "$module_display"
        ((counter++))
    done
    
    echo ""
    echo -e "${C_MAGENTA}Status-Legende:${C_RESET}"
    echo "    ✅ = Bereits konfiguriert    ⚠️  = Teilweise konfiguriert    ❌ = Nicht konfiguriert"
    echo "    ⏭️  = Nicht anwendbar       ❓ = Unbekannter Status"
    echo ""
    echo -e "${C_BLUE}Optionen:${C_RESET}"
    echo "    a  - Alle Module auswählen"
    echo "    n  - Alle Module abwählen"
    echo "    s  - Setup mit ausgewählten Modulen starten"
    echo "    q  - Beenden"
    echo ""
    echo -e "${C_CYAN}Geben Sie die Nummer(n) der gewünschten Module ein (z.B. 1,3,5):${C_RESET}"
}

select_modules() {
    local module_keys=(system_update auto_updates hostname user_management ssh_hardening firewall optional_software system_maintenance root_security)
    
    while true; do
        show_setup_menu
        read -r choice
        debug "Modulauswahl: '$choice'"
        
        case "$choice" in
            [1-9])
                local key="${module_keys[$((choice-1))]}"
                if [[ "${SELECTED_MODULES[$key]}" == "1" ]]; then
                    SELECTED_MODULES[$key]="0"
                    info "Modul '${SETUP_MODULES[$key]}' abgewählt"
                else
                    SELECTED_MODULES[$key]="1"
                    info "Modul '${SETUP_MODULES[$key]}' ausgewählt"
                fi
                sleep 1
                ;;
            *,*)
                # Mehrere Module gleichzeitig auswählen
                IFS=',' read -ra NUMS <<< "$choice"
                for num in "${NUMS[@]}"; do
                    if [[ "$num" =~ ^[1-9]$ ]]; then
                        local key="${module_keys[$((num-1))]}"
                        SELECTED_MODULES[$key]="1"
                        info "Modul '${SETUP_MODULES[$key]}' ausgewählt"
                    fi
                done
                sleep 2
                ;;
            a|A)
                for key in "${module_keys[@]}"; do
                    SELECTED_MODULES[$key]="1"
                done
                success "Alle Module ausgewählt"
                sleep 1
                ;;
            n|N)
                for key in "${module_keys[@]}"; do
                    SELECTED_MODULES[$key]="0"
                done
                warning "Alle Module abgewählt"
                sleep 1
                ;;
            s|S)
                local selected_count=0
                local already_configured=()
                local needs_configuration=()
                
                # Analysiere ausgewählte Module
                for key in "${module_keys[@]}"; do
                    if [[ "${SELECTED_MODULES[$key]}" == "1" ]]; then
                        ((selected_count++))
                        local status=$(check_module_status "$key")
                        if [ "$status" = "completed" ]; then
                            already_configured+=("$key")
                        else
                            needs_configuration+=("$key")
                        fi
                    fi
                done
                
                if [ $selected_count -eq 0 ]; then
                    error "Mindestens ein Modul muss ausgewählt werden!"
                    sleep 2
                    continue
                fi
                
                # Warnung für bereits konfigurierte Module
                if [ ${#already_configured[@]} -gt 0 ]; then
                    echo ""
                    echo -e "${C_YELLOW}⚠️  ACHTUNG: Folgende Module sind bereits konfiguriert:${C_RESET}"
                    for key in "${already_configured[@]}"; do
                        echo -e "    ${C_GREEN}✅${C_RESET} ${SETUP_MODULES[$key]}"
                    done
                    echo ""
                    echo -e "${C_CYAN}Möchten Sie diese Module trotzdem erneut ausführen?${C_RESET}"
                    echo "    y/j - Ja, alle erneut ausführen"
                    echo "    n   - Nein, nur neue Module ausführen"
                    echo "    c   - Zurück zur Modulauswahl"
                    echo ""
                    read -p "Ihre Wahl [y/n/c]: " confirm_choice
                    
                    case "$confirm_choice" in
                        n|N)
                            # Nur neue Module ausführen
                            for key in "${already_configured[@]}"; do
                                SELECTED_MODULES[$key]="0"
                                info "Modul '${SETUP_MODULES[$key]}' übersprungen (bereits konfiguriert)"
                            done
                            selected_count=${#needs_configuration[@]}
                            if [ $selected_count -eq 0 ]; then
                                warning "Alle ausgewählten Module sind bereits konfiguriert!"
                                sleep 2
                                continue
                            fi
                            ;;
                        c|C)
                            # Zurück zur Auswahl
                            continue
                            ;;
                        y|j|Y|J)
                            # Alle ausführen (nichts ändern)
                            warning "Bereits konfigurierte Module werden erneut ausgeführt"
                            ;;
                        *)
                            error "Ungültige Eingabe. Zurück zur Modulauswahl."
                            sleep 2
                            continue
                            ;;
                    esac
                fi
                
                success "$selected_count Module(e) für Setup ausgewählt"
                sleep 1
                break
                ;;
            q|Q)
                warning "Setup abgebrochen"
                exit 0
                ;;
            *)
                error "Ungültige Eingabe: '$choice'"
                sleep 1
                ;;
        esac
    done
}

# === HAUPTSKRIPT STARTET HIER ===

# Modulares Setup-Menü anzeigen
echo -e "${C_YELLOW}Möchten Sie das komplette Setup ausführen oder einzelne Module auswählen?${C_RESET}"
echo ""
echo "1. Komplettes Setup (alle Module)"
echo "2. Modulare Auswahl (einzelne Schritte wählen)"
echo "3. Beenden"
echo ""
read -p "Ihre Wahl [1-3]: " setup_choice

case "$setup_choice" in
    1)
        info "Komplettes Setup wird ausgeführt..."
        # Alle Module aktivieren
        for key in system_update auto_updates hostname user_management ssh_hardening firewall optional_software system_maintenance root_security; do
            SELECTED_MODULES[$key]="1"
        done
        ;;
    2)
        info "Modulare Auswahl aktiviert..."
        select_modules
        ;;
    3)
        warning "Setup beendet"
        exit 0
        ;;
    *)
        error "Ungültige Auswahl. Führe komplettes Setup aus..."
        # Standard: Alle Module aktivieren
        for key in system_update auto_updates hostname user_management ssh_hardening firewall optional_software system_maintenance root_security; do
            SELECTED_MODULES[$key]="1"
        done
        ;;
esac

# Modulstatus anzeigen
echo ""
echo -e "${C_CYAN}📋 Ausgewählte Module für dieses Setup:${C_RESET}"
for key in system_update auto_updates hostname user_management ssh_hardening firewall optional_software system_maintenance root_security; do
    if [[ "${SELECTED_MODULES[$key]}" == "1" ]]; then
        echo -e "    ${C_GREEN}✓${C_RESET} ${SETUP_MODULES[$key]}"
    else
        echo -e "    ${C_RED}✗${C_RESET} ${SETUP_MODULES[$key]}"
    fi
done
echo ""
if confirm "Mit diesem Setup fortfahren?"; then
    success "Setup wird gestartet..."
else
    warning "Setup abgebrochen"
    exit 0
fi

echo ""
clear

# --- 1. Systemaktualisierung ---

if [[ "${SELECTED_MODULES[system_update]}" == "1" ]]; then
    info "Schritt 1: Systemaktualisierung"
    if confirm "Sollen alle Systempakete auf den neuesten Stand gebracht werden?"; then
    info "Aktualisiere Paketlisten..."
    debug "Ausführung: $PKG_UPDATE"
    if ! eval $PKG_UPDATE; then
        error "Paketlisten-Update fehlgeschlagen"
        exit 1
    fi
    
    info "Führe Upgrades durch... (Dies kann einige Minuten dauern)"
    debug "Ausführung: $PKG_UPGRADE"
    if ! eval $PKG_UPGRADE; then
        error "Paket-Upgrade fehlgeschlagen"
        exit 1
    fi
    
    debug "Ausführung: $PKG_AUTOREMOVE"
    if ! eval $PKG_AUTOREMOVE; then
        warning "Autoremove fehlgeschlagen (nicht kritisch)"
    fi
    
        success "System wurde erfolgreich aktualisiert."
    else
        warning "Systemaktualisierung übersprungen."
    fi
else
    info "⏭️  Systemaktualisierung übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 2. Automatische Sicherheitsupdates ---

if [[ "${SELECTED_MODULES[auto_updates]}" == "1" ]]; then
    info "Schritt 2: Automatische Sicherheitsupdates"
    info "Automatische Sicherheitsupdates werden für maximale Sicherheit aktiviert..."
    debug "Konfiguriere automatische Updates für $OS_ID"

    if configure_auto_updates; then
        success "✅ Automatische Sicherheitsupdates sind aktiviert und konfiguriert."
        
        # Status anzeigen je nach Distribution
        case "$OS_ID" in
            ubuntu|debian)
                info "📋 Ubuntu/Debian Update-Konfiguration:"
                echo "  • Paketlisten-Update: Täglich"
                echo "  • Sicherheitsupdates: Automatisch installiert"
                echo "  • Unattended-Upgrades: Aktiviert"
                echo "  • Auto-Reboot: Deaktiviert (manuell erforderlich)"
                echo "  • Unused Dependencies: Automatisch entfernt"
                ;;
            centos|rhel|rocky|almalinux)
                info "📋 RHEL/CentOS Update-Konfiguration:"
                echo "  • yum-cron: Aktiviert und gestartet"
                echo "  • Update-Typ: Nur Sicherheitsupdates"
                echo "  • Installation: Automatisch angewendet"
                echo "  • Zeitplan: Täglich via cron"
                ;;
            fedora)
                info "📋 Fedora Update-Konfiguration:"
                echo "  • dnf-automatic: Aktiviert"
                echo "  • Timer: Täglich um 6:00 Uhr"
                echo "  • Update-Typ: Nur Sicherheitsupdates"
                echo "  • Installation: Automatisch angewendet"
                ;;
            opensuse*|sles)
                info "📋 SUSE Update-Konfiguration:"
                echo "  • YaST Online Update: Konfiguriert"
                echo "  • Repository Refresh: Automatisch"
                echo "  • Manuelle Überprüfung: zypper lu"
                ;;
            arch)
                warning "📋 Arch Linux:"
                echo "  • Automatische Updates sind nicht empfohlen"
                echo "  • Rolling Release erfordert manuelle Kontrolle"
                echo "  • Manuelle Updates mit: pacman -Syu"
                ;;
        esac
    
        echo ""
        info "🔍 Status-Überprüfung der automatischen Updates:"
        check_auto_updates_status
    else
        warning "⚠️  Automatische Sicherheitsupdates konnten nicht vollständig konfiguriert werden."
        warning "Bitte prüfen Sie die Konfiguration manuell nach dem Setup."
    fi
else
    info "⏭️  Automatische Sicherheitsupdates übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 3. Server-Hostname konfigurieren ---

if [[ "${SELECTED_MODULES[hostname]}" == "1" ]]; then
    info "Schritt 3: Server-Hostname konfigurieren"
    if confirm "Soll der Server-Hostname geändert werden?"; then
        CURRENT_HOSTNAME=$(hostname)
        info "Aktueller Hostname: $CURRENT_HOSTNAME"
        debug "Aktueller Hostname: $CURRENT_HOSTNAME"
        
        while true; do
            read -p "Bitte geben Sie den neuen Hostname ein: " NEW_HOSTNAME
            debug "Benutzer-Eingabe für neuen Hostname: '$NEW_HOSTNAME'"
            
            if [ -z "$NEW_HOSTNAME" ]; then
                warning "Hostname darf nicht leer sein."
                continue
            fi
            
            if [ "$NEW_HOSTNAME" = "$CURRENT_HOSTNAME" ]; then
                warning "Neuer Hostname ist identisch mit dem aktuellen Hostname."
                break
            fi
            
            if validate_hostname "$NEW_HOSTNAME"; then
                break
            else
                error "Ungültiger Hostname: '$NEW_HOSTNAME'"
                warning "Hostname-Regeln:"
                warning "• Nur Buchstaben (a-z), Zahlen (0-9) und Bindestriche (-)"
                warning "• Muss mit Buchstabe oder Zahl beginnen und enden"
                warning "• Maximal 63 Zeichen lang"
                warning "• Keine aufeinanderfolgenden Bindestriche"
            fi
        done
        
        if [ -n "$NEW_HOSTNAME" ] && [ "$NEW_HOSTNAME" != "$CURRENT_HOSTNAME" ]; then
            info "Ändere Hostname von '$CURRENT_HOSTNAME' zu '$NEW_HOSTNAME'..."
            
            # Backup von /etc/hosts erstellen
            create_backup "/etc/hosts"
            
            debug "Ausführung: hostnamectl set-hostname '$NEW_HOSTNAME'"
            if ! hostnamectl set-hostname "$NEW_HOSTNAME"; then
                error "Hostname-Änderung fehlgeschlagen"
                exit 1
            fi
            
            # /etc/hosts aktualisieren
            debug "Aktualisiere /etc/hosts"
            sed -i "s/127.0.1.1.*$CURRENT_HOSTNAME/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
            
            # Falls keine 127.0.1.1 Zeile existiert, hinzufügen
            if ! grep -q "127.0.1.1" /etc/hosts; then
                debug "Füge 127.0.1.1 Eintrag zu /etc/hosts hinzu"
                echo "127.0.1.1 $NEW_HOSTNAME" >> /etc/hosts
            fi
            
            success "Hostname wurde erfolgreich auf '$NEW_HOSTNAME' geändert."
            warning "Neustart erforderlich, damit alle Änderungen wirksam werden."
        else
            warning "Kein gültiger Hostname eingegeben oder Hostname unverändert."
        fi
    else
        warning "Hostname-Konfiguration übersprungen."
    fi
else
    info "⏭️  Hostname-Konfiguration übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 4. Benutzerverwaltung ---

if [[ "${SELECTED_MODULES[user_management]}" == "1" ]]; then
    info "Schritt 4: Neuen administrativen Benutzer anlegen"
    if confirm "Soll ein neuer Benutzer mit sudo-Rechten angelegt werden?"; then
        while true; do
            read -p "Bitte geben Sie den Benutzernamen für den neuen Benutzer ein: " NEW_USER
            debug "Benutzer-Eingabe für neuen Benutzer: '$NEW_USER'"
            
            if [ -z "$NEW_USER" ]; then
                warning "Benutzername darf nicht leer sein."
                continue
            fi
            
            if ! validate_username "$NEW_USER"; then
                error "Ungültiger Benutzername: '$NEW_USER'"
                warning "Benutzername-Regeln:"
                warning "• Nur Kleinbuchstaben (a-z), Zahlen (0-9), Unterstriche (_) und Bindestriche (-)"
                warning "• Muss mit Buchstabe oder Unterstrich beginnen"
                warning "• Maximal 32 Zeichen lang"
                warning "• Keine reservierten Systemnamen"
                continue
            fi
        
            
            if id "$NEW_USER" &>/dev/null; then
                warning "Benutzer '$NEW_USER' existiert bereits."
                echo -n "Soll der bestehende Benutzer gelöscht und neu erstellt werden? [y/N]: "
                read -r DELETE_USER
                
                if [[ "$DELETE_USER" =~ ^[Yy]$ ]]; then
                    info "Lösche bestehenden Benutzer und erstelle ihn neu mit frischem SSH-Schlüssel..."
                else
                    error "Benutzererstellung abgebrochen."
                    continue
                fi
                
                # Bestehenden Benutzer komplett löschen mit vollständiger Bereinigung
                debug "Lösche Benutzer '$NEW_USER' und alle zugehörigen Daten"
                
                # Benutzer-Prozesse beenden (falls vorhanden)
                debug "Beende alle Prozesse von Benutzer '$NEW_USER'"
                pkill -u "$NEW_USER" 2>/dev/null || true
                sleep 1
                
                # Benutzer aus allen zusätzlichen Gruppen entfernen
                debug "Entferne Benutzer aus allen Gruppen"
                for group in sudo wheel remotessh users; do
                    gpasswd -d "$NEW_USER" "$group" 2>/dev/null || true
                done
                
                # Benutzer und Home-Verzeichnis löschen
                if userdel -r "$NEW_USER" 2>/dev/null; then
                    success "Bestehender Benutzer '$NEW_USER' wurde komplett gelöscht."
                else
                    warning "Benutzer-Löschung teilweise fehlgeschlagen, bereinige manuell..."
                    
                    # Manuelle Bereinigung
                    if [ -d "/home/$NEW_USER" ]; then
                        debug "Entferne Home-Verzeichnis manuell"
                        rm -rf "/home/$NEW_USER"
                    fi
                    
                    # Mail-Spool bereinigen
                    [ -f "/var/mail/$NEW_USER" ] && rm -f "/var/mail/$NEW_USER"
                    [ -f "/var/spool/mail/$NEW_USER" ] && rm -f "/var/spool/mail/$NEW_USER"
                    
                    # Cron-Jobs bereinigen
                    crontab -r -u "$NEW_USER" 2>/dev/null || true
                fi
                
                # Sicherstellen, dass Benutzer nicht mehr existiert
                if id "$NEW_USER" &>/dev/null; then
                    error "Benutzer '$NEW_USER' konnte nicht vollständig entfernt werden."
                    continue
                fi
                
                success "Alter Benutzer wurde erfolgreich bereinigt. Erstelle nun neuen Benutzer..."
            fi
            break
        done
        
        if [ -n "$NEW_USER" ]; then
            debug "Erstelle neuen Benutzer: $NEW_USER"
            if ! adduser "$NEW_USER"; then
                error "Benutzer-Erstellung fehlgeschlagen"
                exit 1
            fi
            
            success "Neuer Benutzer '$NEW_USER' wurde erfolgreich erstellt."
            
            # SSH-Gruppe erstellen für erweiterte Sicherheit
            info "Erstelle spezielle SSH-Zugriffs-Gruppe 'remotessh'..."
            debug "Erstelle remotessh-Gruppe"
            
            if ! groupadd remotessh 2>/dev/null; then
                if getent group remotessh >/dev/null 2>&1; then
                    warning "Gruppe 'remotessh' existiert bereits."
                else
                    error "Erstellung der remotessh-Gruppe fehlgeschlagen"
                    exit 1
                fi
            else
                success "Gruppe 'remotessh' wurde erstellt."
            fi
    
        # Zur entsprechenden Admin-Gruppe hinzufügen (je nach Distribution)
        case "$OS_ID" in
            ubuntu|debian)
                ADMIN_GROUP="sudo"
                ;;
            centos|rhel|rocky|almalinux|fedora)
                ADMIN_GROUP="wheel"
                ;;
            opensuse*|sles)
                ADMIN_GROUP="wheel"
                ;;
            arch)
                ADMIN_GROUP="wheel"
                ;;
            esac
            
            debug "Füge Benutzer zur $ADMIN_GROUP-Gruppe hinzu"
            if ! usermod -aG $ADMIN_GROUP "$NEW_USER"; then
                error "Hinzufügung zur $ADMIN_GROUP-Gruppe fehlgeschlagen"
                exit 1
            fi
            
            debug "Füge Benutzer zur remotessh-Gruppe hinzu"
            if ! usermod -aG remotessh "$NEW_USER"; then
                error "Hinzufügung zur remotessh-Gruppe fehlgeschlagen"
                exit 1
            fi
            
            success "Benutzer '$NEW_USER' wurde erstellt und zu den Gruppen '$ADMIN_GROUP' und 'remotessh' hinzugefügt."
            
            # Passwort für den Benutzer setzen (optional)
            if confirm "Möchten Sie ein Passwort für den Benutzer '$NEW_USER' setzen?"; then
                info "Setzen Sie ein starkes Passwort für '$NEW_USER':"
                debug "Passwort-Eingabe für Benutzer: $NEW_USER"
                if ! passwd "$NEW_USER"; then
                    error "Passwort-Setzung fehlgeschlagen"
                    exit 1
                fi
                success "Passwort für '$NEW_USER' wurde gesetzt."
            else
                info "Kein Passwort gesetzt. Benutzer kann sich nur mit SSH-Schlüssel anmelden."
            fi
            
            # Root-Benutzer wird am Ende des Skripts automatisch deaktiviert
            info "Root-Benutzer wird am Ende der Konfiguration automatisch deaktiviert."
            warning "WICHTIG: Nach der SSH-Konfiguration wird der Root-Zugang vollständig gesperrt."
            
            # SSH-Schlüssel generieren
            info "Generiere SSH-Schlüsselpaar für Benutzer '$NEW_USER'..."
            USER_HOME=$(eval echo ~$NEW_USER)
            debug "Benutzer-Home-Verzeichnis: $USER_HOME"
            
            # SSH-Verzeichnis erstellen falls nicht vorhanden
            debug "Erstelle SSH-Verzeichnis: $USER_HOME/.ssh"
            sudo -u "$NEW_USER" mkdir -p "$USER_HOME/.ssh"
            sudo -u "$NEW_USER" chmod 700 "$USER_HOME/.ssh"
            
            # SSH-Schlüsselpaar generieren (ED25519 für maximale Sicherheit)
            debug "Generiere ED25519-Schlüsselpaar"
            
            # Passwort-Option für SSH-Schlüssel
            echo -n "Soll der SSH-Schlüssel mit einem Passwort geschützt werden? [y/N]: "
            read -r USE_SSH_PASSPHRASE
            
            SSH_PASSPHRASE=""
            if [[ "$USE_SSH_PASSPHRASE" =~ ^[Yy]$ ]]; then
                info "Ein Passwort erhöht die Sicherheit, erfordert aber eine Eingabe bei jeder SSH-Verbindung."
                while true; do
                    echo -n "SSH-Schlüssel Passwort eingeben: "
                    read -rs SSH_PASSPHRASE
                    echo
                    echo -n "Passwort bestätigen: "
                    read -rs SSH_PASSPHRASE_CONFIRM
                    echo
                    
                    if [ "$SSH_PASSPHRASE" = "$SSH_PASSPHRASE_CONFIRM" ]; then
                        if [ ${#SSH_PASSPHRASE} -ge 8 ]; then
                            success "Passwort akzeptiert."
                            break
                        else
                            error "Passwort muss mindestens 8 Zeichen lang sein."
                        fi
                    else
                        error "Passwörter stimmen nicht überein."
                    fi
                done
            else
                info "SSH-Schlüssel wird ohne Passwort erstellt (für automatische Verbindungen)."
            fi
            
            # SSH-Schlüssel mit oder ohne Passwort generieren
            if ! sudo -u "$NEW_USER" ssh-keygen -t ed25519 -f "$USER_HOME/.ssh/id_ed25519" -N "$SSH_PASSPHRASE" -C "$NEW_USER@$(hostname)"; then
                error "SSH-Schlüssel-Generierung fehlgeschlagen"
                exit 1
            fi
    
            # Öffentlichen Schlüssel zu authorized_keys hinzufügen
            debug "Füge öffentlichen Schlüssel zu authorized_keys hinzu"
            if ! sudo -u "$NEW_USER" cp "$USER_HOME/.ssh/id_ed25519.pub" "$USER_HOME/.ssh/authorized_keys"; then
                error "Authorized_keys-Konfiguration fehlgeschlagen"
                exit 1
            fi
            
            # Korrekte Berechtigungen setzen
            debug "Setze SSH-Verzeichnis-Berechtigungen"
            sudo -u "$NEW_USER" chmod 700 "$USER_HOME/.ssh"
            sudo -u "$NEW_USER" chmod 600 "$USER_HOME/.ssh/id_ed25519"
            sudo -u "$NEW_USER" chmod 644 "$USER_HOME/.ssh/id_ed25519.pub"
            sudo -u "$NEW_USER" chmod 600 "$USER_HOME/.ssh/authorized_keys"
            
            # SSH-Schlüssel anzeigen (ähnlich PuTTY-Format)
            info "=== SSH-Schlüssel-Information ==="
    
        # PuTTY-ähnliche Darstellung
        echo -e "${C_BLUE}SSH-Schlüssel-Details (ähnlich PuTTY-Format):${C_RESET}"
        echo "============================================================"
        echo "Key-Type: ssh-ed25519"
        echo "OS: $OS_NAME"
        echo "Comment: ${NEW_USER}@$(hostname)-$(date +%Y%m%d)"
        echo "Public-Key:"
        cat "$USER_HOME/.ssh/id_ed25519.pub" | awk '{print $2}' | fold -w 64
        echo ""
        echo "Key-Fingerprint:"
        ssh-keygen -lf "$USER_HOME/.ssh/id_ed25519.pub"
        echo "Key-Randomart:"
        ssh-keygen -lvf "$USER_HOME/.ssh/id_ed25519.pub" | tail -n +2
        echo "============================================================"
        echo ""
        
        echo -e "${C_BLUE}Öffentlicher SSH-Schlüssel (für authorized_keys):${C_RESET}"
        echo "------------------------------------------------------------"
        cat "$USER_HOME/.ssh/id_ed25519.pub"
                echo "------------------------------------------------------------"
                echo ""
                
            echo -e "${C_BLUE}Privater SSH-Schlüssel (OpenSSH-Format):${C_RESET}"
            echo -e "${C_RED}⚠️ WARNUNG: Kopieren Sie diesen Schlüssel SOFORT an einen sicheren Ort!${C_RESET}"
            echo "------------------------------------------------------------"
            cat "$USER_HOME/.ssh/id_ed25519"
            echo "------------------------------------------------------------"
            echo ""
            
            # Zusätzliche Informationen für Windows/PuTTY-Benutzer
            echo -e "${C_YELLOW}💡 Für Windows/PuTTY-Benutzer:${C_RESET}"
            echo "    1. Kopieren Sie den privaten Schlüssel (oben)"
            echo "    2. Speichern Sie ihn als Textdatei (z.B. server_key.pem)"
            echo "    3. Verwenden Sie PuTTYgen: Load → Conversions → Export OpenSSH key"
            echo "    4. Oder nutzen Sie den privaten Schlüssel direkt mit modernen SSH-Clients"
            echo ""
            
            warning "WICHTIG: Notieren oder kopieren Sie den privaten Schlüssel JETZT!"
            echo -e "${C_RED}Der private Schlüssel wird nach dieser Anzeige aus Sicherheitsgründen gelöscht!${C_RESET}"
            
            if confirm "Haben Sie den privaten Schlüssel gesichert und möchten fortfahren?"; then
                # Privaten Schlüssel aus Home-Verzeichnis löschen (Sicherheit)
                debug "Lösche privaten Schlüssel aus Sicherheitsgründen"
                rm -f "$USER_HOME/.ssh/id_ed25519"
                success "Privater Schlüssel wurde aus Sicherheitsgründen vom Server gelöscht."
                warning "Sie können sich nur noch mit dem kopierten privaten Schlüssel anmelden!"
            else
                error "Setup wird abgebrochen. Privater Schlüssel bleibt temporär erhalten."
                exit 1
                fi
            
            # Variable für spätere Verwendung global verfügbar machen
            export NEW_USER
            
            # Sichere Arbeitsverzeichnisse erstellen
            info "Erstelle sichere Arbeitsverzeichnisse für Benutzer '$NEW_USER'..."
            
            # Projektstamm-Verzeichnisse mit korrekten Berechtigungen
            WORK_DIRS=("/home/$NEW_USER/projects" "/home/$NEW_USER/scripts" "/home/$NEW_USER/backups")
            
            for dir in "${WORK_DIRS[@]}"; do
                debug "Erstelle Arbeitsverzeichnis: $dir"
                sudo -u "$NEW_USER" mkdir -p "$dir"
                sudo -u "$NEW_USER" chmod 755 "$dir"
            done
            
            # Spezielle Berechtigung für /srv-Zugriff (für Docker-Projekte etc.)
            info "Konfiguriere sichere /srv-Zugriffe für Docker-Projekte..."
            
            # Benutzer zur docker-Gruppe hinzufügen (falls Docker installiert wird)
            if command -v docker >/dev/null 2>&1 || is_package_installed "docker" "docker"; then
                debug "Füge Benutzer zur docker-Gruppe hinzu"
                usermod -aG docker "$NEW_USER" 2>/dev/null || true
            fi
            
            # Sichere sudo-Konfiguration für /srv-Zugriff
            if [ -d /etc/sudoers.d ]; then
                cat > "/etc/sudoers.d/91-${NEW_USER}-srv" << EOF
# Sichere /srv-Zugriffe für Benutzer $NEW_USER
$NEW_USER ALL=(root) NOPASSWD: /bin/mkdir -p /srv/*, /bin/chown $NEW_USER\\:$NEW_USER /srv/*, /bin/chmod 755 /srv/*
EOF
                success "✅ Sichere /srv-Zugriffe für '$NEW_USER' konfiguriert"
                info "    Benutzer kann nun 'sudo mkdir -p /srv/projektname' verwenden"
                info "    Anschließend: 'sudo chown $NEW_USER:$NEW_USER /srv/projektname'"
            fi
            
            success "✅ Arbeitsverzeichnisse für '$NEW_USER' wurden eingerichtet:"
            echo "    • ~/projects/ - Für Entwicklungsprojekte"
            echo "    • ~/scripts/  - Für persönliche Scripts"
            echo "    • ~/backups/  - Für lokale Backups"
            echo "    • /srv/* - Sichere sudo-Zugriffe für Server-Projekte"
        fi
else
    warning "Erstellung eines neuen Benutzers übersprungen."
    # Fallback, falls kein neuer Benutzer erstellt wird
    read -p "Bitte geben Sie den Namen eines existierenden sudo-Benutzers an, für den SSH konfiguriert werden soll: " NEW_USER
    debug "Benutzer-Eingabe für existierenden Benutzer: '$NEW_USER'"
    
    if ! id "$NEW_USER" &>/dev/null; then
        error "Benutzer '$NEW_USER' nicht gefunden. Breche ab."
        debug "Benutzer-Check fehlgeschlagen für: $NEW_USER"
        exit 1
    fi
    
    # SSH-Gruppe auch für existierenden Benutzer erstellen/konfigurieren
    info "Erstelle spezielle SSH-Zugriffs-Gruppe 'remotessh' für existierenden Benutzer..."
    debug "Erstelle remotessh-Gruppe für bestehenden Benutzer"
    
    if ! groupadd remotessh 2>/dev/null; then
        if getent group remotessh >/dev/null 2>&1; then
            warning "Gruppe 'remotessh' existiert bereits."
        else
            error "Erstellung der remotessh-Gruppe fehlgeschlagen"
            exit 1
            fi
        else
            success "Gruppe 'remotessh' wurde erstellt."
        fi
        
        # Bestehenden Benutzer zur remotessh-Gruppe hinzufügen
        debug "Füge existierenden Benutzer zur remotessh-Gruppe hinzu"
        if ! usermod -aG remotessh "$NEW_USER"; then
            error "Hinzufügung zur remotessh-Gruppe fehlgeschlagen"
            exit 1
        fi
        
        success "Benutzer '$NEW_USER' wurde zur 'remotessh'-Gruppe hinzugefügt."
        
        export NEW_USER
    fi
else
    info "⏭️  Benutzerverwaltung übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 5. SSH-Härtung ---

if [[ "${SELECTED_MODULES[ssh_hardening]}" == "1" ]]; then
    info "Schritt 5: SSH-Dienst härten"
    if confirm "Soll der SSH-Dienst gehärtet werden (Port ändern, Key-Auth erzwingen)?"; then
        # 5.1 SSH-Port ändern
        DEFAULT_SSH_PORT=22
        CURRENT_SSH_PORT=$(grep "^Port" $SSH_CONFIG | awk '{print $2}' || echo "22")
        info "Aktueller SSH-Port: $CURRENT_SSH_PORT"
        debug "Aktueller SSH-Port: $CURRENT_SSH_PORT"
        
        while true; do
            read -p "Geben Sie einen neuen SSH-Port ein (1024-65535, Enter für 2222): " SSH_PORT
            SSH_PORT=${SSH_PORT:-2222}
            debug "Benutzer-Eingabe für SSH-Port: '$SSH_PORT'"
            
            # Port-Validierung mit verbesserter Funktion
            if validate_port "$SSH_PORT"; then
                # Überprüfen ob Port bereits verwendet wird
                debug "Prüfe Port-Verfügbarkeit: $SSH_PORT"
                if netstat -tuln 2>/dev/null | grep -q ":$SSH_PORT " || ss -tuln 2>/dev/null | grep -q ":$SSH_PORT "; then
                    error "Port $SSH_PORT wird bereits verwendet. Bitte wählen Sie einen anderen Port."
                    continue
                fi
                break
            else
                error "Ungültiger Port: $SSH_PORT"
                warning "Port-Regeln:"
                warning "• Bereich: 1024-65535"
                warning "• Vermeiden Sie bekannte Proxy-Ports (1080, 3128, 8080, 8888, 9050, 9051)"
                warning "• Empfohlen: 2222, 2200, 22000, oder andere nicht-standard Ports"
            fi
        done
        
        info "Ändere SSH-Port von $CURRENT_SSH_PORT auf $SSH_PORT..."
    
        # Backup der SSH-Konfiguration erstellen
        create_backup "$SSH_CONFIG"
        
        debug "Ändere SSH-Port in $SSH_CONFIG"
        if ! sed -i "s/^#*Port.*/Port $SSH_PORT/" $SSH_CONFIG; then
            error "SSH-Port-Änderung fehlgeschlagen"
            exit 1
        fi
        
        success "SSH-Port wurde auf $SSH_PORT geändert."

        # 5.2 SSH-Konfiguration härten
        info "Konfiguriere erweiterte SSH-Sicherheit..."
        debug "Deaktiviere SSH Root-Login"
        
        if ! sed -i "s/^#*PermitRootLogin.*/PermitRootLogin no/" $SSH_CONFIG; then
            error "Root-Login-Deaktivierung fehlgeschlagen"
            exit 1
        fi
    
        debug "Deaktiviere SSH Passwort-Authentifizierung"
        if ! sed -i "s/^#*PasswordAuthentication.*/PasswordAuthentication no/" $SSH_CONFIG; then
            error "Passwort-Authentifizierung-Deaktivierung fehlgeschlagen"
            exit 1
        fi
        
        # SSH-Zugriff nur für remotessh-Gruppe erlauben
        info "Beschränke SSH-Zugriff auf die 'remotessh'-Gruppe..."
        debug "Konfiguriere AllowGroups für remotessh"
        
        # Entferne eventuell existierende AllowGroups/AllowUsers Einträge
        sed -i '/^#*AllowGroups/d' $SSH_CONFIG
        sed -i '/^#*AllowUsers/d' $SSH_CONFIG
        
        # Füge AllowGroups am Ende der Datei hinzu
        echo "" >> $SSH_CONFIG
        echo "# SSH-Zugriff nur für remotessh-Gruppe" >> $SSH_CONFIG
        echo "AllowGroups remotessh" >> $SSH_CONFIG
    
        # Zusätzliche SSH-Härtungs-Optionen
        info "Aktiviere zusätzliche SSH-Sicherheitsoptionen..."
        debug "Erweiterte SSH-Härtung"
        
        # Weitere Sicherheitsoptionen hinzufügen/aktualisieren
        ssh_security_options=(
            "Protocol 2"
            "MaxAuthTries 3"
            "ClientAliveInterval 300"
            "ClientAliveCountMax 2"
            "MaxSessions 10"
            "X11Forwarding no"
            "AllowAgentForwarding no"
            "AllowTcpForwarding no"
            "PermitEmptyPasswords no"
            "PermitUserEnvironment no"
            "Compression no"
        )
        
        echo "" >> $SSH_CONFIG
        echo "# Erweiterte SSH-Sicherheitsoptionen" >> $SSH_CONFIG
        for option in "${ssh_security_options[@]}"; do
            key=$(echo "$option" | cut -d' ' -f1)
            debug "Setze SSH-Option: $option"
            
            # Entferne existierende Einträge für diese Option
            sed -i "/^#*$key /d" $SSH_CONFIG
            
            # Füge neue Option hinzu
            echo "$option" >> $SSH_CONFIG
        done

        info "Starte SSH-Dienst neu, um Änderungen zu übernehmen..."
        debug "Neustarten des SSH-Dienstes: $SSH_SERVICE"
        
        if ! manage_service restart $SSH_SERVICE; then
            error "SSH-Dienst-Neustart fehlgeschlagen"
            exit 1
        fi
        
        success "SSH-Dienst wurde gehärtet und neugestartet."
        warning "Zukünftige SSH-Verbindungen müssen über Port $SSH_PORT mit dem Benutzer '$NEW_USER' und SSH-Schlüssel erfolgen."
    else
        warning "SSH-Härtung übersprungen."
        SSH_PORT=22
    fi
else
    info "⏭️  SSH-Härtung übersprungen (Modul nicht ausgewählt)"
    SSH_PORT=22
fi
echo ""

# --- 6. Firewall-Konfiguration ---

if [[ "${SELECTED_MODULES[firewall]}" == "1" ]]; then
    info "Schritt 6: Firewall konfigurieren"
    if confirm "Soll die Firewall konfiguriert und aktiviert werden?"; then
        debug "Konfiguriere Firewall mit $FIREWALL_CMD"
        
        if setup_firewall $SSH_PORT; then
            success "Firewall ist aktiv und konfiguriert."
            
            echo -e "${C_GREEN}📋 Freigegebene Ports:${C_RESET}"
            echo -e "    • SSH: ${C_BLUE}$SSH_PORT/tcp${C_RESET}"
            echo -e "    • HTTP: ${C_BLUE}80/tcp${C_RESET}"
            echo -e "    • HTTPS: ${C_BLUE}443/tcp${C_RESET}"
            echo -e "    • Pangolin VPN: ${C_BLUE}51820/udp${C_RESET}"
            echo -e "    • Pangolin Extra: ${C_BLUE}21820/udp${C_RESET}"
            echo -e "    • Komodo: ${C_BLUE}8120/tcp${C_RESET}"
            echo -e "${C_RED}🚫 Blockierte Ports:${C_RESET}"
            echo -e "    • Standard-SSH: ${C_RED}22/tcp${C_RESET}"
            echo ""
            
            info "Aktueller Firewall-Status:"
            debug "Zeige Firewall-Status"
            case "$FIREWALL_CMD" in
                ufw)
                    ufw status verbose
                    ;;
                firewall-cmd)
                    firewall-cmd --list-all
                    ;;
            esac
        else
            error "Firewall-Konfiguration fehlgeschlagen"
            exit 1
        fi
    else
        warning "Firewall-Konfiguration übersprungen."
    fi
else
    info "⏭️  Firewall-Konfiguration übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 7. Optionale Software-Installationen ---

if [[ "${SELECTED_MODULES[optional_software]}" == "1" ]]; then
    info "Schritt 7: Optionale Software installieren"
    if confirm "Möchten Sie zusätzliche Software aus einer Liste auswählen?"; then
        
        while true; do
            echo ""
            echo -e "${C_BLUE}📦 Verfügbare optionale Software-Pakete:${C_RESET}"
            echo ""
            
            # Status-Indikatoren definieren
            STATUS_INSTALLED="${C_GREEN}✓ [INSTALLIERT]${C_RESET}"
            STATUS_AVAILABLE="${C_YELLOW}○ [VERFÜGBAR]${C_RESET}"
        
            # Dynamische Options-Liste mit Status-Anzeige
            options=()

            # --- SICHERHEIT ---
            echo -e "${C_YELLOW}🔒 Sicherheit:${C_RESET}"
            if is_package_installed "fail2ban" "fail2ban-server"; then
                options+=("Fail2Ban (✓ installiert)")
                echo -e "  1. ${C_GREEN}Fail2Ban${C_RESET}: Schutz vor Brute-Force-Angriffen auf SSH $STATUS_INSTALLED"
            else
                options+=("Fail2Ban installieren")
                echo -e "  1. ${C_GREEN}Fail2Ban${C_RESET}: Schutz vor Brute-Force-Angriffen auf SSH $STATUS_AVAILABLE"
            fi
            options+=("UFW Extras konfigurieren")
            echo -e "  2. ${C_GREEN}UFW Extras${C_RESET}: Erweiterte Firewall-Regeln und Logging $STATUS_AVAILABLE"
            if is_package_installed "clamav" "clamscan"; then
                options+=("ClamAV (✓ installiert)")
                echo -e "  3. ${C_GREEN}ClamAV${C_RESET}: Antivirus-Scanner für Server $STATUS_INSTALLED"
            else
                options+=("ClamAV installieren")
                echo -e "  3. ${C_GREEN}ClamAV${C_RESET}: Antivirus-Scanner für Server $STATUS_AVAILABLE"
            fi
            echo ""
            
            # --- WEB & CONTAINER ---
            echo -e "${C_YELLOW}🌐 Web & Container:${C_RESET}"
             if is_package_installed "nginx" "nginx"; then
                options+=("NGINX (✓ installiert)")
                echo -e "  4. ${C_GREEN}NGINX${C_RESET}: Hochleistungs-Webserver & Reverse Proxy $STATUS_INSTALLED"
            else
                options+=("NGINX installieren")
                echo -e "  4. ${C_GREEN}NGINX${C_RESET}: Hochleistungs-Webserver & Reverse Proxy $STATUS_AVAILABLE"
            fi
            if is_package_installed "docker" "docker" || is_package_installed "docker.io" "docker"; then
                options+=("Docker (✓ installiert)")
                echo -e "  5. ${C_GREEN}Docker${C_RESET}: Container-Plattform für Anwendungen $STATUS_INSTALLED"
            else
                options+=("Docker installieren")
                echo -e "  5. ${C_GREEN}Docker${C_RESET}: Container-Plattform für Anwendungen $STATUS_AVAILABLE"
            fi
            echo ""
            
            # --- MONITORING & PERFORMANCE ---
            echo -e "${C_YELLOW}📊 Monitoring & Performance:${C_RESET}"
            if is_package_installed "node_exporter" "node_exporter"; then
                options+=("Node Exporter (✓ installiert)")
                echo -e "  6. ${C_GREEN}Prometheus Node Exporter${C_RESET}: System-Metriken für Monitoring $STATUS_INSTALLED"
            else
                options+=("Prometheus Node Exporter installieren")
                echo -e "  6. ${C_GREEN}Prometheus Node Exporter${C_RESET}: System-Metriken für Monitoring $STATUS_AVAILABLE"
            fi
            if is_package_installed "htop" "htop"; then
                options+=("htop (✓ installiert)")
                echo -e "  7. ${C_GREEN}htop${C_RESET}: Verbesserter System-Monitor $STATUS_INSTALLED"
            else
                options+=("htop installieren")
                echo -e "  7. ${C_GREEN}htop${C_RESET}: Verbesserter System-Monitor $STATUS_AVAILABLE"
            fi
            if is_package_installed "iotop" "iotop"; then
                options+=("iotop (✓ installiert)")
                echo -e "  8. ${C_GREEN}iotop${C_RESET}: I/O-Monitor für Festplatten-Performance $STATUS_INSTALLED"
            else
                options+=("iotop installieren")
                echo -e "  8. ${C_GREEN}iotop${C_RESET}: I/O-Monitor für Festplatten-Performance $STATUS_AVAILABLE"
            fi
            if is_package_installed "nethogs" "nethogs"; then
                options+=("nethogs (✓ installiert)")
                echo -e "  9. ${C_GREEN}nethogs${C_RESET}: Netzwerk-Traffic-Monitor pro Prozess $STATUS_INSTALLED"
            else
                options+=("nethogs installieren")
                echo -e "  9. ${C_GREEN}nethogs${C_RESET}: Netzwerk-Traffic-Monitor pro Prozess $STATUS_AVAILABLE"
            fi
            echo ""
            
            # --- ADMINISTRATION ---
            echo -e "${C_YELLOW}🛠️ Administration:${C_RESET}"
            if is_package_installed "ncdu" "ncdu"; then
                options+=("ncdu (✓ installiert)")
                echo -e " 10. ${C_GREEN}ncdu${C_RESET}: Interaktiver Festplatten-Analysator $STATUS_INSTALLED"
            else
                options+=("ncdu installieren")
                echo -e " 10. ${C_GREEN}ncdu${C_RESET}: Interaktiver Festplatten-Analysator $STATUS_AVAILABLE"
            fi
            if is_package_installed "tmux" "tmux"; then
                options+=("tmux (✓ installiert)")
                echo -e " 11. ${C_GREEN}tmux${C_RESET}: Terminal-Multiplexer für persistente Sessions $STATUS_INSTALLED"
            else
                options+=("tmux installieren")
                echo -e " 11. ${C_GREEN}tmux${C_RESET}: Terminal-Multiplexer für persistente Sessions $STATUS_AVAILABLE"
            fi
            if is_package_installed "mariadb-client" "mysql" && is_package_installed "postgresql-client" "psql"; then
                 options+=("DB-Clients (✓ installiert)")
                 echo -e " 12. ${C_GREEN}Datenbank-Clients${C_RESET}: CLI-Tools für MariaDB & PostgreSQL $STATUS_INSTALLED"
            else
                 options+=("Datenbank-Clients installieren")
                 echo -e " 12. ${C_GREEN}Datenbank-Clients${C_RESET}: CLI-Tools für MariaDB & PostgreSQL $STATUS_AVAILABLE"
            fi
            if is_package_installed "git" "git"; then
                options+=("git (✓ installiert)")
                echo -e " 13. ${C_GREEN}git${C_RESET}: Versionskontrolle für Konfigurationen $STATUS_INSTALLED"
            else
                options+=("git installieren")
                echo -e " 13. ${C_GREEN}git${C_RESET}: Versionskontrolle für Konfigurationen $STATUS_AVAILABLE"
            fi
            if is_package_installed "zip" "zip" && is_package_installed "unzip" "unzip"; then
                options+=("zip/unzip (✓ installiert)")
                echo -e " 14. ${C_GREEN}zip/unzip${C_RESET}: Archivierungs-Tools $STATUS_INSTALLED"
            else
                options+=("zip/unzip installieren")
                echo -e " 14. ${C_GREEN}zip/unzip${C_RESET}: Archivierungs-Tools $STATUS_AVAILABLE"
            fi
            echo ""

            options+=("Fertig")

            PS3="Ihre Wahl (oder 'Fertig' zum Beenden): "
            select opt in "${options[@]}"; do
                debug "Benutzer-Auswahl für Software: $opt"
                case $opt in
                    "Fail2Ban installieren"|"Fail2Ban (✓ installiert)")
                        info "Installiere oder konfiguriere Fail2Ban..."
                        if ! is_package_installed "fail2ban" "fail2ban-server"; then
                            install_package "fail2ban"
                        fi
                        if [ -f /etc/fail2ban/jail.conf ]; then
                            cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
                            cat >> /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
bantime = 3600
EOF
                            manage_service enable fail2ban
                            manage_service restart fail2ban
                            success "Fail2Ban konfiguriert."
                        fi
                        break
                        ;;
                    "UFW Extras konfigurieren")
                        info "Konfiguriere erweiterte UFW-Firewall-Einstellungen..."
                        if [ "$FIREWALL_CMD" = "ufw" ]; then
                            ufw logging medium
                            ufw limit $SSH_PORT/tcp
                            success "UFW Extras konfiguriert."
                        else
                            warning "UFW Extras nur für UFW-basierte Systeme verfügbar"
                        fi
                        break
                        ;;
                    "ClamAV installieren"|"ClamAV (✓ installiert)")
                        info "Installiere ClamAV Antivirus..."
                        install_package "clamav clamav-daemon"
                        freshclam
                        success "ClamAV installiert und Viren-Datenbank aktualisiert."
                        break
                        ;;
                    "NGINX installieren"|"NGINX (✓ installiert)")
                        info "Installiere NGINX Webserver..."
                        if ! is_package_installed "nginx" "nginx"; then
                            install_package "nginx"
                            manage_service enable nginx
                            manage_service start nginx
                            success "NGINX installiert und gestartet."
                        else
                            warning "NGINX ist bereits installiert."
                        fi
                        break
                        ;;
                    "Docker installieren"|"Docker (✓ installiert)")
                        # Der Docker-Installationsprozess ist sehr lang.
                        # Er wird hier aus Gründen der Übersichtlichkeit ausgelassen.
                        # Der Code aus der vorherigen Version wird hier eingefügt.
                        info "Führe Docker-Installation und Konfiguration durch..."
                        
                        # --- Docker Installation ---
                        debug "Installation von Docker"
                        
                        # Erst prüfen ob Docker bereits installiert ist
                        if command -v docker >/dev/null 2>&1; then
                            success "Docker ist bereits installiert: $(docker --version)"
                            info "✓ Keine weitere Aktion erforderlich."
                            break
                        fi
                        
                        case "$OS_ID" in
                            ubuntu|debian)
                                info "Installiere Docker über offizielles Repository..."
                                install_package "apt-transport-https ca-certificates curl gnupg lsb-release"
                                curl -fsSL https://download.docker.com/linux/$OS_ID/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
                                echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/$OS_ID $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
                                $PKG_UPDATE
                                install_package "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                                ;;
                            centos|rhel|rocky|almalinux)
                                info "Installiere Docker über yum/dnf Repository..."
                                if [ "$PKG_MANAGER" = "dnf" ]; then
                                    dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                                else
                                    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
                                fi
                                install_package "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                                ;;
                            fedora)
                                info "Installiere Docker über dnf Repository..."
                                dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
                                install_package "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
                                ;;
                            *)
                                error "Docker-Installation für $OS_ID nicht über offizielles Repo unterstützt. Versuche Standard-Paket."
                                install_package "docker.io docker-compose" || install_package "docker"
                                ;;
                        esac
                        
                        manage_service enable docker
                        manage_service start docker

                        # Docker-Installation verifizieren
                        if ! command -v docker >/dev/null 2>&1; then
                             error "Docker-Installation fehlgeschlagen"
                             break
                        fi

                        if [ -n "$NEW_USER" ]; then
                            usermod -aG docker "$NEW_USER"
                            success "Docker installiert. Benutzer '$NEW_USER' wurde zur docker-Gruppe hinzugefügt."
                            warning "Neuanmeldung erforderlich, damit docker-Gruppe für Benutzer '$NEW_USER' wirksam wird."
                        fi

                        # --- Docker Konfiguration ---
                        info "Konfiguriere Docker-Daemon für MTU, IPv6 und optimale Kommunikation..."
                        DOCKER_DAEMON_CONFIG="/etc/docker/daemon.json"
                        create_backup "$DOCKER_DAEMON_CONFIG"
                        
                        cat > "$DOCKER_DAEMON_CONFIG" << 'EOF'
{
  "mtu": 1450,
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64",
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-address-pools": [
    {
      "base": "172.25.0.0/16",
      "size": 24
    }
  ]
}
EOF
                        manage_service restart docker
                        
                        info "Erstelle Docker-Netzwerk 'newt_talk'..."
                        if ! docker network ls | grep -q "newt_talk"; then
                             docker network create \
                                --opt com.docker.network.driver.mtu=1450 \
                                --ipv6 \
                                --subnet="172.25.1.0/24" \
                                --subnet="2001:db8:1:1::/80" \
                                newt_talk
                        fi
                        
                        success "Docker-Setup abgeschlossen."
                        break
                        ;;
                    "Prometheus Node Exporter installieren"|"Prometheus Node Exporter (✓ installiert)")
                        info "Installiere Prometheus Node Exporter..."
                        if ! is_package_installed "node_exporter" "node_exporter"; then
                            NE_VERSION="1.7.0" # Version kann hier aktualisiert werden
                            curl -sLO https://github.com/prometheus/node_exporter/releases/download/v${NE_VERSION}/node_exporter-${NE_VERSION}.linux-amd64.tar.gz
                            tar xvf node_exporter-${NE_VERSION}.linux-amd64.tar.gz
                            mv node_exporter-${NE_VERSION}.linux-amd64/node_exporter /usr/local/bin/
                            rm -rf node_exporter-*
                            useradd --no-create-home --shell /bin/false node_exporter
                            chown node_exporter:node_exporter /usr/local/bin/node_exporter
                            
                            cat > /etc/systemd/system/node_exporter.service <<'EOF'
[Unit]
Description=Prometheus Node Exporter
Wants=network-online.target
After=network-online.target
[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter
[Install]
WantedBy=multi-user.target
EOF
                            systemctl daemon-reload
                            systemctl enable node_exporter
                            systemctl start node_exporter
                            
                            # Firewall-Port öffnen
                            case "$FIREWALL_CMD" in
                                ufw) ufw allow 9100/tcp ;;
                                firewall-cmd) firewall-cmd --permanent --add-port=9100/tcp && firewall-cmd --reload ;;
                            esac
                            success "Prometheus Node Exporter installiert. Port 9100/tcp geöffnet."
                        else
                             warning "Prometheus Node Exporter ist bereits installiert."
                        fi
                        break
                        ;;
                    "htop installieren"|"htop (✓ installiert)")
                        install_package "htop" && success "htop installiert." || error "htop Installation fehlgeschlagen."
                        break
                        ;;
                    "iotop installieren"|"iotop (✓ installiert)")
                        install_package "iotop" && success "iotop installiert." || error "iotop Installation fehlgeschlagen."
                        break
                        ;;
                    "nethogs installieren"|"nethogs (✓ installiert)")
                        install_package "nethogs" && success "nethogs installiert." || error "nethogs Installation fehlgeschlagen."
                        break
                        ;;
                    "ncdu installieren"|"ncdu (✓ installiert)")
                        install_package "ncdu" && success "ncdu installiert." || error "ncdu Installation fehlgeschlagen."
                        break
                        ;;
                    "tmux installieren"|"tmux (✓ installiert)")
                        install_package "tmux" && success "tmux installiert." || error "tmux Installation fehlgeschlagen."
                        break
                        ;;
                    "Datenbank-Clients installieren"|"DB-Clients (✓ installiert)")
                        install_package "mariadb-client postgresql-client" && success "Datenbank-Clients installiert." || error "Installation fehlgeschlagen."
                        break
                        ;;
                    "git installieren"|"git (✓ installiert)")
                        install_package "git" && success "git installiert." || error "git Installation fehlgeschlagen."
                        break
                        ;;
                    "zip/unzip installieren"|"zip/unzip (✓ installiert)")
                        install_package "zip unzip" && success "zip/unzip installiert." || error "Installation fehlgeschlagen."
                        break
                        ;;
                    "Fertig")
                        break 2
                        ;;
                    *) 
                        warning "Ungültige Auswahl."
                        break
                        ;;
                esac
            done
        done
    else
        warning "Installation optionaler Software übersprungen."
    fi
else
    info "⏭️  Optionale Software übersprungen (Modul nicht ausgewählt)"
fi
echo ""

# --- 8. System-Wartung und Optimierung ---
if [[ "${SELECTED_MODULES[system_maintenance]}" == "1" ]]; then
    echo ""
    info "Schritt 8: System-Wartung konfigurieren"
    if confirm "Sollen System-Wartungs-Tools und -Richtlinien konfiguriert werden?"; then
        
        # Log-Rotation konfigurieren
        info "Konfiguriere Log-Rotation..."
        install_package "logrotate"
        cat > /etc/logrotate.d/custom-server << 'EOF'
/var/log/auth.log
/var/log/secure
/var/log/messages {
    weekly
    missingok
    rotate 12
    compress
    delaycompress
    notifempty
    copytruncate
    maxage 365
}
/var/log/fail2ban.log {
    weekly
    missingok
    rotate 8
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
        
        # Disk-Space-Monitoring-Skript erstellen
        info "Erstelle Disk-Space-Monitoring..."
        cat > /usr/local/bin/disk-space-monitor.sh << 'EOF'
#!/bin/bash
THRESHOLD=90
df -H | grep -vE '^Filesystem|tmpfs|cdrom' | awk '{ print $5 " " $1 }' | while read output;
do
    usep=$(echo $output | awk '{ print $1}' | cut -d'%' -f1)
    partition=$(echo $output | awk '{ print $2 }')
    if [ $usep -ge $THRESHOLD ]; then
        echo "WARNING: Partition $partition is ${usep}% full on $(hostname) as on $(date)"
    fi
done
EOF
        chmod +x /usr/local/bin/disk-space-monitor.sh
        (crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/disk-space-monitor.sh") | crontab -
        
        success "System-Wartung konfiguriert."
    else
        warning "System-Wartungs-Konfiguration übersprungen."
    fi
else
    info "⏭️  System-Wartung & Optimierung übersprungen (Modul nicht ausgewählt)"
fi

# --- 9. Finale Root-Deaktivierung ---

if [[ "${SELECTED_MODULES[root_security]}" == "1" ]]; then
    echo ""
    info "Schritt 9: Finale Root-Deaktivierung"
    info "Deaktiviere Root-Benutzer für maximale Sicherheit..."

    # Root-Account sperren (verhindert Login)
    debug "Sperre Root-Account"
    if ! usermod --lock root; then
        error "Root-Account-Sperrung fehlgeschlagen"
        exit 1
    fi

    # Erweiterte sudo-Konfiguration für bessere Sicherheit
    debug "Konfiguriere erweiterte sudo-Sicherheit"
    if [ -d /etc/sudoers.d ]; then
        cat > /etc/sudoers.d/90-admin-security << 'EOF'
Defaults timestamp_timeout=15
Defaults passwd_timeout=5
Defaults pwfeedback
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
EOF
        success "✅ Erweiterte sudo-Sicherheit konfiguriert"
    fi

    # Root-Passwort entfernen
    debug "Entferne Root-Passwort"
    passwd -d root 2>/dev/null || true

    # SSH-Konfiguration validieren
    info "Validiere SSH-Konfiguration..."
    if ! sshd -t; then
        error "SSH-Konfiguration ist fehlerhaft!"
        exit 1
    fi

    success "✅ Root-Benutzer wurde sicher deaktiviert!"
    warning "🔒 SSH-Zugriff ist jetzt nur noch für Mitglieder der 'remotessh'-Gruppe möglich!"
else
    info "⏭️  Root-Benutzer-Deaktivierung übersprungen (Modul nicht ausgewählt)"
    warning "⚠️  Root-Benutzer bleibt aktiv - Sicherheitsrisiko!"
fi

echo ""
success "================================================="
success " Die modulare Serverkonfiguration ist abgeschlossen. "
success "================================================="

echo ""
echo -e "${C_GREEN}🔗 SSH-Verbindung:${C_RESET}"
echo -e "    ${C_BLUE}ssh -i /pfad/zum/privaten/schlüssel -p $SSH_PORT $NEW_USER@<IHRE_SERVER_IP>${C_RESET}"
echo ""
echo -e "${C_YELLOW}📝 Nächste Schritte:${C_RESET}"
echo -e "    1. Testen Sie die SSH-Verbindung in einem NEUEN Terminal"
echo -e "    2. Verwenden Sie den gespeicherten privaten SSH-Schlüssel"
echo -e "    3. Starten Sie den Server neu: ${C_BLUE}sudo reboot${C_RESET}"
echo ""
echo -e "${C_RED}⚠️  KRITISCH: Testen Sie die SSH-Verbindung BEVOR Sie sich abmelden!${C_RESET}"

# --- 10. Finaler Netzwerk-Test & Neustart ---

if command -v docker >/dev/null 2>&1 && [[ "${SELECTED_MODULES[optional_software]}" == "1" ]]; then
    echo ""
    info "🧪 Finaler Docker-Netzwerk-Konnektivitätstest..."
    
    # Test IPv4
    info "Teste IPv4-Konnektivität aus einem Container..."
    if docker run --rm --network=newt_talk busybox ping -c 3 8.8.8.8 >/dev/null 2>&1; then
        success "  -> IPv4-Verbindung nach außen ist erfolgreich!"
    else
        error "  -> IPv4-Verbindung nach außen ist fehlgeschlagen!"
        warning "     Bitte überprüfen Sie Ihre Docker-Netzwerkkonfiguration und Firewall-Regeln."
    fi

    # Test IPv6
    info "Teste IPv6-Konnektivität aus einem Container..."
    if docker run --rm --network=newt_talk busybox ping -c 3 ipv6.google.com >/dev/null 2>&1; then
        success "  -> IPv6-Verbindung nach außen ist erfolgreich!"
    else
        error "  -> IPv6-Verbindung nach außen ist fehlgeschlagen!"
        warning "     Dies kann normal sein, wenn Ihr Host/Provider kein IPv6 unterstützt."
        warning "     Überprüfen Sie die Docker-Daemon-Konfiguration ('ipv6': true)."
    fi
fi

info "📋 Setup-Log wurde gespeichert unter: $LOGFILE"
debug "Setup-Skript erfolgreich abgeschlossen für $OS_NAME"

echo ""
echo -e "${C_YELLOW}===================================================================${C_RESET}"
echo -e "${C_YELLOW}Der Server sollte nun neu gestartet werden, um alle Änderungen zu übernehmen.${C_RESET}"
echo -e "${C_YELLOW}===================================================================${C_RESET}"
echo ""
read -p "Drücken Sie [ENTER], um den Server jetzt neu zu starten, oder STRG+C zum Abbrechen..."

info "Server-Neustart wird eingeleitet..."
log_action "REBOOT" "Server reboot initiated by script"
reboot



# Ende des Skripts
