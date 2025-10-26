# 🚀 Universelles Linux Server-Setup-Skript v3.0

Ein umfassendes, modulares Setup-Skript für die sichere Ersteinrichtung von Linux-Servern mit automatischer Konfiguration von Tailscale VPN, Komodo Periphery und modernen CLI-Tools.

## ✨ Features

### 🔐 Sicherheit
- **SSH-Härtung**: Port-Änderung, Key-Only-Auth, Root-Login deaktivieren
- **Firewall**: Automatische UFW/firewalld-Konfiguration mit IPv6-Support
- **Automatische Updates**: Unattended-upgrades für Debian/Ubuntu, yum-cron für RHEL
- **Fail2Ban Integration**: Schutz vor Brute-Force-Angriffen
- **Root-Account-Sperrung**: Sichere Deaktivierung nach Setup

### 🌐 Netzwerk
- **Tailscale VPN**: Automatische Installation mit Auth-Key-Integration
- **IP-Adressen-Anzeige**: Öffentliche IPv4/IPv6 + Tailscale-IPs
- **Hostname-Konfiguration**: Automatisch VOR Tailscale gesetzt
- **MTU-Optimierung**: Docker-Netzwerk-Konfiguration für VPN/Overlay

### 🦎 Komodo Periphery
- **Automatisches Setup**: Docker Compose + .env Konfiguration
- **Tailscale-Integration**: Bindet automatisch an Tailscale-IP
- **Sicheres Passkey**: Automatisch generiert und angezeigt
- **/opt/komodo**: Automatische Verzeichniserstellung

### 🛠️ Moderne CLI-Tools
- **bat**: cat-Alternative mit Syntax-Highlighting
- **exa**: ls-Alternative mit Icons und Git-Integration
- **fzf**: Fuzzy Finder für Kommandozeile
- **ripgrep (rg)**: Blitzschnelles grep
- **fd**: find-Alternative
- **Oh-My-Zsh**: Mit Powerlevel10k Theme und Plugins

### 🔧 Weitere Features
- **Multi-Distro-Support**: Ubuntu, Debian, CentOS, RHEL, Fedora, SUSE, Arch
- **Modulares System**: Wähle nur die benötigten Module
- **Dry-Run-Modus**: Teste ohne echte Änderungen
- **Idempotenz**: Mehrfach ausführbar ohne Probleme
- **Error-Recovery**: Automatische Backups und Retry-Mechanismen
- **Ausführliches Logging**: Alle Aktionen in `/var/log/server-setup.log`

## 📋 Unterstützte Distributionen

- ✅ **Ubuntu** 20.04+, 22.04+, 24.04+
- ✅ **Debian** 10+, 11+, 12+
- ✅ **CentOS** 7+, 8+
- ✅ **RHEL** 7+, 8+, 9+
- ✅ **Rocky Linux** 8+, 9+
- ✅ **AlmaLinux** 8+, 9+
- ✅ **Fedora** 35+
- ✅ **openSUSE** Leap 15+
- ✅ **Arch Linux**

## 🚦 Schnellstart

### Einfache Ausführung

```bash
# Repository klonen oder herunterladen
git clone <repository-url>
cd setup

# Als root/sudo ausführen
sudo ./start.sh
```

### Mit Optionen

```bash
# Normal
sudo ./start.sh

# Debug-Modus (ausführliche Ausgabe)
sudo ./start.sh debug

# Dry-Run (keine Änderungen, nur Test)
sudo ./start.sh dry-run
```

### Direkte Ausführung

```bash
# Normal
sudo ./setup.sh

# Mit Umgebungsvariablen
DEBUG=1 sudo ./setup.sh
DRY_RUN=1 sudo ./setup.sh
```

## 📖 Verwendung

### 1. Komplettes Setup

Das Skript führt Sie interaktiv durch alle Module:

```bash
sudo ./start.sh
```

Sie werden gefragt:
1. **Setup-Art**: Komplett oder modulare Auswahl
2. **System-Update**: Alle Pakete aktualisieren
3. **Hostname**: Server-Namen festlegen (❗ WICHTIG: VOR Tailscale!)
4. **Benutzer**: Neuen Admin-Benutzer mit sudo-Rechten erstellen
5. **SSH**: Härtung mit Port-Änderung und Key-Auth
6. **Firewall**: UFW/firewalld aktivieren
7. **Tailscale**: VPN installieren und Auth-Key eingeben
8. **Komodo**: Periphery für Docker-Management
9. **CLI-Tools**: Moderne Werkzeuge installieren
10. **Oh-My-Zsh**: Verbesserte Shell-Umgebung

### 2. Modulare Auswahl

Wählen Sie nur bestimmte Module:

```bash
sudo ./start.sh

# Im Menü: Option "2. Modulare Auswahl"
# Dann einzelne Module mit Nummern auswählen (z.B. 1,3,5)
```

## 🔑 Tailscale Setup

### Vorbereitung

1. **Auth-Key erstellen**: https://login.tailscale.com/admin/settings/keys
   - ✅ **Reusable**: Ja (für mehrere Server)
   - ✅ **Pre-authorized**: Ja (keine manuelle Freigabe)
   - ❌ **Ephemeral**: Nein (Server bleibt im Netzwerk)
   - 📝 **Tags**: Optional (z.B. `tag:server`)

2. **Bei Setup-Ausführung**:
   ```
   Tailscale Auth-Key eingeben: tskey-auth-XXXXX-YYYYY
   ```

3. **Automatische Konfiguration**:
   - Firewall-Port 41641/udp wird geöffnet
   - Optional: Exit-Node Konfiguration
   - Optional: Tailscale SSH aktivieren

### Nach der Installation

```bash
# Status prüfen
sudo tailscale status

# IP-Adressen anzeigen
sudo tailscale ip -4  # IPv4
sudo tailscale ip -6  # IPv6

# Manuelle Verbindung (falls übersprungen)
sudo tailscale up --authkey=tskey-auth-XXXXX-YYYYY
```

## 🦎 Komodo Periphery

Das Skript richtet automatisch Komodo Periphery ein:

### Automatische Konfiguration

- **Verzeichnis**: `/opt/komodo/`
- **Port**: `<tailscale-ip>:8120` (bindet an Tailscale-IP)
- **Passkey**: Automatisch generiert und angezeigt
- **Docker Compose**: Fertig konfiguriert
- **SSL**: Aktiviert

### Wichtige Dateien

```
/opt/komodo/
├── docker-compose.yml    # Container-Konfiguration
├── .env                  # Umgebungsvariablen (PASSKEY hier!)
└── ...                   # Repos, Stacks, Builds
```

### Passkey notieren!

⚠️ **WICHTIG**: Das automatisch generierte Passkey wird NUR EINMAL angezeigt!

```
🔑 Passkey: ijQGCrwLG4bjfNq1vKBIsqSqbzDJCTZVN7fOA988CoeJJK1bmyjLnQn8fWnVL6cr
```

Notieren Sie es für die Verbindung mit Komodo Core.

### Komodo starten/stoppen

```bash
# Starten
cd /opt/komodo && docker compose up -d

# Stoppen
cd /opt/komodo && docker compose down

# Logs anzeigen
cd /opt/komodo && docker compose logs -f

# Status prüfen
docker ps | grep komodo
```

## 📡 IP-Adressen Anzeige

Das Skript zeigt automatisch alle relevanten IPs an:

```
═══════════════════════════════════════════════════
           📡 NETZWERK-INFORMATIONEN
═══════════════════════════════════════════════════

🌐 Öffentliche IPv4-Adresse:
   5.83.145.130

🌐 Öffentliche IPv6-Adresse:
   2a13:7e80:0:582::1

🔐 Tailscale VPN-Adresse:
   IPv4: 100.126.38.111
   IPv6: fd7a:115c:a1e0::1

🔌 Lokale Netzwerk-Interfaces:
   eth0  UP  10.0.0.5/24
   tailscale0  UP  100.126.38.111/32
```

Diese Informationen sind wichtig für:
- Komodo Core Verbindung
- Firewall-Konfiguration
- Monitoring-Tools
- DNS-Einträge

## 🛠️ Moderne CLI-Tools

Nach der Installation stehen folgende Tools zur Verfügung:

### bat (cat-Alternative)
```bash
bat file.txt          # Syntax-Highlighting
bat file.log          # Mit Zeilennummern
alias cat='bat'       # Automatisch gesetzt
```

### exa (ls-Alternative)
```bash
exa                   # Mit Icons
exa -l                # Long format
exa -la --git         # Mit Git-Status
alias ls='exa'        # Automatisch gesetzt
```

### fzf (Fuzzy Finder)
```bash
<Ctrl+R>             # Command History durchsuchen
<Ctrl+T>             # Dateien durchsuchen
<Alt+C>              # Verzeichnisse wechseln
```

### ripgrep (grep-Alternative)
```bash
rg "pattern" /path   # Blitzschnell
rg -i "text"         # Case-insensitive
alias grep='rg'      # Automatisch gesetzt
```

### fd (find-Alternative)
```bash
fd filename          # Datei finden
fd -e txt            # Nach Endung
alias find='fd'      # Automatisch gesetzt
```

## 🎨 Oh-My-Zsh

Optional wird Oh-My-Zsh mit Powerlevel10k Theme installiert:

### Features
- **Powerlevel10k**: Modernes, schnelles Theme
- **Plugins**: git, docker, sudo, history, fzf
- **Aliase**: Für alle modernen Tools automatisch gesetzt
- **Auto-Completion**: Intelligente Tab-Vervollständigung

### Aktivierte Aliase

```bash
# Docker
dps              # docker ps
dcup             # docker compose up -d
dcdown           # docker compose down

# Git
gs               # git status
ga               # git add
gc               # git commit
gp               # git push

# Nützliches
myip             # curl ifconfig.me
ports            # netstat -tuln
update           # apt update && upgrade
```

## 🧪 Dry-Run Modus

Teste das Skript ohne echte Änderungen:

```bash
sudo ./start.sh dry-run
```

Ausgabe:
```
[DRY-RUN] Would execute: apt update
[DRY-RUN] Would execute: apt install -y tailscale
[DRY-RUN] Would create: /opt/komodo/docker-compose.yml
...
```

Nützlich für:
- Test auf neuen Distributionen
- Verstehen der geplanten Änderungen
- Debugging von Problemen

## 🐛 Debug-Modus

Ausführliche Logging-Ausgabe:

```bash
sudo ./start.sh debug
```

Zeigt:
- Alle Befehle vor Ausführung
- Variablenwerte
- OS-Erkennungsdetails
- Paketmanager-Operationen
- Fehlerdiagnose

## 📝 Logging

Alle Aktionen werden protokolliert:

```bash
# Log-Datei anzeigen
sudo tail -f /var/log/server-setup.log

# Log durchsuchen
sudo grep "ERROR" /var/log/server-setup.log
sudo grep "TAILSCALE" /var/log/server-setup.log
```

Log-Format:
```
[2025-10-26 17:30:15] [INFO] System update started
[2025-10-26 17:30:45] [SUCCESS] Tailscale installed
[2025-10-26 17:31:00] [NETWORK] Tailscale IPv4: 100.126.38.111
[2025-10-26 17:31:30] [KOMODO] Passkey: ijQGCrwLG...
```

## 🔄 Idempotenz

Das Skript kann mehrfach ausgeführt werden:

- ✅ Überprüft ob Pakete bereits installiert sind
- ✅ Überspringt bereits konfigurierte Module
- ✅ Warnt vor Überschreiben bestehender Konfigurationen
- ✅ Erstellt Backups vor Änderungen

```bash
# Erstmaliges Setup
sudo ./start.sh

# Später erneut ausführen (z.B. für neue Module)
sudo ./start.sh
# → Bereits konfigurierte Module werden erkannt
```

## 🔒 Sicherheitshinweise

### Nach dem Setup

1. **SSH-Verbindung testen** (in neuem Terminal!):
   ```bash
   ssh -i /pfad/zum/key -p <SSH_PORT> <USER>@<SERVER_IP>
   ```

2. **Root-Account ist gesperrt**:
   - Login als root nicht mehr möglich
   - Nur sudo über konfigurierten Benutzer

3. **Firewall aktiv**:
   - Standard-SSH-Port 22 ist blockiert
   - Nur konfigurierter Port ist offen

4. **Privater SSH-Key**:
   - Wurde vom Server gelöscht
   - Nur gesicherter Key funktioniert

### Notfall-Zugriff

Falls SSH-Zugriff verloren:
1. Server-Provider-Console nutzen (z.B. Hetzner, AWS Console)
2. Firewall temporär deaktivieren
3. SSH-Konfiguration prüfen

## ❓ FAQ

### Kann ich das Skript auf einem bereits konfigurierten Server ausführen?

Ja! Das Skript erkennt bestehende Konfigurationen und fragt nach:
- Überschreiben
- Überspringen
- Nur neue Module ausführen

### Was passiert wenn das Skript abbricht?

- Backups in `/var/backups/server-setup/`
- Log-Datei zeigt letzten erfolgreichen Schritt
- Einfach erneut ausführen (idempotent)

### Wie deinstalliere ich einzelne Komponenten?

```bash
# Tailscale
sudo tailscale down
sudo apt remove tailscale

# Komodo
cd /opt/komodo && docker compose down
sudo rm -rf /opt/komodo

# Oh-My-Zsh
rm -rf ~/.oh-my-zsh
```

### Funktioniert es mit ARM-Prozessoren?

Ja, getestet auf:
- Raspberry Pi (ARM64)
- AWS Graviton
- Oracle Cloud ARM

### Kann ich eigene Module hinzufügen?

Ja! Das Skript ist modular aufgebaut. Siehe Dokumentation zur Erweiterung.

## 🤝 Beitragen

Verbesserungsvorschläge und Fehlermeldungen sind willkommen!

## 📄 Lizenz

MIT License

## 🙏 Credits

- [Tailscale](https://tailscale.com/) - Zero-config VPN
- [Komodo](https://github.com/moghtech/komodo) - Docker Management
- [Oh-My-Zsh](https://ohmyz.sh/) - Zsh Framework
- [Powerlevel10k](https://github.com/romkatv/powerlevel10k) - Zsh Theme

---

**Viel Erfolg mit Ihrem Server-Setup! 🚀**
