# 🚀 Universelles Linux Server-Setup-Skript v3.0

Ein umfassendes, modulares Setup-Skript für die sichere Ersteinrichtung von Linux-Servern mit automatischer Konfiguration von Tailscale VPN, Komodo Periphery und modernen CLI-Tools.

## ✨ Features

### 🔐 Sicherheit
- **SSH-Härtung**: Port-Änderung, Key-Only-Auth, Root-Login deaktivieren
- **Firewall**: Automatische UFW/firewalld-Konfiguration mit IPv6-Support
- **Automatische Updates**: Unattended-upgrades für Debian/Ubuntu, yum-cron für RHEL
- **Fail2Ban**: Automatischer Schutz vor Brute-Force-Angriffen auf SSH
  - 3 Fehlversuche → 1 Stunde Ban
  - Automatische IP-Sperrung
  - Logs in /var/log/fail2ban.log
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

### 🎨 Benutzerfreundlichkeit
- **Custom Motd**: Informatives Login-Banner mit
  - Öffentlicher IPv4/IPv6-Adresse
  - Tailscale VPN-IP
  - System-Status (Uptime, Load, Memory, Disk)
  - Docker & Komodo Status
  - Tailscale Verbindungsstatus

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
# Normal (interaktiv)
sudo ./setup.sh

# Hilfe anzeigen
sudo ./setup.sh --help

# Mit Command-line Argumenten (EMPFOHLEN für Automatisierung!)
sudo ./setup.sh \
  --tailscale-key tskey-auth-k1234567CNTRL-ABCD \
  --komodo-path /srv/komodo \
  --hostname myserver \
  --ssh-port 2222 \
  --yes  # Keine interaktiven Fragen

# Kurz-Form
sudo ./setup.sh -t tskey-auth-XXX -k /srv/komodo -H myserver -p 2222 -y

# Dry-Run zum Testen
sudo ./setup.sh --dry-run --tailscale-key tskey-auth-XXX

# Mit Umgebungsvariablen (Alternative)
TAILSCALE_KEY=tskey-auth-XXX KOMODO_PATH=/srv/komodo sudo ./setup.sh

# Alles kombiniert (ENV + Args)
TAILSCALE_KEY=tskey-auth-XXX DEBUG=1 sudo ./setup.sh --yes --hostname myserver
```

## ⚙️ Konfiguration über Umgebungsvariablen

Das Skript unterstützt folgende Umgebungsvariablen für automatisierte Setups:

| Variable | Beschreibung | Standard | Beispiel |
|----------|-------------|----------|----------|
| `DEBUG` | Debug-Ausgabe aktivieren | `0` | `DEBUG=1` |
| `DRY_RUN` | Test-Modus (keine Änderungen) | `0` | `DRY_RUN=1` |
| `TAILSCALE_KEY` | Tailscale Auth-Key | (leer) | `TAILSCALE_KEY=tskey-auth-XXX` |
| `KOMODO_PATH` | Komodo Installationspfad | `/opt/komodo` | `KOMODO_PATH=/srv/komodo` |
| `HOSTNAME_SET` | Server Hostname | (leer) | `HOSTNAME_SET=myserver` |
| `SSH_PORT_SET` | SSH Port | (leer) | `SSH_PORT_SET=2222` |
| `SKIP_INTERACTIVE` | Non-interactive Modus | `0` | `SKIP_INTERACTIVE=1` |

### Beispiele

```bash
# Vollautomatisches Setup mit Tailscale
TAILSCALE_KEY=tskey-auth-k1234567CNTRL-ABCDEFGH sudo ./setup.sh

# Mit eigenem Komodo-Pfad
KOMODO_PATH=/srv/komodo sudo ./setup.sh

# Alles kombiniert für CI/CD
TAILSCALE_KEY=tskey-auth-XXX \
KOMODO_PATH=/home/deploy/komodo \
DEBUG=1 \
sudo ./setup.sh

# Dry-Run zum Testen
DRY_RUN=1 TAILSCALE_KEY=tskey-auth-XXX sudo ./setup.sh
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

2. **Auth-Key übergeben** (zwei Methoden):

   **Methode 1: Umgebungsvariable** (empfohlen für Automatisierung)
   ```bash
   TAILSCALE_KEY=tskey-auth-XXXXX-YYYYY sudo ./setup.sh
   ```

   **Methode 2: Interaktive Eingabe**
   ```bash
   sudo ./setup.sh
   # → Skript fragt nach: "Tailscale Auth-Key eingeben: tskey-auth-XXXXX-YYYYY"
   ```

3. **Automatische Konfiguration**:
   - Firewall-Port 41641/udp wird geöffnet
   - ✅ **Tailscale-Interface komplett geöffnet** (alle Ports!)
   - ✅ **Docker kann über Tailscale kommunizieren**
   - Optional: Exit-Node Konfiguration
   - Optional: Tailscale SSH aktivieren
   - IP-Adressen werden automatisch angezeigt

### Tailscale + Docker Integration

Das Skript konfiguriert die Firewall so, dass:
- **Alle Ports auf dem Tailscale-Interface (tailscale0) offen sind**
- Docker-Container über Tailscale kommunizieren können
- Komodo Periphery über Tailscale erreichbar ist

```bash
# UFW (Ubuntu/Debian)
ufw allow in on tailscale0
ufw allow out on tailscale0

# firewalld (RHEL/CentOS/Fedora)
firewall-cmd --permanent --zone=trusted --add-interface=tailscale0
```

**Vorteile:**
- 🔒 Sicher: Nur Tailscale-Netzwerk hat Zugriff
- 🐳 Docker: Container können über Tailscale kommunizieren
- 🦎 Komodo: Periphery ist nur über Tailscale erreichbar
- 🚀 Einfach: Keine manuellen Port-Freigaben nötig

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

- **Verzeichnis**: `/opt/komodo/` (Standard) oder eigener Pfad
- **Port**: `<tailscale-ip>:8120` (bindet an Tailscale-IP)
- **Passkey**: Automatisch generiert und angezeigt
- **Docker Compose**: Fertig konfiguriert
- **SSL**: Aktiviert

### Installationspfad konfigurieren

**Methode 1: Umgebungsvariable** (empfohlen für Automatisierung)
```bash
# Eigener Pfad statt /opt/komodo
KOMODO_PATH=/srv/komodo sudo ./setup.sh
KOMODO_PATH=/home/admin/komodo sudo ./setup.sh
```

**Methode 2: Interaktive Eingabe**
```bash
sudo ./setup.sh
# → Skript fragt: "Möchten Sie einen anderen Installationspfad verwenden?"
# → Eingabe: /srv/komodo
```

**Hinweis**: Der Pfad wird automatisch erstellt, falls er nicht existiert.

### Wichtige Dateien

```
$KOMODO_PATH/              # Ihr gewählter Pfad (z.B. /opt/komodo oder /srv/komodo)
├── docker-compose.yml     # Container-Konfiguration
├── .env                   # Umgebungsvariablen (PASSKEY hier!)
└── ...                    # Repos, Stacks, Builds
```

### Passkey notieren!

⚠️ **WICHTIG**: Das automatisch generierte Passkey wird NUR EINMAL angezeigt!

```
🔑 Passkey: ijQGCrwLG4bjfNq1vKBIsqSqbzDJCTZVN7fOA988CoeJJK1bmyjLnQn8fWnVL6cr
```

Notieren Sie es für die Verbindung mit Komodo Core.

### Komodo starten/stoppen

```bash
# Starten (passe /opt/komodo an deinen Pfad an)
cd /opt/komodo && docker compose up -d

# Mit Variable (wenn KOMODO_PATH gesetzt)
cd $KOMODO_PATH && docker compose up -d

# Stoppen
cd /opt/komodo && docker compose down

# Logs anzeigen
cd /opt/komodo && docker compose logs -f

# Status prüfen
docker ps | grep komodo

# Neustart
cd /opt/komodo && docker compose restart
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

## 🛡️ Fail2Ban - SSH-Schutz

Das Skript installiert und konfiguriert automatisch Fail2Ban zum Schutz vor Brute-Force-Angriffen.

### Automatische Konfiguration

- **Port-Erkennung**: Nutzt automatisch den konfigurierten SSH-Port
- **Ban-Zeit**: 1 Stunde nach 3 Fehlversuchen
- **Zeitfenster**: 10 Minuten
- **Schutz**: SSH + SSH-DDOS

### Fail2Ban-Einstellungen

```bash
# Standard-Konfiguration
Max. Versuche: 3
Ban-Zeit: 3600 Sekunden (1 Stunde)
Zeitfenster: 600 Sekunden (10 Minuten)
```

### Nützliche Befehle

```bash
# Status anzeigen
sudo fail2ban-client status
sudo fail2ban-client status sshd

# Gebannte IPs anzeigen
sudo fail2ban-client status sshd

# IP manuell entbannen
sudo fail2ban-client unban 192.168.1.100

# Logs anzeigen
sudo tail -f /var/log/fail2ban.log

# Service neu starten
sudo systemctl restart fail2ban
```

### Was wird geschützt?

- ✅ SSH-Login-Versuche
- ✅ Ungültige Benutzernamen
- ✅ Root-Login-Versuche
- ✅ SSH-DDOS-Angriffe

## 🎨 Custom Motd - Login-Banner

Beim Login über SSH wird ein informatives Banner angezeigt.

### Was wird angezeigt?

```
╔════════════════════════════════════════════════════════════╗
║  myserver                                                  ║
╠════════════════════════════════════════════════════════════╣
║  Öffentliche IP:    5.83.145.130                          ║
║  Tailscale IP:      100.126.38.111                        ║
╠════════════════════════════════════════════════════════════╣
║  Uptime:            3 days, 5 hours, 12 minutes           ║
║  Load Average:      0.15, 0.10, 0.08                      ║
║  Memory:            2.1G / 16G (13%)                      ║
║  Disk (root):       45G / 100G (45%)                      ║
╠════════════════════════════════════════════════════════════╣
║  Docker:            3/5 Container                          ║
║  Komodo Periphery:  ✓ Aktiv                               ║
║  Tailscale VPN:     ✓ Verbunden                           ║
╚════════════════════════════════════════════════════════════╝
```

### Dynamische Informationen

- **System-Status**: Uptime, Load, Memory, Disk
- **Netzwerk**: Öffentliche IP + Tailscale-IP
- **Services**: Docker, Komodo, Tailscale Status
- **Farben**: Status-Indikatoren (✓ = grün, ⊘ = gelb)

### Manuelle Anzeige

```bash
# Motd manuell anzeigen (ohne Login)
run-parts /etc/update-motd.d/

# Oder statisches Motd
cat /etc/motd
```

### Anpassung

Die Motd-Scripte befinden sich in:
- `/etc/update-motd.d/00-custom-header` (dynamisch)
- `/etc/motd` (statisch, Fallback)

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
