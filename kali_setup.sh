#!/bin/bash
# =============================================================================
# KALI_SETUP.SH - Configuração automática do Kali Linux para pentest
# Configurado especialmente para interceptação HTTPS com Burp Suite
# =============================================================================

set -e
exec > >(tee /var/log/kali-setup.log) 2>&1

# Variáveis do template
STUDENT_NAME="${student_name}"
VNC_PASSWORD="${vnc_password}"
LAB_NAME="${lab_name}"
BURP_PROXY_IP="${burp_proxy_ip}"
TARGET_IP="${target_ip}"
ENABLE_BURP_PRO="${enable_burp_pro}"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log "🚀 Iniciando configuração do Kali Linux + Burp Suite para ${STUDENT_NAME}"
log "📝 Laboratório: ${LAB_NAME}"
log "🎯 Configurando interceptação HTTPS com Burp Suite"

# Atualizar repositórios e sistema
log "📦 Atualizando sistema Kali Linux..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get dist-upgrade -y

# Instalar dependências essenciais para Burp Suite
log "🔧 Instalando dependências para Burp Suite e interceptação HTTPS..."
apt-get install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    tree \
    unzip \
    zip \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    default-jdk \
    openjdk-17-jdk \
    firefox-esr \
    chromium \
    ca-certificates \
    openssl \
    libnss3-tools \
    certutil

# Configurar Java para Burp Suite
log "☕ Configurando Java para Burp Suite..."
update-alternatives --install /usr/bin/java java /usr/lib/jvm/java-17-openjdk-amd64/bin/java 1700
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
echo 'export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64' >> /etc/environment

# Configurar interface gráfica e VNC
log "🖥️ Configurando interface gráfica XFCE..."
apt-get install -y kali-desktop-xfce

# Instalar e configurar VNC
log "🔗 Configurando VNC Server..."
apt-get install -y tightvncserver xfce4 xfce4-goodies

# Criar usuário kali se não existir
if ! id "kali" &>/dev/null; then
    log "👤 Criando usuário kali..."
    useradd -m -s /bin/bash kali
    echo "kali:${VNC_PASSWORD}" | chpasswd
    usermod -aG sudo kali
else
    log "✅ Usuário kali já existe"
    echo "kali:${VNC_PASSWORD}" | chpasswd
fi

# Configurar VNC para usuário kali
log "🔧 Configurando VNC para usuário kali..."
sudo -u kali mkdir -p /home/kali/.vnc

# Configurar senha VNC
echo "${VNC_PASSWORD}" | sudo -u kali vncpasswd -f > /home/kali/.vnc/passwd
chmod 600 /home/kali/.vnc/passwd
chown kali:kali /home/kali/.vnc/passwd

# Criar script de inicialização VNC
cat > /home/kali/.vnc/xstartup << 'EOF'
#!/bin/bash
xrdb $HOME/.Xresources
startxfce4 &
EOF

chmod +x /home/kali/.vnc/xstartup
chown kali:kali /home/kali/.vnc/xstartup

# Configurar serviço VNC
cat > /etc/systemd/system/vncserver@.service << 'EOF'
[Unit]
Description=Start TightVNC server at startup
After=syslog.target network.target

[Service]
Type=forking
User=kali
Group=kali
WorkingDirectory=/home/kali

PIDFile=/home/kali/.vnc/%H:%i.pid
ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver -depth 24 -geometry 1920x1080 :%i
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar VNC
systemctl daemon-reload
systemctl enable vncserver@1.service

# =============================================================================
# INSTALAÇÃO E CONFIGURAÇÃO DO BURP SUITE
# =============================================================================

log "🔥 Configurando Burp Suite para interceptação HTTPS..."

# Baixar Burp Suite Community Edition
log "📥 Baixando Burp Suite Community Edition..."
cd /opt
wget -O burpsuite_community.jar "https://portswigger.net/burp/releases/download?product=community&type=jar"
chown kali:kali burpsuite_community.jar

# Criar diretório para Burp Suite
sudo -u kali mkdir -p /home/kali/.BurpSuite
sudo -u kali mkdir -p /home/kali/burp-workspace

# Configurar Burp Suite com configurações específicas para HTTPS
log "⚙️ Configurando Burp Suite para interceptação HTTPS..."
cat > /home/kali/.BurpSuite/UserConfigCommunity.json << EOF
{
  "user_options": {
    "connections": {
      "upstream_proxy": {
        "servers": []
      },
      "socks_proxy": {
        "do_dns_lookup": true,
        "host": "",
        "port": 1080,
        "use_proxy": false,
        "username": "",
        "password": ""
      },
      "timeouts": {
        "normal_timeout": 120000,
        "open_ended_timeout": 3600000,
        "domain_name_timeout": 30000
      },
      "hostname_resolution": [],
      "out_of_scope_requests": {
        "drop_all": false,
        "drop_not_in_scope": false
      }
    },
    "ssl": {
      "server_certificates": {
        "mode": "generate_ca_signed_per_host"
      },
      "client_certificates": {
        "certificates": []
      },
      "negotiation_overrides": []
    },
    "proxy": {
      "request_listeners": [
        {
          "certificate_mode": "per_host",
          "listen_mode": "all_interfaces",
          "listen_specific_address": "",
          "listener_port": 8080,
          "running": true,
          "support_invisible_proxying": true
        }
      ],
      "response_modification": {
        "rules": []
      },
      "request_modification": {
        "rules": []
      },
      "match_replace_rules": [],
      "ssl_negotiation_override": [],
      "miscellaneous": {
        "use_http_1_0_in_requests_to_server": false,
        "use_http_1_0_in_responses_to_client": false,
        "strip_proxy_headers": true,
        "strip_sec_websocket_extensions_headers": false,
        "unpack_gzip": true,
        "disable_web_interface": false,
        "suppress_burp_error_messages": false,
        "disable_logging": false,
        "suppress_connection_error_messages": false
      },
      "interceptor": {
        "rules": [],
        "auto_update_content_length": true,
        "auto_update_content_length_for": "requests",
        "auto_fix_missing_or_superfluous_content_length_headers": true,
        "auto_set_connection_header": true,
        "strip_tls": false,
        "break_on_ssl_failure": false
      }
    },
    "scanner": {
      "live_scanning": {
        "live_audit": {
          "audit_everything": false,
          "audit_proxy_traffic": true,
          "audit_spider_traffic": false,
          "audit_repeater_traffic": false
        },
        "live_passive_crawl": {
          "crawl_everything": false,
          "crawl_proxy_traffic": true,
          "crawl_spider_traffic": false,
          "crawl_repeater_traffic": false
        }
      }
    }
  }
}
EOF

chown kali:kali /home/kali/.BurpSuite/UserConfigCommunity.json

# Criar script de inicialização do Burp Suite
cat > /home/kali/start-burp.sh << 'EOF'
#!/bin/bash
cd /opt
java -Xmx2g -jar burpsuite_community.jar &
sleep 5

# Aguardar Burp iniciar e gerar certificado CA
echo "Aguardando Burp Suite inicializar..."
while ! netstat -tnl | grep -q ":8080 "; do
    sleep 2
done

echo "✅ Burp Suite iniciado e escutando na porta 8080"
echo "📜 Certificado CA disponível em: http://localhost:8080/cert"
EOF

chmod +x /home/kali/start-burp.sh
chown kali:kali /home/kali/start-burp.sh

# Criar serviço para Burp Suite
cat > /etc/systemd/system/burpsuite.service << 'EOF'
[Unit]
Description=Burp Suite Community Edition
After=network.target graphical-session.target

[Service]
Type=simple
User=kali
Group=kali
WorkingDirectory=/opt
Environment=DISPLAY=:1
ExecStart=/usr/bin/java -Xmx2g -jar burpsuite_community.jar --config-file=/home/kali/.BurpSuite/UserConfigCommunity.json
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable burpsuite

# =============================================================================
# CONFIGURAÇÃO DE CERTIFICADOS SSL PARA INTERCEPTAÇÃO HTTPS
# =============================================================================

log "🔒 Configurando certificados SSL para interceptação HTTPS..."

# Criar script para baixar e instalar certificado CA do Burp
cat > /home/kali/install-burp-ca.sh << 'EOF'
#!/bin/bash
echo "🔒 Instalando certificado CA do Burp Suite..."

# Aguardar Burp estar online
while ! curl -s http://localhost:8080 > /dev/null; do
    echo "Aguardando Burp Suite..."
    sleep 2
done

# Baixar certificado CA do Burp
curl -s http://localhost:8080/cert -o /tmp/cacert.der

if [ -f /tmp/cacert.der ]; then
    # Converter para formato PEM
    openssl x509 -in /tmp/cacert.der -inform DER -out /tmp/burp-ca.crt
    
    # Instalar no sistema
    sudo cp /tmp/burp-ca.crt /usr/local/share/ca-certificates/
    sudo update-ca-certificates
    
    # Instalar no Firefox
    if [ -d "$HOME/.mozilla" ]; then
        # Encontrar perfil do Firefox
        PROFILE_DIR=$(find $HOME/.mozilla/firefox -name "*.default*" -type d | head -1)
        if [ -n "$PROFILE_DIR" ]; then
            certutil -A -n "Burp Suite CA" -t "TC,," -i /tmp/burp-ca.crt -d "$PROFILE_DIR"
            echo "✅ Certificado instalado no Firefox"
        fi
    fi
    
    # Instalar no Chromium
    if [ -d "$HOME/.config/chromium" ]; then
        mkdir -p "$HOME/.pki/nssdb"
        certutil -d sql:$HOME/.pki/nssdb -A -t "TC,," -n "Burp Suite CA" -i /tmp/burp-ca.crt
        echo "✅ Certificado instalado no Chromium"
    fi
    
    echo "✅ Certificado CA do Burp Suite instalado com sucesso!"
else
    echo "❌ Falha ao baixar certificado CA do Burp"
fi
EOF

chmod +x /home/kali/install-burp-ca.sh
chown kali:kali /home/kali/install-burp-ca.sh

# =============================================================================
# CONFIGURAÇÃO DE BROWSERS PARA PROXY
# =============================================================================

log "🌐 Configurando browsers para uso com Burp Suite..."

# Configurar Firefox para usar proxy Burp automaticamente
sudo -u kali mkdir -p /home/kali/.mozilla/firefox

# Criar perfil Firefox personalizado para pentest
cat > /home/kali/create-firefox-profile.sh << 'EOF'
#!/bin/bash
# Criar perfil Firefox para pentest
firefox -CreateProfile "pentest /home/kali/.mozilla/firefox/pentest" -headless

# Configurar proxy no Firefox
PREFS_FILE="/home/kali/.mozilla/firefox/pentest/prefs.js"
cat > "$PREFS_FILE" << EOL
user_pref("network.proxy.type", 1);
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", 8080);
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", 8080);
user_pref("network.proxy.share_proxy_settings", true);
user_pref("network.proxy.no_proxies_on", "");
user_pref("security.tls.insecure_fallback_hosts", "");
user_pref("security.mixed_content.block_active_content", false);
user_pref("security.mixed_content.block_display_content", false);
user_pref("browser.safebrowsing.enabled", false);
user_pref("browser.safebrowsing.malware.enabled", false);
user_pref("dom.security.https_only_mode", false);
EOL

echo "✅ Perfil Firefox configurado para Burp Suite"
EOF

chmod +x /home/kali/create-firefox-profile.sh
chown kali:kali /home/kali/create-firefox-profile.sh

# Instalar ferramentas de pentest adicionais
log "🛠️ Instalando ferramentas de pentest..."

# Ferramentas web essenciais
apt-get install -y \
    zaproxy \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    sqlmap \
    commix \
    whatweb \
    wafw00f

# Ferramentas de rede
apt-get install -y \
    nmap \
    masscan \
    zmap \
    netcat-traditional \
    socat \
    tcpdump \
    wireshark \
    ettercap-text-only \
    responder

# Ferramentas de exploração
apt-get install -y \
    metasploit-framework \
    armitage \
    exploitdb \
    searchsploit \
    social-engineer-toolkit \
    beef-xss

# Ferramentas de análise
apt-get install -y \
    binwalk \
    foremost \
    volatility3 \
    autopsy \
    sleuthkit \
    hashcat \
    john \
    hydra \
    medusa \
    patator

# Instalar ferramentas Python específicas para web testing
log "🐍 Instalando ferramentas Python para web testing..."
sudo -u kali python3 -m pip install --user \
    requests \
    beautifulsoup4 \
    selenium \
    scapy \
    pycrypto \
    paramiko \
    impacket \
    bloodhound \
    mitm6 \
    crackmapexec \
    httpx \
    subfinder \
    nuclei-templates

# Configurar Metasploit
log "🎯 Configurando Metasploit..."
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres createuser msf
sudo -u postgres createdb msf_database -O msf
sudo -u postgres psql -c "ALTER USER msf WITH PASSWORD 'msf_password';"
sudo -u kali msfdb init

# Instalar ferramentas do GitHub
log "📥 Instalando ferramentas do GitHub..."
cd /opt

# SecLists
git clone https://github.com/danielmiessler/SecLists.git
chown -R kali:kali SecLists

# PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
chown -R kali:kali PayloadsAllTheThings

# PEASS - Privilege Escalation Awesome Scripts
git clone https://github.com/carlospolop/PEASS-ng.git
chown -R kali:kali PEASS-ng

# Burp Suite Extensions (Community)
sudo -u kali mkdir -p /home/kali/burp-extensions
cd /home/kali/burp-extensions

# Baixar extensões populares do Burp
sudo -u kali wget https://github.com/PortSwigger/json-beautifier/releases/latest/download/json-beautifier.jar
sudo -u kali wget https://github.com/albinowax/ActiveScanPlusPlus/releases/latest/download/activescan++.jar

# Configurar diretório de trabalho do estudante
log "📁 Configurando workspace para pentest com Burp Suite..."
sudo -u kali mkdir -p /home/kali/pentest-lab
sudo -u kali mkdir -p /home/kali/pentest-lab/tools
sudo -u kali mkdir -p /home/kali/pentest-lab/wordlists
sudo -u kali mkdir -p /home/kali/pentest-lab/exploits
sudo -u kali mkdir -p /home/kali/pentest-lab/reports
sudo -u kali mkdir -p /home/kali/pentest-lab/burp-projects
sudo -u kali mkdir -p /home/kali/pentest-lab/certificates
sudo -u kali mkdir -p /home/kali/pentest-lab/intercepted-traffic

# Criar links simbólicos para ferramentas
sudo -u kali ln -s /opt/SecLists /home/kali/pentest-lab/wordlists/SecLists
sudo -u kali ln -s /opt/PayloadsAllTheThings /home/kali/pentest-lab/exploits/PayloadsAllTheThings
sudo -u kali ln -s /usr/share/wordlists /home/kali/pentest-lab/wordlists/system

# Configurar aliases específicos para Burp Suite
cat >> /home/kali/.bashrc << 'EOF'

# Aliases para pentest com Burp Suite
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias lab='cd ~/pentest-lab'
alias burp='cd /opt && java -Xmx2g -jar burpsuite_community.jar'
alias burp-bg='cd /opt && java -Xmx2g -jar burpsuite_community.jar &'
alias install-ca='~/install-burp-ca.sh'
alias firefox-pentest='firefox -P pentest'

# Aliases para ferramentas com proxy
alias curl-burp='curl --proxy http://127.0.0.1:8080'
alias wget-burp='wget --proxy=on --http-proxy=127.0.0.1:8080 --https-proxy=127.0.0.1:8080'

# Funções para interceptação HTTPS
function burp-start() {
    echo "🔥 Iniciando Burp Suite..."
    cd /opt && java -Xmx2g -jar burpsuite_community.jar &
    sleep 10
    echo "🔒 Instalando certificado CA..."
    ~/install-burp-ca.sh
    echo "✅ Burp Suite pronto para interceptação HTTPS!"
}

function target() {
    echo "Target IP: $1" > ~/pentest-lab/current-target.txt
    export TARGET_IP=$1
    echo "🎯 Target set to: $1"
    echo "🌐 HTTP: http://$1:3000"
    echo "🔒 HTTPS: https://$1:3443"
}

function scan-target() {
    if [ -z "$1" ]; then
        echo "Usage: scan-target <target_ip>"
        return 1
    fi
    echo "🔍 Scanning $1..."
    nmap -sC -sV -p 80,443,3000,3443,8080 -oN ~/pentest-lab/reports/scan-$1.txt $1
}

function burp-intercept() {
    echo "🔥 Configurando interceptação para $1..."
    export http_proxy=http://127.0.0.1:8080
    export https_proxy=http://127.0.0.1:8080
    echo "✅ Proxy configurado. Acesse: $1"
}
EOF

# Configurar arquivo de informações do lab
cat > /home/kali/LAB_INFO.txt << EOF
═══════════════════════════════════════════════════════
🛡️  LABORATÓRIO DE CIBERSEGURANÇA - KALI + BURP SUITE
═══════════════════════════════════════════════════════

Estudante: ${STUDENT_NAME}
Laboratório: ${LAB_NAME}
Data de criação: $(date)
IP Interno: $(hostname -I | awk '{print $1}')

🖥️  ACESSO VNC:
   Endereço: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5901
   Senha: [configurada via variável vnc_password]
   Resolução: 1920x1080

🔧 SSH:
   ssh kali@$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
   Senha: [mesma do VNC]

🔥 BURP SUITE - INTERCEPTAÇÃO HTTPS:
   Proxy: $(hostname -I | awk '{print $1}'):8080
   Interface: http://$(hostname -I | awk '{print $1}'):8080
   CA Certificate: http://$(hostname -I | awk '{print $1}'):8080/cert

📁 DIRETÓRIOS:
   ~/pentest-lab/              - Workspace principal
   ~/pentest-lab/burp-projects/ - Projetos Burp Suite
   ~/pentest-lab/certificates/ - Certificados SSL/CA
   ~/pentest-lab/intercepted-traffic/ - Tráfego capturado
   ~/pentest-lab/reports/      - Relatórios de pentest

🛠️  FERRAMENTAS PRINCIPAIS:
   • Burp Suite Community - Interceptação HTTPS
   • Firefox (perfil pentest) - Browser configurado
   • OWASP ZAP - Scanner alternativo
   • Nmap, SQLMap, Gobuster - Ferramentas essenciais

🎯 ALVOS DO LABORATÓRIO:
   Target IP: ${TARGET_IP}
   HTTP: http://${TARGET_IP}:3000
   HTTPS: https://${TARGET_IP}:3443

🔒 CONFIGURAÇÃO HTTPS INTERCEPT:

1. INICIAR BURP SUITE:
   burp-start                  # Inicia Burp + instala CA

2. CONFIGURAR BROWSER:
   firefox-pentest            # Firefox com proxy configurado
   # OU configure manualmente: Proxy 127.0.0.1:8080

3. INTERCEPTAR TRÁFEGO:
   target ${TARGET_IP}         # Define alvo
   burp-intercept https://${TARGET_IP}:3443

4. VERIFICAR CERTIFICADO:
   # Acesse https://target e aceite certificado Burp
   # Verifique se tráfego aparece no Burp

🔧 COMANDOS ÚTEIS:
   burp-start               - Iniciar Burp Suite + CA
   target <IP>              - Definir IP do alvo
   scan-target <IP>         - Scan rápido com nmap
   install-ca               - Instalar certificado CA
   firefox-pentest          - Firefox configurado
   lab                      - Ir para workspace

🌐 INTERCEPTAÇÃO HTTPS WORKFLOW:

1. Execute: burp-start
2. Aguarde Burp Suite abrir
3. Configure Intercept ON
4. Abra firefox-pentest
5. Navegue para https://${TARGET_IP}:3443
6. Aceite certificado do Burp
7. Veja requisições interceptadas no Burp
8. Use Repeater, Intruder, Scanner

⚠️  IMPORTANTE:
   - Certificados são auto-assinados (aceite warnings)
   - Tráfego HTTPS é descriptografado pelo Burp
   - Use apenas para fins educacionais
   - Documente descobertas em ~/pentest-lab/reports/

💡 DICAS BURP SUITE:
   - Target > Site map: mapeamento automático
   - Proxy > History: histórico de requisições
   - Repeater: modificar e reenviar requests
   - Intruder: ataques automatizados
   - Scanner: detecção de vulnerabilidades

═══════════════════════════════════════════════════════
EOF

chown kali:kali /home/kali/LAB_INFO.txt

# Criar script de status especializado para Burp Suite
cat > /home/kali/lab-status.sh << 'EOF'
#!/bin/bash
echo "🔍 STATUS DO LABORATÓRIO - BURP SUITE HTTPS INTERCEPT"
echo "====================================================="
echo ""
echo "💻 Sistema:"
echo "   Uptime: $(uptime -p)"
echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "   Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "   Disk: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" usado)"}')"
echo ""
echo "🌐 Rede:"
echo "   IP Público: $(curl -s --max-time 5 ipinfo.io/ip || echo 'N/A')"
echo "   IP Privado: $(hostname -I | awk '{print $1}')"
echo ""
echo "🛠️  Serviços:"
echo "   VNC: $(systemctl is-active vncserver@1 2>/dev/null || echo 'inactive')"
echo "   Burp Suite: $(pgrep -f burpsuite > /dev/null && echo 'active' || echo 'inactive')"
echo "   PostgreSQL: $(systemctl is-active postgresql)"
echo ""
echo "🔥 Burp Suite Status:"
if netstat -tnl | grep -q ":8080 "; then
    echo "   ✅ Proxy ativo na porta 8080"
    echo "   🌐 Interface: http://$(hostname -I | awk '{print $1}'):8080"
    echo "   🔒 CA Cert: http://$(hostname -I | awk '{print $1}'):8080/cert"
else
    echo "   ❌ Proxy não está ativo"
    echo "   💡 Execute: burp-start"
fi
echo ""
echo "🔒 Certificados SSL:"
if [ -f /usr/local/share/ca-certificates/burp-ca.crt ]; then
    echo "   ✅ CA do Burp instalado no sistema"
else
    echo "   ❌ CA do Burp não instalado"
    echo "   💡 Execute: install-ca"
fi
echo ""
echo "🎯 Target Configurado:"
if [ -f ~/pentest-lab/current-target.txt ]; then
    TARGET_IP=$(cat ~/pentest-lab/current-target.txt | cut -d' ' -f3)
    echo "   🎯 Target: $TARGET_IP"
    echo "   🌐 HTTP: http://$TARGET_IP:3000"
    echo "   🔒 HTTPS: https://$TARGET_IP:3443"
    
    # Testar conectividade
    if curl -s --max-time 3 http://$TARGET_IP:3000 > /dev/null; then
        echo "   ✅ HTTP acessível"
    else
        echo "   ❌ HTTP não acessível"
    fi
    
    if curl -s --max-time 3 -k https://$TARGET_IP:3443 > /dev/null; then
        echo "   ✅ HTTPS acessível"
    else
        echo "   ❌ HTTPS não acessível"
    fi
else
    echo "   ❌ Nenhum target definido"
    echo "   💡 Execute: target <IP_DO_TARGET>"
fi
echo ""
echo "🌐 Proxy Configuration:"
if [ "$http_proxy" = "http://127.0.0.1:8080" ]; then
    echo "   ✅ Variáveis de proxy configuradas"
else
    echo "   ❌ Variáveis de proxy não configuradas"
    echo "   💡 Execute: burp-intercept <target_url>"
fi
echo ""
echo "🔧 Comandos Rápidos:"
echo "   burp-start              # Iniciar Burp + certificados"
echo "   target <IP>             # Definir alvo"
echo "   firefox-pentest         # Browser configurado"
echo "   scan-target <IP>        # Scan com nmap"
echo "   install-ca              # Instalar certificado CA"
EOF

chmod +x /home/kali/lab-status.sh
chown kali:kali /home/kali/lab-status.sh

# Configurar desktop environment com ícones para Burp Suite
log "🖼️ Configurando ambiente desktop com Burp Suite..."
sudo -u kali mkdir -p /home/kali/.config/xfce4/xfconf/xfce-perchannel-xml
sudo -u kali mkdir -p /home/kali/Desktop

# Criar atalhos no desktop
cat > /home/kali/Desktop/Burp_Suite.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Burp Suite
Comment=Web Application Security Testing - HTTPS Intercept
Exec=sh -c 'cd /opt && java -Xmx2g -jar burpsuite_community.jar'
Icon=/opt/burp-icon.png
Terminal=false
Categories=Network;Security;
StartupNotify=true
EOF

cat > /home/kali/Desktop/Firefox_Pentest.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Firefox Pentest
Comment=Firefox configurado para Burp Suite
Exec=firefox -P pentest
Icon=firefox
Terminal=false
Categories=Network;WebBrowser;
EOF

cat > /home/kali/Desktop/Lab_Status_Burp.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Lab Status Burp
Comment=Status do Laboratório Burp Suite
Exec=xfce4-terminal -e "/home/kali/lab-status.sh; read -p 'Pressione Enter para continuar...'"
Icon=utilities-system-monitor
Terminal=false
Categories=Utility;
EOF

cat > /home/kali/Desktop/Install_Burp_CA.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Install Burp CA
Comment=Instalar Certificado CA do Burp Suite
Exec=xfce4-terminal -e "/home/kali/install-burp-ca.sh; read -p 'Pressione Enter para continuar...'"
Icon=certificate-manager
Terminal=false
Categories=Security;
EOF

chmod +x /home/kali/Desktop/*.desktop
chown kali:kali /home/kali/Desktop/*.desktop

# Baixar ícone para Burp Suite
wget -O /opt/burp-icon.png "https://portswigger.net/content/images/logos/burp-suite-professional.svg" 2>/dev/null || echo "# Ícone do Burp não disponível"

# Configurar firewall local
log "🔥 Configurando firewall para Burp Suite..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 5901/tcp comment 'VNC'
ufw allow 8080/tcp comment 'Burp Suite Proxy'
ufw allow 8081/tcp comment 'Burp Collaborator'

# Criar script para configuração automática do Burp ao iniciar
cat > /home/kali/auto-setup-burp.sh << 'EOF'
#!/bin/bash
echo "🔄 Configuração automática do Burp Suite..."

# Aguardar sistema estar pronto
sleep 30

# Iniciar Burp Suite em background
echo "🔥 Iniciando Burp Suite..."
cd /opt && java -Xmx2g -jar burpsuite_community.jar &
BURP_PID=$!

# Aguardar Burp estar online
echo "⏳ Aguardando Burp Suite inicializar..."
timeout=60
while [ $timeout -gt 0 ] && ! netstat -tnl | grep -q ":8080 "; do
    sleep 2
    timeout=$((timeout-2))
done

if netstat -tnl | grep -q ":8080 "; then
    echo "✅ Burp Suite iniciado com sucesso!"
    
    # Instalar certificado CA
    sleep 5
    echo "🔒 Instalando certificado CA..."
    /home/kali/install-burp-ca.sh
    
    # Criar perfil Firefox
    echo "🌐 Configurando Firefox..."
    /home/kali/create-firefox-profile.sh
    
    echo "🎉 Setup automático concluído!"
    echo "✅ Burp Suite: http://$(hostname -I | awk '{print $1}'):8080"
    echo "✅ Certificado CA instalado"
    echo "✅ Firefox configurado"
else
    echo "❌ Falha na inicialização do Burp Suite"
    exit 1
fi
EOF

chmod +x /home/kali/auto-setup-burp.sh
chown kali:kali /home/kali/auto-setup-burp.sh

# Configurar para executar setup automático após boot
cat > /etc/systemd/system/auto-setup-burp.service << 'EOF'
[Unit]
Description=Auto setup Burp Suite for HTTPS intercept
After=graphical-session.target
Wants=graphical-session.target

[Service]
Type=oneshot
User=kali
Group=kali
Environment=DISPLAY=:1
ExecStart=/home/kali/auto-setup-burp.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable auto-setup-burp.service

# Configurar MOTD especializado para Burp Suite
cat > /etc/motd << 'EOF'

████████████████████████████████████████████████████
█                                                  █
█   🔥 KALI LINUX + BURP SUITE - HTTPS INTERCEPT   █
█                                                  █
████████████████████████████████████████████████████

🎯 Laboratório configurado para interceptação HTTPS!

🔥 Burp Suite: Proxy em <IP_KALI>:8080
🌐 Acesso VNC: <IP_PÚBLICO>:5901
🔒 CA Certificate: http://<IP_KALI>:8080/cert

📚 Comandos essenciais:
   cat LAB_INFO.txt         - Informações completas
   ./lab-status.sh          - Status Burp Suite
   burp-start               - Iniciar Burp + CA
   firefox-pentest          - Browser configurado

🎯 Workflow HTTPS Intercept:
   1. burp-start           2. firefox-pentest
   3. target <IP>          4. Interceptar HTTPS!

════════════════════════════════════════════════════
EOF

# Iniciar VNC
systemctl start vncserver@1

# Verificações finais específicas para Burp Suite
log "🔍 Executando verificações finais para Burp Suite..."

# Verificar VNC
sleep 5
if systemctl is-active --quiet vncserver@1; then
    log "✅ VNC Server está ativo na porta 5901"
else
    error "❌ Problema com VNC Server"
    systemctl status vncserver@1
fi

# Verificar Java
if java -version 2>&1 | grep -q "17"; then
    log "✅ Java 17 configurado para Burp Suite"
else
    warning "⚠️ Java pode não estar corretamente configurado"
fi

# Verificar Burp Suite
if [ -f /opt/burpsuite_community.jar ]; then
    log "✅ Burp Suite Community baixado"
else
    error "❌ Problema no download do Burp Suite"
fi

# Verificar ferramentas principais
for tool in nmap firefox chromium; do
    if command -v $tool >/dev/null 2>&1; then
        log "✅ $tool instalado"
    else
        warning "⚠️ $tool não encontrado"
    fi
done

# Informações finais
log "🎉 Configuração do Kali Linux + Burp Suite concluída!"
log "📍 Informações importantes:"
log "   - VNC: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5901"
log "   - SSH: kali@$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
log "   - Burp Proxy: $(hostname -I | awk '{print $1}'):8080"
log "   - Senha VNC: [configurada via vnc_password]"
log "   - Workspace: /home/kali/pentest-lab/"
log ""
log "🔥 PRÓXIMOS PASSOS:"
log "   1. Conecte via VNC"
log "   2. Execute: burp-start"
log "   3. Configure target com IP do alvo"
log "   4. Use firefox-pentest para navegar"
log "   5. Intercete tráfego HTTPS no Burp Suite!"

exit 0#!/bin/bash
# =============================================================================
# KALI_SETUP.SH - Configuração automática do Kali Linux para pentest
# Executado na inicialização da instância EC2
# =============================================================================

set -e
exec > >(tee /var/log/kali-setup.log) 2>&1

# Variáveis do template
STUDENT_NAME="${student_name}"
VNC_PASSWORD="${vnc_password}"
LAB_NAME="${lab_name}"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "$${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1$${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

log "🚀 Iniciando configuração do Kali Linux para ${STUDENT_NAME}"
log "📝 Laboratório: ${LAB_NAME}"

# Atualizar repositórios e sistema
log "📦 Atualizando sistema Kali Linux..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get dist-upgrade -y

# Instalar dependências essenciais
log "🔧 Instalando dependências essenciais..."
apt-get install -y \
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    tree \
    unzip \
    zip \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    default-jdk \
    firefox-esr \
    chromium

# Configurar interface gráfica e VNC
log "🖥️ Configurando interface gráfica XFCE..."
apt-get install -y kali-desktop-xfce

# Instalar e configurar VNC
log "🔗 Configurando VNC Server..."
apt-get install -y tightvncserver xfce4 xfce4-goodies

# Criar usuário kali se não existir
if ! id "kali" &>/dev/null; then
    log "👤 Criando usuário kali..."
    useradd -m -s /bin/bash kali
    echo "kali:${VNC_PASSWORD}" | chpasswd
    usermod -aG sudo kali
else
    log "✅ Usuário kali já existe"
    echo "kali:${VNC_PASSWORD}" | chpasswd
fi

# Configurar VNC para usuário kali
log "🔧 Configurando VNC para usuário kali..."
sudo -u kali mkdir -p /home/kali/.vnc

# Configurar senha VNC
echo "${VNC_PASSWORD}" | sudo -u kali vncpasswd -f > /home/kali/.vnc/passwd
chmod 600 /home/kali/.vnc/passwd
chown kali:kali /home/kali/.vnc/passwd

# Criar script de inicialização VNC
cat > /home/kali/.vnc/xstartup << 'EOF'
#!/bin/bash
xrdb $HOME/.Xresources
startxfce4 &
EOF

chmod +x /home/kali/.vnc/xstartup
chown kali:kali /home/kali/.vnc/xstartup

# Configurar serviço VNC
cat > /etc/systemd/system/vncserver@.service << 'EOF'
[Unit]
Description=Start TightVNC server at startup
After=syslog.target network.target

[Service]
Type=forking
User=kali
Group=kali
WorkingDirectory=/home/kali

PIDFile=/home/kali/.vnc/%H:%i.pid
ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver -depth 24 -geometry 1280x1024 :%i
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar VNC
systemctl daemon-reload
systemctl enable vncserver@1.service
systemctl start vncserver@1.service

# Instalar ferramentas de pentest adicionais
log "🛠️ Instalando ferramentas de pentest..."

# Ferramentas web essenciais
apt-get install -y \
    burpsuite \
    zaproxy \
    nikto \
    dirb \
    gobuster \
    wfuzz \
    sqlmap \
    commix \
    whatweb \
    wafw00f

# Ferramentas de rede
apt-get install -y \
    nmap \
    masscan \
    zmap \
    netcat-traditional \
    socat \
    tcpdump \
    wireshark \
    ettercap-text-only \
    responder

# Ferramentas de exploração
apt-get install -y \
    metasploit-framework \
    armitage \
    exploitdb \
    searchsploit \
    social-engineer-toolkit \
    beef-xss

# Ferramentas de análise
apt-get install -y \
    binwalk \
    foremost \
    volatility3 \
    autopsy \
    sleuthkit \
    hashcat \
    john \
    hydra \
    medusa \
    patator

# Ferramentas de desenvolvimento
apt-get install -y \
    gcc \
    g++ \
    make \
    cmake \
    gdb \
    radare2 \
    ghidra \
    binutils \
    strace \
    ltrace

# Instalar ferramentas Python específicas
log "🐍 Instalando ferramentas Python..."
sudo -u kali python3 -m pip install --user \
    requests \
    beautifulsoup4 \
    selenium \
    scapy \
    pycrypto \
    paramiko \
    impacket \
    bloodhound \
    mitm6 \
    crackmapexec

# Configurar Metasploit
log "🎯 Configurando Metasploit..."
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres createuser msf
sudo -u postgres createdb msf_database -O msf
sudo -u postgres psql -c "ALTER USER msf WITH PASSWORD 'msf_password';"

# Inicializar banco do Metasploit
sudo -u kali msfdb init

# Configurar BeEF
log "🥩 Configurando BeEF XSS Framework..."
systemctl enable beef-xss
systemctl start beef-xss

# Instalar ferramentas adicionais via Git
log "📥 Instalando ferramentas do GitHub..."
cd /opt

# SecLists
git clone https://github.com/danielmiessler/SecLists.git
chown -R kali:kali SecLists

# PayloadsAllTheThings
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
chown -R kali:kali PayloadsAllTheThings

# LinEnum
git clone https://github.com/rebootuser/LinEnum.git
chown -R kali:kali LinEnum

# Windows Exploit Suggester
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
chown -R kali:kali Windows-Exploit-Suggester

# PEASS - Privilege Escalation Awesome Scripts
git clone https://github.com/carlospolop/PEASS-ng.git
chown -R kali:kali PEASS-ng

# Impacket (versão mais recente)
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket
sudo -u kali python3 -m pip install --user .
cd /opt

# PowerSploit
git clone https://github.com/PowerShellMafia/PowerSploit.git
chown -R kali:kali PowerSploit

# Configurar diretório de trabalho do estudante
log "📁 Configurando diretório de trabalho..."
sudo -u kali mkdir -p /home/kali/pentest-lab
sudo -u kali mkdir -p /home/kali/pentest-lab/tools
sudo -u kali mkdir -p /home/kali/pentest-lab/wordlists
sudo -u kali mkdir -p /home/kali/pentest-lab/exploits
sudo -u kali mkdir -p /home/kali/pentest-lab/reports
sudo -u kali mkdir -p /home/kali/pentest-lab/scripts

# Criar links simbólicos para ferramentas
sudo -u kali ln -s /opt/SecLists /home/kali/pentest-lab/wordlists/SecLists
sudo -u kali ln -s /opt/PayloadsAllTheThings /home/kali/pentest-lab/exploits/PayloadsAllTheThings
sudo -u kali ln -s /usr/share/wordlists /home/kali/pentest-lab/wordlists/system

# Configurar aliases úteis
cat >> /home/kali/.bashrc << 'EOF'

# Aliases para pentest
alias ll='ls -la'
alias la='ls -A'
alias l='ls -CF'
alias lab='cd ~/pentest-lab'
alias tools='cd ~/pentest-lab/tools'
alias wordlists='cd ~/pentest-lab/wordlists'
alias reports='cd ~/pentest-lab/reports'

# Aliases para ferramentas comuns
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias searchsploit='searchsploit --color'
alias msfconsole='msfconsole -q'

# Funções úteis
function target() {
    echo "Target IP: $1" > ~/pentest-lab/current-target.txt
    export TARGET_IP=$1
    echo "Target set to: $1"
}

function scan_quick() {
    if [ -z "$1" ]; then
        echo "Usage: scan_quick <target_ip>"
        return 1
    fi
    nmap -sC -sV -oN ~/pentest-lab/reports/quick-scan-$1.txt $1
}

function scan_full() {
    if [ -z "$1" ]; then
        echo "Usage: scan_full <target_ip>"
        return 1
    fi
    nmap -sC -sV -p- -oN ~/pentest-lab/reports/full-scan-$1.txt $1
}
EOF

# Configurar arquivo de boas-vindas
cat > /home/kali/LAB_INFO.txt << EOF
═══════════════════════════════════════════════════════
🛡️  LABORATÓRIO DE CIBERSEGURANÇA - KALI LINUX
═══════════════════════════════════════════════════════

Estudante: ${STUDENT_NAME}
Laboratório: ${LAB_NAME}
Data de criação: $(date)
IP Interno: $(hostname -I | awk '{print $1}')

🖥️  ACESSO VNC:
   Endereço: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5901
   Senha: [configurada via variável vnc_password]
   Resolução: 1280x1024

🔧 SSH:
   ssh kali@$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
   Senha: [mesma do VNC]

📁 DIRETÓRIOS:
   ~/pentest-lab/          - Diretório principal de trabalho
   ~/pentest-lab/tools/    - Ferramentas personalizadas
   ~/pentest-lab/wordlists/ - Wordlists e dicionários
   ~/pentest-lab/exploits/ - Exploits e payloads
   ~/pentest-lab/reports/  - Relatórios de pentest

🛠️  FERRAMENTAS INSTALADAS:
   • Web: Burp Suite, OWASP ZAP, Nikto, SQLMap
   • Rede: Nmap, Masscan, Wireshark, Ettercap
   • Exploit: Metasploit, SearchSploit, BeEF
   • Crack: Hashcat, John, Hydra
   • Forense: Volatility, Autopsy, Binwalk

🎯 COMANDOS ÚTEIS:
   target <IP>           - Definir IP do alvo
   scan_quick <IP>       - Scan rápido com nmap
   scan_full <IP>        - Scan completo de portas
   lab                   - Ir para diretório do lab
   msfconsole            - Iniciar Metasploit

🌐 ALVOS DO LABORATÓRIO:
   Execute 'terraform output' para ver IPs dos alvos

⚠️  IMPORTANTE:
   - Use apenas para fins educacionais
   - Respeite as regras do laboratório
   - Documente suas descobertas em ~/pentest-lab/reports/

═══════════════════════════════════════════════════════
EOF

chown kali:kali /home/kali/LAB_INFO.txt

# Criar script de status do laboratório
cat > /home/kali/lab-status.sh << 'EOF'
#!/bin/bash
echo "🔍 STATUS DO LABORATÓRIO"
echo "========================"
echo ""
echo "💻 Sistema:"
echo "   Uptime: $(uptime -p)"
echo "   Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "   Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "   Disk: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" usado)"}')"
echo ""
echo "🌐 Rede:"
echo "   IP Público: $(curl -s --max-time 5 ipinfo.io/ip || echo 'N/A')"
echo "   IP Privado: $(hostname -I | awk '{print $1}')"
echo ""
echo "🛠️  Serviços:"
echo "   VNC: $(systemctl is-active vncserver@1 2>/dev/null || echo 'inactive')"
echo "   PostgreSQL: $(systemctl is-active postgresql)"
echo "   BeEF: $(systemctl is-active beef-xss 2>/dev/null || echo 'inactive')"
echo ""
echo "🎯 Ferramentas Principais:"
which msfconsole >/dev/null && echo "   ✅ Metasploit" || echo "   ❌ Metasploit"
which burpsuite >/dev/null && echo "   ✅ Burp Suite" || echo "   ❌ Burp Suite"
which nmap >/dev/null && echo "   ✅ Nmap" || echo "   ❌ Nmap"
which sqlmap >/dev/null && echo "   ✅ SQLMap" || echo "   ❌ SQLMap"
echo ""
if [ -f ~/pentest-lab/current-target.txt ]; then
    echo "🎯 Alvo Atual:"
    cat ~/pentest-lab/current-target.txt
else
    echo "🎯 Nenhum alvo definido (use: target <IP>)"
fi
EOF

chmod +x /home/kali/lab-status.sh
chown kali:kali /home/kali/lab-status.sh

# Configurar desktop environment
log "🖼️ Configurando ambiente desktop..."
sudo -u kali mkdir -p /home/kali/.config/xfce4/xfconf/xfce-perchannel-xml
sudo -u kali mkdir -p /home/kali/Desktop

# Criar atalhos no desktop
cat > /home/kali/Desktop/Lab_Info.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Lab Info
Comment=Informações do Laboratório
Exec=xfce4-terminal -e "cat /home/kali/LAB_INFO.txt; read -p 'Pressione Enter para continuar...'"
Icon=utilities-terminal
Terminal=false
Categories=Utility;
EOF

cat > /home/kali/Desktop/Lab_Status.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Lab Status
Comment=Status do Laboratório
Exec=xfce4-terminal -e "/home/kali/lab-status.sh; read -p 'Pressione Enter para continuar...'"
Icon=utilities-system-monitor
Terminal=false
Categories=Utility;
EOF

cat > /home/kali/Desktop/Burp_Suite.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Burp Suite
Comment=Web Application Security Testing
Exec=burpsuite
Icon=burpsuite
Terminal=false
Categories=Network;Security;
EOF

cat > /home/kali/Desktop/Metasploit.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Type=Application
Name=Metasploit
Comment=Penetration Testing Framework
Exec=xfce4-terminal -e "msfconsole"
Icon=utilities-terminal
Terminal=false
Categories=Network;Security;
EOF

chmod +x /home/kali/Desktop/*.desktop
chown kali:kali /home/kali/Desktop/*.desktop

# Configurar firewall local
log "🔥 Configurando firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 5901/tcp comment 'VNC'

# Configurar MOTD
cat > /etc/motd << 'EOF'

████████████████████████████████████████████████████
█                                                  █
█      🛡️  KALI LINUX - LABORATÓRIO DE PENTEST     █
█                                                  █
████████████████████████████████████████████████████

🎯 Bem-vindo ao ambiente de aprendizado de cibersegurança!

📚 Execute os seguintes comandos para começar:
   cat LAB_INFO.txt     - Informações do laboratório
   ./lab-status.sh      - Status atual do sistema
   lab                  - Ir para diretório de trabalho

🔧 Acesso remoto:
   VNC: <IP_PÚBLICO>:5901
   SSH: ssh kali@<IP_PÚBLICO>

════════════════════════════════════════════════════
EOF

# Configurar logs
log "📊 Configurando logs..."
mkdir -p /var/log/pentest
chown kali:kali /var/log/pentest

# Script de limpeza para fim de sessão
cat > /home/kali/cleanup-lab.sh << 'EOF'
#!/bin/bash
echo "🧹 Limpando laboratório..."

# Limpar históricos sensíveis
history -c
rm -f ~/.bash_history

# Backup de relatórios importantes
if [ -d ~/pentest-lab/reports ]; then
    tar -czf ~/lab-backup-$(date +%Y%m%d).tar.gz ~/pentest-lab/reports/
    echo "✅ Backup dos relatórios criado: ~/lab-backup-$(date +%Y%m%d).tar.gz"
fi

# Parar serviços
sudo systemctl stop beef-xss 2>/dev/null
sudo systemctl stop postgresql

echo "✅ Limpeza concluída!"
EOF

chmod +x /home/kali/cleanup-lab.sh
chown kali:kali /home/kali/cleanup-lab.sh

# Verificações finais
log "🔍 Executando verificações finais..."

# Verificar VNC
sleep 5
if systemctl is-active --quiet vncserver@1; then
    log "✅ VNC Server está ativo"
else
    error "❌ Problema com VNC Server"
    systemctl status vncserver@1
fi

# Verificar PostgreSQL
if systemctl is-active --quiet postgresql; then
    log "✅ PostgreSQL está ativo"
else
    warning "⚠️ PostgreSQL não está ativo"
fi

# Verificar ferramentas principais
for tool in nmap burpsuite msfconsole sqlmap; do
    if command -v $tool >/dev/null 2>&1; then
        log "✅ $tool instalado"
    else
        warning "⚠️ $tool não encontrado"
    fi
done

# Informações finais
log "🎉 Configuração do Kali Linux concluída!"
log "📍 Informações importantes:"
log "   - VNC: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5901"
log "   - SSH: kali@$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
log "   - Senha: [configurada via vnc_password]"
log "   - Workspace: /home/kali/pentest-lab/"

# Restart VNC para garantir funcionamento
systemctl restart vncserver@1

exit 0