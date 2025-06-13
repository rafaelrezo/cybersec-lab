#!/bin/bash
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