#!/bin/bash
# Script de configuração da instância atacante (Kali Linux)
# setup_attacker.sh

set -e

# Variáveis
LAB_NAME="${lab_name}"
TARGET_IP="${target_ip}"
LOG_FILE="/var/log/attacker-setup.log"
MAIN_USER="ubuntu"

# Função de log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log "=== CONFIGURANDO INSTÂNCIA ATACANTE (KALI TOOLS) ==="
log "Alvo configurado: $TARGET_IP"

# Atualizar sistema
log "Atualizando sistema Ubuntu..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Instalar dependências básicas
log "Instalando dependências básicas..."
apt-get install -y \
    curl \
    wget \
    git \
    vim \
    htop \
    tree \
    unzip \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    xfce4 \
    xfce4-goodies \
    tightvncserver \
    xrdp \
    firefox \
    chromium-browser \
    openjdk-11-jdk \
    python3 \
    python3-pip \
    build-essential \
    postgresql \
    postgresql-contrib \
    net-tools \
    dnsutils

# Instalar todas as ferramentas de pentesting do Kali
log "Instalando arsenal completo de ferramentas de pentesting..."
apt-get install -y \
    nmap \
    masscan \
    rustscan \
    nikto \
    dirb \
    gobuster \
    dirbuster \
    wfuzz \
    ffuf \
    sqlmap \
    hydra \
    medusa \
    john \
    hashcat \
    aircrack-ng \
    wireshark \
    tshark \
    tcpdump \
    netcat-traditional \
    socat \
    proxychains4 \
    tor \
    whatweb \
    wpscan \
    dmitry \
    dnsrecon \
    dnsenum \
    fierce \
    theharvester \
    recon-ng \
    maltego \
    beef-xss \
    zaproxy \
    burpsuite \
    exploitdb \
    searchsploit

# Configurar usuário
log "Configurando usuário $MAIN_USER..."
usermod -aG sudo $MAIN_USER
echo "$MAIN_USER:cybersec2024" | chpasswd

# Instalar Metasploit Framework
log "Instalando Metasploit Framework..."
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
chmod 755 /tmp/msfinstall
/tmp/msfinstall

# Instalar Docker para ferramentas adicionais
log "Instalando Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable docker
systemctl start docker
usermod -aG docker $MAIN_USER

# Instalar Node.js para ferramentas JavaScript
log "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Baixar e configurar Burp Suite Community
log "Configurando Burp Suite Community..."
cd /opt
wget -O burpsuite_community.jar "https://portswigger.net/burp/releases/download?product=community&type=jar"
chown $MAIN_USER:$MAIN_USER burpsuite_community.jar

# Criar script para executar Burp Suite
cat > /usr/local/bin/burpsuite << 'EOF'
#!/bin/bash
cd /opt
java -jar burpsuite_community.jar "$@"
EOF
chmod +x /usr/local/bin/burpsuite

# Configurar VNC Server
log "Configurando VNC Server..."
sudo -u $MAIN_USER mkdir -p /home/$MAIN_USER/.vnc
sudo -u $MAIN_USER bash -c 'echo "vncpassword" | vncpasswd -f > /home/'$MAIN_USER'/.vnc/passwd'
chmod 600 /home/$MAIN_USER/.vnc/passwd
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/.vnc/passwd

# Criar configuração do VNC
cat > /home/$MAIN_USER/.vnc/xstartup << 'EOF'
#!/bin/bash
xrdb $HOME/.Xresources
startxfce4 &
EOF
chmod +x /home/$MAIN_USER/.vnc/xstartup
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/.vnc/xstartup

# Criar serviço systemd para VNC
cat > /etc/systemd/system/vncserver@.service << EOF
[Unit]
Description=Start TightVNC server at startup
After=syslog.target network.target

[Service]
Type=forking
User=$MAIN_USER
Group=$MAIN_USER
WorkingDirectory=/home/$MAIN_USER

PIDFile=/home/$MAIN_USER/.vnc/%H:%i.pid
ExecStartPre=-/usr/bin/vncserver -kill :%i > /dev/null 2>&1
ExecStart=/usr/bin/vncserver -depth 24 -geometry 1440x900 :%i
ExecStop=/usr/bin/vncserver -kill :%i

[Install]
WantedBy=multi-user.target
EOF

# Habilitar e iniciar VNC
systemctl daemon-reload
systemctl enable vncserver@1.service
systemctl start vncserver@1.service

# Configurar XRDP
log "Configurando XRDP..."
systemctl enable xrdp
systemctl start xrdp
adduser xrdp ssl-cert

# Configurar PostgreSQL para Metasploit
log "Configurando PostgreSQL e Metasploit..."
systemctl start postgresql
systemctl enable postgresql
sudo -u $MAIN_USER msfdb init

# Instalar ferramentas Python adicionais
log "Instalando ferramentas Python..."
pip3 install \
    requests \
    beautifulsoup4 \
    selenium \
    scapy \
    impacket \
    pycryptodome \
    netaddr \
    dnspython

# Baixar wordlists populares
log "Baixando wordlists..."
mkdir -p /usr/share/wordlists
cd /usr/share/wordlists
wget -O rockyou.txt.gz https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
gunzip rockyou.txt.gz 2>/dev/null || true
wget -O dirb_common.txt https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt
chown -R $MAIN_USER:$MAIN_USER /usr/share/wordlists

# Criar desktop shortcuts
log "Criando atalhos no desktop..."
sudo -u $MAIN_USER mkdir -p /home/$MAIN_USER/Desktop

# Atalho para Burp Suite
cat > /home/$MAIN_USER/Desktop/BurpSuite.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Name=Burp Suite Community
Comment=Web Application Security Testing
Exec=burpsuite
Icon=applications-internet
Terminal=false
Type=Application
Categories=Network;Security;
EOF

# Atalho para Metasploit
cat > /home/$MAIN_USER/Desktop/Metasploit.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Name=Metasploit Framework
Comment=Penetration Testing Framework
Exec=gnome-terminal -- msfconsole
Icon=applications-accessories
Terminal=true
Type=Application
Categories=Network;Security;
EOF

# Atalho para Firefox com alvo
cat > /home/$MAIN_USER/Desktop/Target-JuiceShop.desktop << EOF
[Desktop Entry]
Version=1.0
Name=Target - Juice Shop
Comment=Aplicação Alvo - Juice Shop
Exec=firefox http://$TARGET_IP:3000
Icon=firefox
Terminal=false
Type=Application
Categories=Network;WebBrowser;
EOF

# Atalho para OWASP ZAP
cat > /home/$MAIN_USER/Desktop/OWASP-ZAP.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Name=OWASP ZAP
Comment=Web Application Security Scanner
Exec=zaproxy
Icon=applications-internet
Terminal=false
Type=Application
Categories=Network;Security;
EOF

# Definir permissões dos atalhos
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/*.desktop
chmod +x /home/$MAIN_USER/Desktop/*.desktop

# Criar script de reconhecimento do alvo
cat > /home/$MAIN_USER/Desktop/recon_target.sh << EOF
#!/bin/bash
echo "=== RECONHECIMENTO DO ALVO ==="
echo "Alvo: $TARGET_IP"
echo ""
echo "1. Ping test:"
ping -c 3 $TARGET_IP
echo ""
echo "2. Port scan básico:"
nmap -sV -p- $TARGET_IP
echo ""
echo "3. Verificando serviço web:"
curl -I http://$TARGET_IP:3000 2>/dev/null || echo "Serviço web não respondeu"
echo ""
echo "=== RECONHECIMENTO CONCLUÍDO ==="
EOF

chmod +x /home/$MAIN_USER/Desktop/recon_target.sh
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/recon_target.sh

# Criar arquivo README detalhado
cat > /home/$MAIN_USER/Desktop/README_ATACANTE.txt << EOF
=== INSTÂNCIA ATACANTE - LABORATÓRIO CYBERSECURITY ===

CONFIGURAÇÃO:
- Sistema: Ubuntu 22.04 + Ferramentas Kali
- Usuário: $MAIN_USER
- Senha: cybersec2024
- Alvo: $TARGET_IP (Juice Shop)

FERRAMENTAS INSTALADAS:

WEB SECURITY:
- Burp Suite Community (burpsuite)
- OWASP ZAP (zaproxy)
- Nikto (nikto)
- SQLMap (sqlmap)

NETWORK SCANNING:
- Nmap (nmap)
- Masscan (masscan)
- Rustscan (rustscan)

DIRECTORY/FILE DISCOVERY:
- Gobuster (gobuster)
- Dirb (dirb)
- FFuF (ffuf)

BRUTE FORCE:
- Hydra (hydra)
- Medusa (medusa)
- John the Ripper (john)
- Hashcat (hashcat)

FRAMEWORKS:
- Metasploit (msfconsole)
- Recon-ng (recon-ng)

NETWORK ANALYSIS:
- Wireshark (wireshark)
- Tcpdump (tcpdump)

COMANDOS ÚTEIS:
1. Reconhecimento inicial: ./recon_target.sh
2. Scan de portas: nmap -sV $TARGET_IP
3. Scan web: nikto -h http://$TARGET_IP:3000
4. Brute force dirs: gobuster dir -u http://$TARGET_IP:3000 -w /usr/share/wordlists/dirb_common.txt
5. SQLMap: sqlmap -u "http://$TARGET_IP:3000/page?param=1" --batch

ACESSO AO ALVO:
- URL: http://$TARGET_IP:3000
- O alvo está ISOLADO - apenas acessível desta instância
- Use ferramentas de proxy (Burp/ZAP) para interceptar tráfego

EXERCÍCIOS SUGERIDOS:
1. Fazer reconhecimento completo do alvo
2. Identificar vulnerabilidades no Juice Shop
3. Explorar vulnerabilidades OWASP Top 10
4. Usar Burp Suite para análise de requisições
5. Tentar SQL Injection, XSS, etc.

Para mais informações, consulte a documentação das ferramentas.
EOF

chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/README_ATACANTE.txt

# Configurar proxychains para usar com Burp/ZAP
cat > /etc/proxychains4.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
http 127.0.0.1 8080
EOF

# Configurar firewall
log "Configurando firewall..."
ufw --force enable
ufw allow ssh
ufw allow 5901/tcp
ufw allow 3389/tcp
# Permitir comunicação com subnet alvo
ufw allow from 10.0.2.0/24

# Criar script de status do lab
cat > /usr/local/bin/lab-status << EOF
#!/bin/bash
echo "=== STATUS DO LABORATÓRIO ATACANTE ==="
echo "VNC Server: \$(systemctl is-active vncserver@1)"
echo "XRDP: \$(systemctl is-active xrdp)"
echo "Docker: \$(systemctl is-active docker)"
echo "PostgreSQL: \$(systemctl is-active postgresql)"
echo ""
echo "=== CONECTIVIDADE COM ALVO ==="
echo "Alvo: $TARGET_IP"
ping -c 1 $TARGET_IP > /dev/null 2>&1 && echo "Ping: OK" || echo "Ping: FALHOU"
curl -s http://$TARGET_IP:3000 > /dev/null 2>&1 && echo "Juice Shop: OK" || echo "Juice Shop: FALHOU"
echo ""
echo "=== PORTAS LOCAIS ABERTAS ==="
netstat -tlnp | grep -E ':(22|5901|3389)\s'
EOF
chmod +x /usr/local/bin/lab-status

# Limpar cache
log "Limpando cache..."
apt-get autoremove -y
apt-get autoclean

# Configurar ambiente do usuário
sudo -u $MAIN_USER bash << 'EOF'
cd /home/ubuntu
echo 'export TARGET_IP='"$TARGET_IP" >> .bashrc
echo 'alias ll="ls -la"' >> .bashrc
echo 'alias target="firefox http://'"$TARGET_IP"':3000 &"' >> .bashrc
echo 'alias recon="./Desktop/recon_target.sh"' >> .bashrc
echo 'alias burp="burpsuite &"' >> .bashrc
echo 'alias msf="msfconsole"' >> .bashrc
EOF

log "=== CONFIGURAÇÃO DO ATACANTE CONCLUÍDA ==="
log "Reiniciando serviços..."
systemctl restart xrdp
systemctl restart vncserver@1

log "Sistema será reiniciado em 2 minutos para finalizar configuração..."
shutdown -r +2 "Reiniciando para finalizar configuração do laboratório."