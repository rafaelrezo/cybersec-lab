#!/bin/bash
# Script de configuração do laboratório de cybersecurity
# setup_lab.sh

set -e

# Variáveis
LAB_NAME="${lab_name}"
LOG_FILE="/var/log/cybersec-lab-setup.log"

# Função de log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log "Iniciando configuração do laboratório de cybersecurity..."

# Atualizar sistema
log "Atualizando sistema..."
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
    firefox-esr \
    chromium \
    openjdk-11-jdk

# Configurar usuário kali
log "Configurando usuário kali..."
usermod -aG sudo kali
echo "kali:kali2024" | chpasswd

# Instalar Docker
log "Instalando Docker..."
curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable docker
systemctl start docker
usermod -aG docker kali

# Instalar Node.js e npm
log "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Baixar e configurar Burp Suite Community
log "Configurando Burp Suite..."
cd /opt
wget -O burpsuite_community.jar "https://portswigger.net/burp/releases/download?product=community&type=jar"
chown kali:kali burpsuite_community.jar

# Criar script para executar Burp Suite
cat > /usr/local/bin/burpsuite << 'EOF'
#!/bin/bash
cd /opt
java -jar burpsuite_community.jar "$@"
EOF
chmod +x /usr/local/bin/burpsuite

# Configurar OWASP Juice Shop com Docker
log "Configurando OWASP Juice Shop..."
docker pull bkimminich/juice-shop

# Criar script para iniciar Juice Shop
cat > /usr/local/bin/start-juiceshop << 'EOF'
#!/bin/bash
docker run -d --name juice-shop -p 3000:3000 --restart unless-stopped bkimminich/juice-shop
EOF
chmod +x /usr/local/bin/start-juiceshop

# Iniciar Juice Shop
/usr/local/bin/start-juiceshop

# Configurar VNC Server
log "Configurando VNC Server..."
sudo -u kali mkdir -p /home/kali/.vnc
sudo -u kali bash -c 'echo "vncpassword" | vncpasswd -f > /home/kali/.vnc/passwd'
chmod 600 /home/kali/.vnc/passwd
chown kali:kali /home/kali/.vnc/passwd

# Criar configuração do VNC
cat > /home/kali/.vnc/xstartup << 'EOF'
#!/bin/bash
xrdb $HOME/.Xresources
startxfce4 &
EOF
chmod +x /home/kali/.vnc/xstartup
chown kali:kali /home/kali/.vnc/xstartup

# Criar serviço systemd para VNC
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
ExecStart=/usr/bin/vncserver -depth 24 -geometry 1280x800 :%i
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

# Adicionar kali ao grupo ssl-cert para XRDP
adduser xrdp ssl-cert

# Instalar ferramentas adicionais de pentesting
log "Instalando ferramentas adicionais..."
apt-get install -y \
    nmap \
    nikto \
    sqlmap \
    gobuster \
    dirb \
    hydra \
    john \
    hashcat \
    metasploit-framework \
    wireshark \
    tcpdump \
    netcat-traditional \
    socat \
    proxychains4

# Configurar Metasploit
log "Configurando Metasploit..."
systemctl start postgresql
systemctl enable postgresql
msfdb init

# Criar desktop shortcuts
log "Criando atalhos no desktop..."
sudo -u kali mkdir -p /home/kali/Desktop

# Atalho para Burp Suite
cat > /home/kali/Desktop/BurpSuite.desktop << 'EOF'
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

# Atalho para Firefox com Juice Shop
cat > /home/kali/Desktop/JuiceShop.desktop << 'EOF'
[Desktop Entry]
Version=1.0
Name=OWASP Juice Shop
Comment=Vulnerable Web Application
Exec=firefox-esr http://localhost:3000
Icon=firefox-esr
Terminal=false
Type=Application
Categories=Network;WebBrowser;
EOF

# Atalho para Metasploit
cat > /home/kali/Desktop/Metasploit.desktop << 'EOF'
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

# Definir permissões dos atalhos
chown kali:kali /home/kali/Desktop/*.desktop
chmod +x /home/kali/Desktop/*.desktop

# Criar arquivo README no desktop
cat > /home/kali/Desktop/README.txt << 'EOF'
=== LABORATÓRIO DE CYBERSECURITY ===

Bem-vindo ao laboratório de cybersecurity!

FERRAMENTAS INSTALADAS:
- Kali Linux (sistema base)
- OWASP Juice Shop (aplicação vulnerável)
- Burp Suite Community (proxy para testes web)
- Metasploit Framework (framework de pentesting)
- Ferramentas de rede: nmap, nikto, sqlmap, etc.

ACESSOS:
- OWASP Juice Shop: http://localhost:3000
- Burp Suite: Execute o atalho no desktop
- VNC: porta 5901 (senha: vncpassword)
- RDP: porta 3389 (usuário: kali, senha: kali2024)

COMANDOS ÚTEIS:
- Iniciar Juice Shop: start-juiceshop
- Executar Burp Suite: burpsuite
- Metasploit Console: msfconsole

Para mais informações, consulte a documentação das ferramentas.
EOF

chown kali:kali /home/kali/Desktop/README.txt

# Configurar firewall básico
log "Configurando firewall..."
ufw --force enable
ufw allow ssh
ufw allow 3000/tcp
ufw allow 5901/tcp
ufw allow 3389/tcp
ufw allow 8080/tcp

# Limpar cache de pacotes
log "Limpando cache..."
apt-get autoremove -y
apt-get autoclean

# Criar script de status do laboratório
cat > /usr/local/bin/lab-status << 'EOF'
#!/bin/bash
echo "=== STATUS DO LABORATÓRIO ==="
echo "Docker: $(systemctl is-active docker)"
echo "Juice Shop: $(docker ps --filter name=juice-shop --format 'table {{.Status}}')"
echo "VNC Server: $(systemctl is-active vncserver@1)"
echo "XRDP: $(systemctl is-active xrdp)"
echo "PostgreSQL: $(systemctl is-active postgresql)"
echo ""
echo "=== PORTAS ABERTAS ==="
netstat -tlnp | grep -E ':(22|3000|3389|5901|8080)\s'
EOF
chmod +x /usr/local/bin/lab-status

# Reinicializar serviços essenciais
log "Reinicializando serviços..."
systemctl restart docker
systemctl restart xrdp

log "Configuração do laboratório concluída!"
log "Execute 'lab-status' para verificar o status dos serviços."

# Reboot para garantir que tudo esteja funcionando
log "Agendando reinicialização..."
shutdown -r +2 "Sistema será reiniciado em 2 minutos para finalizar a configuração."