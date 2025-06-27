#!/bin/bash
# Script de configuração da instância alvo (Juice Shop)
# setup_target.sh

set -e

# Variáveis
LAB_NAME="${lab_name}"
LOG_FILE="/var/log/target-setup.log"
MAIN_USER="ubuntu"

# Função de log
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log "=== CONFIGURANDO INSTÂNCIA ALVO (JUICE SHOP) ==="

# Atualizar sistema
log "Atualizando sistema Ubuntu..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Instalar dependências mínimas
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
    net-tools \
    fail2ban

# Configurar usuário
log "Configurando usuário $MAIN_USER..."
usermod -aG sudo $MAIN_USER
echo "$MAIN_USER:target2024" | chpasswd

# Instalar Docker
log "Instalando Docker..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl enable docker
systemctl start docker
usermod -aG docker $MAIN_USER

# Instalar Node.js (para Juice Shop nativo se necessário)
log "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Configurar OWASP Juice Shop com Docker
log "Configurando OWASP Juice Shop..."
docker pull bkimminich/juice-shop:latest

# Criar script para iniciar Juice Shop
cat > /usr/local/bin/start-juiceshop << 'EOF'
#!/bin/bash
docker run -d \
    --name juice-shop \
    --restart unless-stopped \
    -p 3000:3000 \
    -e NODE_ENV=unsafe \
    bkimminich/juice-shop:latest
EOF
chmod +x /usr/local/bin/start-juiceshop

# Criar script para parar Juice Shop
cat > /usr/local/bin/stop-juiceshop << 'EOF'
#!/bin/bash
docker stop juice-shop
docker rm juice-shop
EOF
chmod +x /usr/local/bin/stop-juiceshop

# Criar script para reiniciar Juice Shop
cat > /usr/local/bin/restart-juiceshop << 'EOF'
#!/bin/bash
docker stop juice-shop 2>/dev/null || true
docker rm juice-shop 2>/dev/null || true
docker run -d \
    --name juice-shop \
    --restart unless-stopped \
    -p 3000:3000 \
    -e NODE_ENV=unsafe \
    bkimminich/juice-shop:latest
EOF
chmod +x /usr/local/bin/restart-juiceshop

# Iniciar Juice Shop
log "Iniciando OWASP Juice Shop..."
/usr/local/bin/start-juiceshop

# Aguardar Juice Shop inicializar
log "Aguardando Juice Shop inicializar..."
sleep 30

# Verificar se está rodando
if curl -s http://localhost:3000 > /dev/null; then
    log "Juice Shop iniciado com sucesso!"
else
    log "ERRO: Juice Shop não conseguiu iniciar. Tentando novamente..."
    /usr/local/bin/restart-juiceshop
    sleep 30
fi

# Instalar aplicações web vulneráveis adicionais (opcionais)
log "Instalando aplicações vulneráveis adicionais..."

# DVWA (Damn Vulnerable Web Application)
docker pull vulnerables/web-dvwa
cat > /usr/local/bin/start-dvwa << 'EOF'
#!/bin/bash
docker run -d \
    --name dvwa \
    --restart unless-stopped \
    -p 8080:80 \
    vulnerables/web-dvwa
EOF
chmod +x /usr/local/bin/start-dvwa

# WebGoat
docker pull webgoat/webgoat-8.0
cat > /usr/local/bin/start-webgoat << 'EOF'
#!/bin/bash
docker run -d \
    --name webgoat \
    --restart unless-stopped \
    -p 8081:8080 \
    webgoat/webgoat-8.0
EOF
chmod +x /usr/local/bin/start-webgoat

# Mutillidae
docker pull citizenstig/nowasp
cat > /usr/local/bin/start-mutillidae << 'EOF'
#!/bin/bash
docker run -d \
    --name mutillidae \
    --restart unless-stopped \
    -p 8082:80 \
    citizenstig/nowasp
EOF
chmod +x /usr/local/bin/start-mutillidae

# Configurar serviços de monitoramento simples
log "Configurando monitoramento básico..."

# Script de saúde das aplicações
cat > /usr/local/bin/health-check << 'EOF'
#!/bin/bash
echo "=== HEALTH CHECK - APLICAÇÕES VULNERÁVEIS ==="
echo "Data: $(date)"
echo ""

# Juice Shop
if curl -s http://localhost:3000 > /dev/null; then
    echo "✓ Juice Shop (porta 3000): OK"
else
    echo "✗ Juice Shop (porta 3000): FALHOU"
fi

# DVWA
if docker ps | grep -q dvwa; then
    if curl -s http://localhost:8080 > /dev/null; then
        echo "✓ DVWA (porta 8080): OK"
    else
        echo "✗ DVWA (porta 8080): Container rodando mas não responde"
    fi
else
    echo "- DVWA (porta 8080): Não iniciado"
fi

# WebGoat
if docker ps | grep -q webgoat; then
    if curl -s http://localhost:8081 > /dev/null; then
        echo "✓ WebGoat (porta 8081): OK"
    else
        echo "✗ WebGoat (porta 8081): Container rodando mas não responde"
    fi
else
    echo "- WebGoat (porta 8081): Não iniciado"
fi

# Mutillidae
if docker ps | grep -q mutillidae; then
    if curl -s http://localhost:8082 > /dev/null; then
        echo "✓ Mutillidae (porta 8082): OK"
    else
        echo "✗ Mutillidae (porta 8082): Container rodando mas não responde"
    fi
else
    echo "- Mutillidae (porta 8082): Não iniciado"
fi

echo ""
echo "=== CONTAINERS DOCKER ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
EOF
chmod +x /usr/local/bin/health-check

# Criar script de gerenciamento de laboratório
cat > /usr/local/bin/lab-manage << 'EOF'
#!/bin/bash
case "$1" in
    start)
        echo "Iniciando todas as aplicações vulneráveis..."
        start-juiceshop
        start-dvwa
        start-webgoat
        start-mutillidae
        echo "Aguardando inicialização..."
        sleep 30
        health-check
        ;;
    stop)
        echo "Parando todas as aplicações..."
        docker stop juice-shop dvwa webgoat mutillidae 2>/dev/null || true
        docker rm juice-shop dvwa webgoat mutillidae 2>/dev/null || true
        echo "Aplicações paradas."
        ;;
    restart)
        echo "Reiniciando todas as aplicações..."
        $0 stop
        sleep 5
        $0 start
        ;;
    status)
        health-check
        ;;
    *)
        echo "Uso: $0 {start|stop|restart|status}"
        echo ""
        echo "Comandos disponíveis:"
        echo "  start     - Inicia todas as aplicações vulneráveis"
        echo "  stop      - Para todas as aplicações"
        echo "  restart   - Reinicia todas as aplicações"
        echo "  status    - Mostra status das aplicações"
        exit 1
        ;;
esac
EOF
chmod +x /usr/local/bin/lab-manage

# Configurar logs centralizados
log "Configurando logs..."
mkdir -p /var/log/vulnerable-apps

# Script de logs
cat > /usr/local/bin/show-logs << 'EOF'
#!/bin/bash
echo "=== LOGS DAS APLICAÇÕES VULNERÁVEIS ==="
echo ""
echo "=== JUICE SHOP LOGS ==="
docker logs juice-shop --tail 50 2>/dev/null || echo "Juice Shop não está rodando"
echo ""
echo "=== DVWA LOGS ==="
docker logs dvwa --tail 20 2>/dev/null || echo "DVWA não está rodando"
echo ""
echo "=== WEBGOAT LOGS ==="
docker logs webgoat --tail 20 2>/dev/null || echo "WebGoat não está rodando"
echo ""
echo "=== MUTILLIDAE LOGS ==="
docker logs mutillidae --tail 20 2>/dev/null || echo "Mutillidae não está rodando"
EOF
chmod +x /usr/local/bin/show-logs

# Configurar firewall restritivo
log "Configurando firewall..."
ufw --force enable
# Apenas conexões da subnet do atacante
ufw allow from 172.16.1.0/24 to any port 22
ufw allow from 172.16.1.0/24 to any port 3000
ufw allow from 172.16.1.0/24 to any port 8080
ufw allow from 172.16.1.0/24 to any port 8081
ufw allow from 172.16.1.0/24 to any port 8082
ufw deny from any to any

# Configurar fail2ban para proteção adicional
log "Configurando fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Criar arquivo de configuração do laboratório
cat > /home/$MAIN_USER/TARGET_INFO.txt << 'EOF'
=== INSTÂNCIA ALVO - LABORATÓRIO CYBERSECURITY ===

CONFIGURAÇÃO:
- Sistema: Ubuntu 22.04 Minimal
- Usuário: ubuntu
- Senha: target2024
- Função: Host de aplicações vulneráveis

APLICAÇÕES VULNERÁVEIS DISPONÍVEIS:

1. OWASP Juice Shop (Principal)
   - Porta: 3000
   - Status: Sempre ativo
   - Descrição: Aplicação moderna com vulnerabilidades OWASP Top 10

2. DVWA (Damn Vulnerable Web Application)
   - Porta: 8080
   - Comando: start-dvwa
   - Descrição: Aplicação PHP com vulnerabilidades clássicas

3. WebGoat
   - Porta: 8081
   - Comando: start-webgoat
   - Descrição: Aplicação Java educacional da OWASP

4. Mutillidae
   - Porta: 8082
   - Comando: start-mutillidae
   - Descrição: Aplicação PHP/MySQL com múltiplas vulnerabilidades

COMANDOS DE GERENCIAMENTO:
- lab-manage start    : Inicia todas as aplicações
- lab-manage stop     : Para todas as aplicações
- lab-manage restart  : Reinicia todas as aplicações
- lab-manage status   : Mostra status das aplicações
- health-check        : Verifica saúde das aplicações
- show-logs          : Mostra logs das aplicações

COMANDOS ESPECÍFICOS:
- start-juiceshop / stop-juiceshop / restart-juiceshop
- start-dvwa
- start-webgoat
- start-mutillidae

SEGURANÇA:
- Firewall configurado para aceitar apenas conexões da subnet 172.16.1.0/24
- Fail2ban ativo para proteção contra brute force
- Acesso SSH restrito apenas da instância atacante
- Sistema isolado da internet (apenas aplicações vulneráveis)

VULNERABILIDADES DISPONÍVEIS PARA TESTE:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Broken Authentication
- Sensitive Data Exposure
- Broken Access Control
- Security Misconfiguration
- Components with Known Vulnerabilities
- Insufficient Logging & Monitoring

NOTA: Esta instância é ISOLADA e só pode ser acessada pela instância atacante.
EOF

chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/TARGET_INFO.txt

# Configurar ambiente do usuário
sudo -u $MAIN_USER bash << 'EOF'
cd /home/ubuntu
echo 'alias ll="ls -la"' >> .bashrc
echo 'alias lab="lab-manage"' >> .bashrc
echo 'alias status="health-check"' >> .bashrc
echo 'alias logs="show-logs"' >> .bashrc
echo 'alias juice="restart-juiceshop"' >> .bashrc
EOF

# Configurar cron para monitoramento automático
log "Configurando monitoramento automático..."
cat > /etc/cron.d/lab-monitoring << 'EOF'
# Verificar saúde das aplicações a cada 5 minutos
*/5 * * * * root /usr/local/bin/health-check >> /var/log/vulnerable-apps/health-check.log 2>&1

# Restart automático do Juice Shop se necessário (a cada hora)
0 * * * * root docker ps | grep juice-shop || /usr/local/bin/start-juiceshop

# Limpeza de logs antigos (diariamente)
0 2 * * * root find /var/log/vulnerable-apps -name "*.log" -mtime +7 -delete
EOF

# Criar serviço systemd para auto-start das aplicações
cat > /etc/systemd/system/vulnerable-apps.service << 'EOF'
[Unit]
Description=Vulnerable Web Applications
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/lab-manage start
ExecStop=/usr/local/bin/lab-manage stop
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vulnerable-apps.service

# Limpar cache
log "Limpando cache..."
apt-get autoremove -y
apt-get autoclean

# Status final
log "=== CONFIGURAÇÃO DO ALVO CONCLUÍDA ==="
log "Verificando status das aplicações..."
/usr/local/bin/health-check

log "Sistema alvo configurado com sucesso!"
log "Aplicações vulneráveis disponíveis na instância."

# Não reiniciar automaticamente - deixar rodando
log "Configuração completa. Sistema permanecerá ativo."