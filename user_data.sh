#!/bin/bash
# =============================================================================
# USER_DATA.SH - Script de instalação do OWASP Juice Shop
# Executado automaticamente na inicialização da instância EC2
# =============================================================================

set -e  # Parar em caso de erro

# Variáveis do template
STUDENT_NAME="${student_name}"
JUICE_SHOP_PORT="${juice_shop_port}"
DOMAIN_NAME="${domain_name}"
ENABLE_SSL="${enable_ssl}"

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Função de log
log() {
    echo -e "$${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1$${NC}" | tee -a /var/log/juice-shop-setup.log
}

error() {
    echo -e "$${RED}[ERROR] $1$${NC}" | tee -a /var/log/juice-shop-setup.log
}

warning() {
    echo -e "$${YELLOW}[WARNING] $1$${NC}" | tee -a /var/log/juice-shop-setup.log
}

log "🚀 Iniciando instalação do OWASP Juice Shop para $${STUDENT_NAME}"

# Atualizar sistema
log "📦 Atualizando sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Instalar dependências básicas
log "🔧 Instalando dependências básicas..."
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    htop \
    tree \
    vim \
    nano \
    net-tools \
    ufw \
    fail2ban \
    nginx \
    certbot \
    python3-certbot-nginx

# Instalar Node.js (versão LTS)
log "🟢 Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs

# Verificar instalação do Node.js
node_version=$(node --version)
npm_version=$(npm --version)
log "✅ Node.js $${node_version} e npm $${npm_version} instalados"

# Criar usuário para Juice Shop
log "👤 Criando usuário juiceshop..."
useradd -m -s /bin/bash juiceshop
usermod -aG sudo juiceshop

# Diretório de instalação
JUICE_SHOP_DIR="/opt/juice-shop"
mkdir -p $${JUICE_SHOP_DIR}
chown juiceshop:juiceshop $${JUICE_SHOP_DIR}

# Clonar repositório do Juice Shop
log "📥 Clonando OWASP Juice Shop..."
cd $${JUICE_SHOP_DIR}
sudo -u juiceshop git clone https://github.com/juice-shop/juice-shop.git .

# Instalar dependências do Juice Shop
log "📦 Instalando dependências do Juice Shop..."
sudo -u juiceshop npm install --production

# Configurar arquivo de configuração personalizado
log "⚙️ Configurando Juice Shop..."
cat > $${JUICE_SHOP_DIR}/config/custom.yml << EOF
# Configuração personalizada para laboratório de pentest
# Estudante: $${STUDENT_NAME}

application:
  name: 'OWASP Juice Shop - Lab $${STUDENT_NAME}'
  welcomeBanner:
    showOnFirstStart: true
    title: 'Laboratório de Pentest'
    message: 'Bem-vindo ao ambiente de teste, $${STUDENT_NAME}!'
  
server:
  port: $${JUICE_SHOP_PORT}

challenges:
  showHints: true
  showMitigations: true
  
ctf:
  showFlagsInNotifications: true

hackingInstructor:
  isEnabled: true

EOF

chown juiceshop:juiceshop $${JUICE_SHOP_DIR}/config/custom.yml

# Criar script de inicialização
log "🔄 Criando script de inicialização..."
cat > /opt/juice-shop/start-juice-shop.sh << 'EOF'
#!/bin/bash
cd /opt/juice-shop
export NODE_ENV=custom
export PORT=${JUICE_SHOP_PORT}
npm start
EOF

chmod +x /opt/juice-shop/start-juice-shop.sh
chown juiceshop:juiceshop /opt/juice-shop/start-juice-shop.sh

# Criar serviço systemd
log "🎯 Criando serviço systemd..."
cat > /etc/systemd/system/juice-shop.service << EOF
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/opt/juice-shop
ExecStart=/opt/juice-shop/start-juice-shop.sh
Restart=always
RestartSec=10
Environment=NODE_ENV=custom
Environment=PORT=$${JUICE_SHOP_PORT}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=juice-shop

[Install]
WantedBy=multi-user.target
EOF

# Configurar firewall
log "🔥 Configurando firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow $${JUICE_SHOP_PORT}/tcp comment 'Juice Shop'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Configurar Nginx como proxy reverso
log "🌐 Configurando Nginx..."
cat > /etc/nginx/sites-available/juice-shop << EOF
server {
    listen 80;
    server_name $${DOMAIN_NAME:-_};
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    
    # Logs
    access_log /var/log/nginx/juice-shop.access.log;
    error_log /var/log/nginx/juice-shop.error.log;
    
    location / {
        proxy_pass http://localhost:$${JUICE_SHOP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_redirect off;
    }
    
    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
EOF

# Ativar site
ln -sf /etc/nginx/sites-available/juice-shop /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Configurar SSL se habilitado
if [ "$${ENABLE_SSL}" = "true" ]; then
    log "🔒 Configurando SSL..."
    if [ -n "$${DOMAIN_NAME}" ]; then
        # SSL com Let's Encrypt para domínio real
        certbot --nginx -d $${DOMAIN_NAME} --non-interactive --agree-tos --email admin@$${DOMAIN_NAME}
    else
        # Certificado auto-assinado
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/juice-shop.key \
            -out /etc/ssl/certs/juice-shop.crt \
            -subj "/C=BR/ST=Lab/L=Lab/O=PentestLab/CN=juice-shop"
        
        # Configurar HTTPS no Nginx
        cat >> /etc/nginx/sites-available/juice-shop << EOF

server {
    listen 443 ssl http2;
    server_name $${DOMAIN_NAME:-_};
    
    ssl_certificate /etc/ssl/certs/juice-shop.crt;
    ssl_certificate_key /etc/ssl/private/juice-shop.key;
    
    # SSL Security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    location / {
        proxy_pass http://localhost:$${JUICE_SHOP_PORT};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF
    fi
fi

# Testar configuração do Nginx
nginx -t
systemctl restart nginx
systemctl enable nginx

# Iniciar e habilitar Juice Shop
log "🎯 Iniciando OWASP Juice Shop..."
systemctl daemon-reload
systemctl enable juice-shop
systemctl start juice-shop

# Aguardar inicialização
log "⏳ Aguardando inicialização do Juice Shop..."
sleep 30

# Verificar se está funcionando
if curl -f http://localhost:$${JUICE_SHOP_PORT} > /dev/null 2>&1; then
    log "✅ Juice Shop iniciado com sucesso!"
else
    error "❌ Falha na inicialização do Juice Shop"
    systemctl status juice-shop
fi

# Criar script de informações
cat > /home/ubuntu/lab-info.sh << EOF
#!/bin/bash
echo "===========================================" 
echo "🧪 LABORATÓRIO OWASP JUICE SHOP"
echo "Estudante: $${STUDENT_NAME}"
echo "==========================================="
echo ""
echo "🌐 URLs de Acesso:"
echo "   HTTP:  http://\$(curl -s ipinfo.io/ip):$${JUICE_SHOP_PORT}"
if [ "$${ENABLE_SSL}" = "true" ]; then
echo "   HTTPS: https://\$(curl -s ipinfo.io/ip):443"
fi
echo ""
echo "📊 Status dos Serviços:"
echo "   Juice Shop: \$(systemctl is-active juice-shop)"
echo "   Nginx:      \$(systemctl is-active nginx)"
echo ""
echo "📁 Diretórios Importantes:"
echo "   Juice Shop: /opt/juice-shop"
echo "   Logs:       /var/log/nginx/ e journalctl -u juice-shop"
echo ""
echo "🔧 Comandos Úteis:"
echo "   sudo systemctl restart juice-shop"
echo "   sudo systemctl status juice-shop"
echo "   sudo journalctl -u juice-shop -f"
echo ""
echo "⚠️  ATENÇÃO: Esta aplicação é VULNERÁVEL por design!"
echo "   Use apenas para aprendizado em ambiente isolado."
echo "==========================================="
EOF

chmod +x /home/ubuntu/lab-info.sh
chown ubuntu:ubuntu /home/ubuntu/lab-info.sh

# Criar MOTD personalizado
cat > /etc/motd << EOF