#!/bin/bash
# =============================================================================
# TARGET_SETUP.SH - Configuração de alvos vulneráveis para pentest
# OWASP Juice Shop + DVWA + WebGoat
# =============================================================================

set -e
exec > >(tee /var/log/target-setup.log) 2>&1

# Variáveis do template
STUDENT_NAME="${student_name}"
LAB_NAME="${lab_name}"
JUICE_SHOP_PORT="${juice_shop_port}"

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
    echo -e "$${RED}[ERROR] $1$${NC}"
}

warning() {
    echo -e "$${YELLOW}[WARNING] $1$${NC}"
}

log "🎯 Iniciando configuração de alvos vulneráveis para $${STUDENT_NAME}"
log "📝 Laboratório: $${LAB_NAME}"

# Atualizar sistema
log "📦 Atualizando sistema Ubuntu..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Instalar dependências
log "🔧 Instalando dependências..."
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    vim \
    nano \
    htop \
    tree \
    net-tools \
    nginx \
    mysql-server \
    php \
    php-fpm \
    php-mysql \
    php-gd \
    php-xml \
    php-mbstring \
    php-curl \
    python3 \
    python3-pip \
    default-jdk \
    docker.io \
    docker-compose

# Configurar MySQL
log "🗄️ Configurando MySQL..."
systemctl start mysql
systemctl enable mysql

# Configurar usuário MySQL para aplicações vulneráveis
mysql -e "CREATE DATABASE dvwa;"
mysql -e "CREATE DATABASE webgoat;"
mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa_password';"
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
mysql -e "CREATE USER 'webgoat'@'localhost' IDENTIFIED BY 'webgoat_password';"
mysql -e "GRANT ALL PRIVILEGES ON webgoat.* TO 'webgoat'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Instalar Node.js (versão LTS)
log "🟢 Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs

# Verificar instalações
node_version=$(node --version)
npm_version=$(npm --version)
log "✅ Node.js $${node_version} e npm $${npm_version} instalados"

# =============================================================================
# OWASP JUICE SHOP
# =============================================================================

log "🧃 Configurando OWASP Juice Shop..."

# Criar usuário para Juice Shop
useradd -m -s /bin/bash juiceshop
usermod -aG sudo juiceshop

# Diretório de instalação
JUICE_SHOP_DIR="/opt/juice-shop"
mkdir -p $${JUICE_SHOP_DIR}
chown juiceshop:juiceshop $${JUICE_SHOP_DIR}

# Clonar e configurar Juice Shop
cd $${JUICE_SHOP_DIR}
sudo -u juiceshop git clone https://github.com/juice-shop/juice-shop.git .

# Instalar dependências
log "📦 Instalando dependências do Juice Shop..."
sudo -u juiceshop npm install --production

# Configuração personalizada
cat > $${JUICE_SHOP_DIR}/config/custom.yml << EOF
application:
  name: 'OWASP Juice Shop - Lab $${STUDENT_NAME}'
  welcomeBanner:
    showOnFirstStart: true
    title: 'Laboratório de Pentest'
    message: 'Bem-vindo ao ambiente de teste, $${STUDENT_NAME}! Este é um alvo INTENCIONALMENTE VULNERÁVEL.'

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

# Criar serviço systemd para Juice Shop
cat > /etc/systemd/system/juice-shop.service << EOF
[Unit]
Description=OWASP Juice Shop
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/opt/juice-shop
ExecStart=/usr/bin/npm start
Restart=always
RestartSec=10
Environment=NODE_ENV=custom
Environment=PORT=$${JUICE_SHOP_PORT}

[Install]
WantedBy=multi-user.target
EOF

# =============================================================================
# DVWA (Damn Vulnerable Web Application)
# =============================================================================

log "🕷️ Configurando DVWA..."

# Baixar DVWA
cd /var/www/html
git clone https://github.com/digininja/DVWA.git dvwa
chown -R www-data:www-data dvwa

# Configurar DVWA
cd dvwa
cp config/config.inc.php.dist config/config.inc.php

# Configurar conexão com banco
sed -i "s/\$_DVWA\['db_password'\] = 'p@ssw0rd';/\$_DVWA['db_password'] = 'dvwa_password';/" config/config.inc.php
sed -i "s/\$_DVWA\['db_user'\] = 'dvwa';/\$_DVWA['db_user'] = 'dvwa';/" config/config.inc.php
sed -i "s/\$_DVWA\['db_database'\] = 'dvwa';/\$_DVWA['db_database'] = 'dvwa';/" config/config.inc.php

# Configurar permissões
chmod 666 hackable/uploads/
chmod 777 external/phpids/0.6/lib/IDS/tmp/phpids_log.txt

# =============================================================================
# WEBGOAT
# =============================================================================

log "🐐 Configurando WebGoat..."

# Baixar WebGoat
mkdir -p /opt/webgoat
cd /opt/webgoat
wget https://github.com/WebGoat/WebGoat/releases/latest/download/webgoat-8.2.2.jar -O webgoat.jar
chown -R www-data:www-data /opt/webgoat

# Criar serviço para WebGoat
cat > /etc/systemd/system/webgoat.service << 'EOF'
[Unit]
Description=WebGoat vulnerable web application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/webgoat
ExecStart=/usr/bin/java -jar webgoat.jar --server.port=8080 --server.address=0.0.0.0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# =============================================================================
# MUTILLIDAE II
# =============================================================================

log "🦟 Configurando Mutillidae II..."

# Baixar Mutillidae
cd /var/www/html
git clone https://github.com/webpwnized/mutillidae.git
chown -R www-data:www-data mutillidae

# Configurar banco para Mutillidae
mysql -e "CREATE DATABASE mutillidae;"
mysql -e "CREATE USER 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidae';"
mysql -e "GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# =============================================================================
# CONFIGURAÇÃO DO NGINX
# =============================================================================

log "🌐 Configurando Nginx..."

# Backup da configuração padrão
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup

# Configuração principal do Nginx
cat > /etc/nginx/sites-available/vulnerable-apps << EOF
# Página principal do laboratório
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html/lab-dashboard;
    index index.html index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}

# DVWA
server {
    listen 80;
    server_name dvwa.local;
    root /var/www/html/dvwa;
    index index.php index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}

# Mutillidae
server {
    listen 80;
    server_name mutillidae.local;
    root /var/www/html/mutillidae;
    index index.php index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}

# Proxy para Juice Shop
server {
    listen 80;
    server_name juiceshop.local;
    
    location / {
        proxy_pass http://localhost:${JUICE_SHOP_PORT};
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

# Proxy para WebGoat
server {
    listen 80;
    server_name webgoat.local;
    
    location / {
        proxy_pass http://localhost:8080;
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

# Ativar configuração
ln -sf /etc/nginx/sites-available/vulnerable-apps /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# =============================================================================
# DASHBOARD DO LABORATÓRIO
# =============================================================================

log "📊 Criando dashboard do laboratório..."

# Criar diretório para o dashboard
mkdir -p /var/www/html/lab-dashboard
chown -R www-data:www-data /var/www/html/lab-dashboard

# Página principal do dashboard
cat > /var/www/html/lab-dashboard/index.html << 'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Laboratório de Cibersegurança</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #eee;
            padding-bottom: 20px;
        }
        
        .header h1 {
            color: #333;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #666;
            font-size: 1.2em;
        }
        
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 30px;
            color: #856404;
        }
        
        .warning strong {
            color: #e17055;
        }
        
        .targets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .target-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            border-left: 4px solid #667eea;
            transition: transform 0.3s ease;
        }
        
        .target-card:hover {
            transform: translateY(-5px);
        }
        
        .target-card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.4em;
        }
        
        .target-card p {
            color: #666;
            margin-bottom: 15px;
            line-height: 1.6;
        }
        
        .target-card .access-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            transition: all 0.3s ease;
            display: inline-block;
        }
        
        .btn-primary {
            background: #667eea;
            color: white;
        }
        
        .btn-primary:hover {
            background: #5a67d8;
        }
        
        .btn-secondary {
            background: #48bb78;
            color: white;
        }
        
        .btn-secondary:hover {
            background: #38a169;
        }
        
        .info-section {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
        }
        
        .info-section h3 {
            color: #333;
            margin-bottom: 15px;
        }
        
        .info-list {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #48bb78;
        }
        
        .status-indicator {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online {
            background: #48bb78;
        }
        
        .status-offline {
            background: #e53e3e;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Laboratório de Cibersegurança</h1>
            <p class="subtitle">Ambiente de Aprendizado de Pentest - ${STUDENT_NAME}</p>
        </div>
        
        <div class="warning">
            <strong>⚠️ ATENÇÃO:</strong> Este laboratório contém aplicações INTENCIONALMENTE VULNERÁVEIS para fins educacionais. 
            Use apenas em ambiente controlado e para aprendizado de técnicas de segurança ofensiva.
        </div>
        
        <div class="targets-grid">
            <div class="target-card">
                <h3>🧃 OWASP Juice Shop</h3>
                <p>Aplicação moderna vulnerável com desafios gamificados. Ideal para aprender sobre vulnerabilidades web modernas como XSS, SQL Injection, autenticação quebrada e muito mais.</p>
                <div class="access-links">
                    <a href="http://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_PORT}" class="btn btn-primary" target="_blank">Acessar Aplicação</a>
                    <a href="http://juiceshop.local" class="btn btn-secondary" target="_blank">Via Domain</a>
                </div>
            </div>
            
            <div class="target-card">
                <h3>🕷️ DVWA</h3>
                <p>Damn Vulnerable Web Application - aplicação PHP/MySQL com diferentes níveis de segurança. Perfeita para praticar técnicas básicas de pentest web.</p>
                <div class="access-links">
                    <a href="/dvwa" class="btn btn-primary" target="_blank">Acessar DVWA</a>
                    <a href="http://dvwa.local" class="btn btn-secondary" target="_blank">Via Domain</a>
                </div>
            </div>
            
            <div class="target-card">
                <h3>🐐 WebGoat</h3>
                <p>Aplicação Java educacional da OWASP com lições interativas sobre segurança de aplicações web. Inclui tutoriais passo-a-passo.</p>
                <div class="access-links">
                    <a href="http://$(hostname -I | awk '{print $1}'):8080/WebGoat" class="btn btn-primary" target="_blank">Acessar WebGoat</a>
                    <a href="http://webgoat.local" class="btn btn-secondary" target="_blank">Via Domain</a>
                </div>
            </div>
            
            <div class="target-card">
                <h3>🦟 Mutillidae II</h3>
                <p>Aplicação PHP extremamente vulnerável com OWASP Top 10 e além. Inclui muitas vulnerabilidades para prática intensiva.</p>
                <div class="access-links">
                    <a href="/mutillidae" class="btn btn-primary" target="_blank">Acessar Mutillidae</a>
                    <a href="http://mutillidae.local" class="btn btn-secondary" target="_blank">Via Domain</a>
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>📋 Informações do Laboratório</h3>
            <div class="info-list">
                <div class="info-item">
                    <strong>🎯 IP do Alvo:</strong><br>
                    $(hostname -I | awk '{print $1}') (Interno)<br>
                    $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4) (Externo)
                </div>
                <div class="info-item">
                    <strong>🌐 Rede:</strong><br>
                    Subnet: $(ip route | grep 'src' | head -1 | awk '{print $1}')<br>
                    Gateway: $(ip route | grep default | awk '{print $3}')
                </div>
                <div class="info-item">
                    <strong>💻 Sistema:</strong><br>
                    OS: $(lsb_release -d | cut -f2)<br>
                    Kernel: $(uname -r)
                </div>
                <div class="info-item">
                    <strong>⏰ Uptime:</strong><br>
                    $(uptime -p)<br>
                    Iniciado: $(uptime -s)
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>🔧 Status dos Serviços</h3>
            <div class="info-list">
                <div class="info-item">
                    <span class="status-indicator status-online"></span>
                    <strong>Nginx:</strong> Ativo
                </div>
                <div class="info-item">
                    <span class="status-indicator status-online"></span>
                    <strong>MySQL:</strong> Ativo
                </div>
                <div class="info-item">
                    <span class="status-indicator status-online"></span>
                    <strong>PHP-FPM:</strong> Ativo
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>📚 Recursos de Aprendizado</h3>
            <div class="info-list">
                <div class="info-item">
                    <strong>🎓 OWASP Top 10:</strong><br>
                    <a href="https://owasp.org/www-project-top-ten/" target="_blank">owasp.org/www-project-top-ten</a>
                </div>
                <div class="info-item">
                    <strong>📖 Web Security Academy:</strong><br>
                    <a href="https://portswigger.net/web-security" target="_blank">portswigger.net/web-security</a>
                </div>
                <div class="info-item">
                    <strong>🛠️ Burp Suite:</strong><br>
                    Proxy para interceptação de requisições
                </div>
                <div class="info-item">
                    <strong>🔍 OWASP ZAP:</strong><br>
                    Scanner de vulnerabilidades web
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Verificar status dos serviços via JavaScript
        function checkServiceStatus() {
            const services = [
                { name: 'Juice Shop', url: 'http://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_PORT}', element: 'juice-shop-status' },
                { name: 'WebGoat', url: 'http://$(hostname -I | awk '{print $1}'):8080/WebGoat', element: 'webgoat-status' }
            ];
            
            // Implementar verificação de status em tempo real se necessário
        }
        
        // Atualizar timestamp
        setInterval(function() {
            document.querySelector('.info-section:last-child').innerHTML += 
                '<p style="text-align: center; margin-top: 20px; color: #666;">Última atualização: ' + 
                new Date().toLocaleString('pt-BR') + '</p>';
        }, 60000);
    </script>
</body>
</html>
EOF

# =============================================================================
# CONFIGURAÇÕES FINAIS
# =============================================================================

# Configurar PHP
log "🐘 Configurando PHP..."
sed -i 's/allow_url_include = Off/allow_url_include = On/' /etc/php/*/fpm/php.ini
sed -i 's/display_errors = Off/display_errors = On/' /etc/php/*/fpm/php.ini

# Reiniciar serviços
systemctl restart php*-fpm
systemctl restart nginx
systemctl restart mysql

# Habilitar serviços
systemctl enable nginx
systemctl enable mysql
systemctl enable php*-fpm
systemctl enable juice-shop
systemctl enable webgoat

# Iniciar aplicações vulneráveis
log "🚀 Iniciando aplicações vulneráveis..."
systemctl start juice-shop
sleep 10
systemctl start webgoat

# Configurar firewall básico
log "🔥 Configurando firewall..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw allow ${JUICE_SHOP_PORT}/tcp comment 'Juice Shop'
ufw allow 8080/tcp comment 'WebGoat'

# Criar scripts úteis
log "📝 Criando scripts de administração..."

# Script de status
cat > /home/ubuntu/target-status.sh << 'EOF'
#!/bin/bash
echo "🎯 STATUS DOS ALVOS VULNERÁVEIS"
echo "================================="
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
printf "   %-15s %s\n" "Nginx:" "$(systemctl is-active nginx)"
printf "   %-15s %s\n" "MySQL:" "$(systemctl is-active mysql)"
printf "   %-15s %s\n" "PHP-FPM:" "$(systemctl is-active php*-fpm | head -1)"
printf "   %-15s %s\n" "Juice Shop:" "$(systemctl is-active juice-shop)"
printf "   %-15s %s\n" "WebGoat:" "$(systemctl is-active webgoat)"
echo ""

echo "🎯 Aplicações Vulneráveis:"
printf "   %-15s %s\n" "Dashboard:" "http://$(hostname -I | awk '{print $1}')"
printf "   %-15s %s\n" "Juice Shop:" "http://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_PORT}"
printf "   %-15s %s\n" "DVWA:" "http://$(hostname -I | awk '{print $1}')/dvwa"
printf "   %-15s %s\n" "WebGoat:" "http://$(hostname -I | awk '{print $1}'):8080/WebGoat"
printf "   %-15s %s\n" "Mutillidae:" "http://$(hostname -I | awk '{print $1}')/mutillidae"
echo ""

echo "🔍 Verificação de Conectividade:"
for port in 80 ${JUICE_SHOP_PORT} 8080; do
    if netstat -tnl | grep -q ":$port "; then
        printf "   %-15s %s\n" "Porta $port:" "✅ Aberta"
    else
        printf "   %-15s %s\n" "Porta $port:" "❌ Fechada"
    fi
done
EOF

chmod +x /home/ubuntu/target-status.sh
chown ubuntu:ubuntu /home/ubuntu/target-status.sh

# Script de restart das aplicações
cat > /home/ubuntu/restart-targets.sh << 'EOF'
#!/bin/bash
echo "🔄 Reiniciando alvos vulneráveis..."

echo "Parando serviços..."
sudo systemctl stop juice-shop webgoat

echo "Aguardando 5 segundos..."
sleep 5

echo "Iniciando serviços..."
sudo systemctl start juice-shop
sleep 10
sudo systemctl start webgoat

echo "Verificando status..."
sudo systemctl status juice-shop --no-pager -l
sudo systemctl status webgoat --no-pager -l

echo "✅ Restart concluído!"
EOF

chmod +x /home/ubuntu/restart-targets.sh
chown ubuntu:ubuntu /home/ubuntu/restart-targets.sh

# Arquivo de informações
cat > /home/ubuntu/TARGET_INFO.txt << EOF
═══════════════════════════════════════════════════════
🎯 ALVOS VULNERÁVEIS - LABORATÓRIO DE CIBERSEGURANÇA
═══════════════════════════════════════════════════════

Estudante: ${STUDENT_NAME}
Laboratório: ${LAB_NAME}
Data de criação: $(date)
IP Interno: $(hostname -I | awk '{print $1}')
IP Externo: $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

🌐 APLICAÇÕES DISPONÍVEIS:

📊 Dashboard Principal:
   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)

🧃 OWASP Juice Shop:
   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):${JUICE_SHOP_PORT}
   Tipo: Aplicação Node.js moderna vulnerável
   Foco: OWASP Top 10, desafios gamificados

🕷️  DVWA:
   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)/dvwa
   Tipo: Aplicação PHP clássica
   Login padrão: admin/password
   Foco: Vulnerabilidades web básicas

🐐 WebGoat:
   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080/WebGoat
   Tipo: Aplicação Java educacional
   Foco: Lições interativas da OWASP

🦟 Mutillidae II:
   http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)/mutillidae
   Tipo: Aplicação PHP extremamente vulnerável
   Foco: OWASP Top 10 e vulnerabilidades avançadas

🔧 CREDENCIAIS PADRÃO:

DVWA:
   Usuário: admin
   Senha: password

WebGoat:
   Criar conta na primeira vez

Mutillidae:
   Usuário: admin
   Senha: admin

MySQL (para análise):
   dvwa/dvwa_password (banco: dvwa)
   webgoat/webgoat_password (banco: webgoat)
   mutillidae/mutillidae (banco: mutillidae)

🛠️  SCRIPTS ÚTEIS:

./target-status.sh     - Status dos alvos
./restart-targets.sh   - Reiniciar aplicações

📚 DICAS DE PENTEST:

1. Comece com o dashboard para visão geral
2. Use Burp Suite ou ZAP como proxy
3. Inicie com Juice Shop (mais moderno)
4. DVWA tem níveis de dificuldade ajustáveis
5. WebGoat tem tutoriais integrados
6. Mutillidae é o mais complexo

⚠️  IMPORTANTE:
- Estas aplicações são VULNERÁVEIS por design
- Use apenas para fins educacionais
- Documente suas descobertas

═══════════════════════════════════════════════════════
EOF

chown ubuntu:ubuntu /home/ubuntu/TARGET_INFO.txt

# Configurar MOTD
cat > /etc/motd << 'EOF'

████████████████████████████████████████████████████
█                                                  █
█     🎯 ALVOS VULNERÁVEIS - LAB CIBERSEGURANÇA     █
█                                                  █
████████████████████████████████████████████████████

🧃 Aplicações disponíveis para pentest:
   • OWASP Juice Shop  • DVWA  • WebGoat  • Mutillidae

📊 Dashboard: http://<IP_PÚBLICO>
📚 Informações: cat TARGET_INFO.txt
🔧 Status: ./target-status.sh

⚠️  APLICAÇÕES INTENCIONALMENTE VULNERÁVEIS!

════════════════════════════════════════════════════
EOF

# Verificações finais
log "🔍 Executando verificações finais..."

# Aguardar aplicações iniciarem
sleep 15

# Verificar Juice Shop
if curl -f http://localhost:${JUICE_SHOP_PORT} > /dev/null 2>&1; then
    log "✅ Juice Shop está funcionando"
else
    error "❌ Problema com Juice Shop"
    systemctl status juice-shop --no-pager
fi

# Verificar WebGoat
if curl -f http://localhost:8080 > /dev/null 2>&1; then
    log "✅ WebGoat está funcionando"
else
    warning "⚠️ WebGoat ainda inicializando ou com problema"
fi

# Verificar DVWA
if [ -f /var/www/html/dvwa/index.php ]; then
    log "✅ DVWA instalado"
else
    error "❌ Problema com DVWA"
fi

# Verificar Nginx
if nginx -t; then
    log "✅ Nginx configurado corretamente"
else
    error "❌ Problema na configuração do Nginx"
fi

# Informações finais
log "🎉 Configuração dos alvos vulneráveis concluída!"
log "📍 Acesse o dashboard em: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)"
log "🧃 Juice Shop: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):${JUICE_SHOP_PORT}"
log "📚 Informações detalhadas: cat /home/ubuntu/TARGET_INFO.txt"

exit 0