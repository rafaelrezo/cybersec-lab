cat > /etc/systemd/system/juice-shop-https.service << EOF
[Unit]
Description=OWASP Juice Shop HTTPS
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/opt/juice-shop
ExecStart=/usr/bin/node app-https.js
Restart=always
RestartSec=10
Environment=NODE_ENV=custom
Environment=HTTPS_PORT=${JUICE_SHOP_HTTPS_PORT}
Environment=SSL_KEY=/etc/ssl/lab-certs/juiceshop.key
Environment=SSL_CERT=/etc/ssl/lab-certs/juiceshop.crt

[Install]
WantedBy=multi-user.target
EOF
fi

# =============================================================================
# DVWA (Damn Vulnerable Web Application) COM HTTPS
# =============================================================================

log "🕷️ Configurando DVWA com suporte HTTPS..."

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

# =============================================================================
# CONFIGURAÇÃO DO NGINX COM HTTPS
# =============================================================================

log "🌐 Configurando Nginx com HTTPS para interceptação Burp Suite..."

# Backup da configuração padrão
cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.backup

# Configuração principal do Nginx
cat > /etc/nginx/sites-available/vulnerable-apps << EOF
# Dashboard principal do laboratório
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html/lab-dashboard;
    index index.html index.php;
    
    # Headers de segurança desabilitados para pentest
    add_header X-Frame-Options "ALLOWALL" always;
    add_header X-Content-Type-Options "" always;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
}

# HTTPS redirect para dashboard
server {
    listen 443 ssl http2;
    server_name _;
    
    ssl_certificate /etc/ssl/lab-certs/juiceshop.crt;
    ssl_certificate_key /etc/ssl/lab-certs/juiceshop.key;
    
    # SSL settings otimizadas para interceptação
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
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

# DVWA HTTP
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

# DVWA HTTPS
server {
    listen 443 ssl http2;
    server_name dvwa.local;
    
    ssl_certificate /etc/ssl/lab-certs/juiceshop.crt;
    ssl_certificate_key /etc/ssl/lab-certs/juiceshop.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
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

# Mutillidae HTTP
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

# Mutillidae HTTPS
server {
    listen 443 ssl http2;
    server_name mutillidae.local;
    
    ssl_certificate /etc/ssl/lab-certs/juiceshop.crt;
    ssl_certificate_key /etc/ssl/lab-certs/juiceshop.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
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

# Proxy para Juice Shop HTTP
server {
    listen 80;
    server_name juiceshop.local juice-shop.lab;
    
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

# Proxy para WebGoat HTTP
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

# Proxy para WebGoat HTTPS
server {
    listen 443 ssl http2;
    server_name webgoat.local;
    
    ssl_certificate /etc/ssl/lab-certs/juiceshop.crt;
    ssl_certificate_key /etc/ssl/lab-certs/juiceshop.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

# Ativar configuração
ln -sf /etc/nginx/sites-available/vulnerable-apps /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# =============================================================================
# DASHBOARD DO LABORATÓRIO COM BURP SUITE INTEGRATION
# =============================================================================

log "📊 Criando dashboard especializado para Burp Suite..."

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
    <title>Laboratório Burp Suite - Interceptação HTTPS</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        }
        
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 3px solid #ff6b6b;
            padding-bottom: 20px;
        }
        
        .header h1 {
            color: #333;
            font-size: 2.8em;
            margin-bottom: 10px;
        }
        
        .header .subtitle {
            color: #666;
            font-size: 1.3em;
        }
        
        .burp-warning {
            background: linear-gradient(135deg, #ff9ff3 0%, #f368e0 100%);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 30px;
            color: white;
            text-align: center;
        }
        
        .burp-warning h3 {
            margin-bottom: 10px;
            font-size: 1.5em;
        }
        
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 30px;
            color: #856404;
        }
        
        .targets-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        
        .target-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
            border-left: 5px solid #ff6b6b;
            transition: all 0.3s ease;
        }
        
        .target-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
        }
        
        .target-card.https {
            border-left-color: #00b894;
        }
        
        .target-card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .ssl-badge {
            background: #00b894;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.7em;
            font-weight: bold;
        }
        
        .target-card p {
            color: #666;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        
        .access-links {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 12px 20px;
            text-decoration: none;
            border-radius: 6px;
            font-weight: bold;
            transition: all 0.3s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        
        .btn-http {
            background: #0984e3;
            color: white;
        }
        
        .btn-http:hover {
            background: #0770c2;
            transform: translateY(-2px);
        }
        
        .btn-https {
            background: #00b894;
            color: white;
        }
        
        .btn-https:hover {
            background: #00a085;
            transform: translateY(-2px);
        }
        
        .btn-burp {
            background: #fd79a8;
            color: white;
        }
        
        .btn-burp:hover {
            background: #e84393;
            transform: translateY(-2px);
        }
        
        .burp-section {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
            border: 2px solid #fd79a8;
        }
        
        .burp-section h3 {
            color: #333;
            margin-bottom: 20px;
            font-size: 1.6em;
        }
        
        .burp-steps {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        
        .step {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #fd79a8;
        }
        
        .step h4 {
            color: #fd79a8;
            margin-bottom: 10px;
        }
        
        .step code {
            background: #f1f3f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
        
        .info-section {
            background: #f7fafc;
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }
        
        .info-item {
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid #0984e3;
        }
        
        .status-online {
            color: #00b894;
            font-weight: bold;
        }
        
        .status-offline {
            color: #d63031;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔥 Laboratório Burp Suite</h1>
            <p class="subtitle">Interceptação HTTPS - Ambiente de Pentest - ${STUDENT_NAME}</p>
        </div>
        
        <div class="burp-warning">
            <h3>🎯 Configurado para Interceptação HTTPS com Burp Suite</h3>
            <p>Este laboratório está otimizado para interceptar tráfego HTTPS usando o Burp Suite. Todos os alvos possuem certificados SSL configurados especialmente para pentest.</p>
        </div>
        
        <div class="warning">
            <strong>🔒 IMPORTANTE:</strong> Este laboratório contém aplicações INTENCIONALMENTE VULNERÁVEIS com HTTPS habilitado. 
            Configure o Burp Suite para interceptar todo o tráfego SSL/TLS. Aceite certificados auto-assinados durante os testes.
        </div>
        
        <div class="targets-grid">
            <div class="target-card https">
                <h3>🧃 OWASP Juice Shop <span class="ssl-badge">HTTPS</span></h3>
                <p>Aplicação moderna vulnerável com HTTPS habilitado. Certificado SSL configurado para interceptação com Burp Suite. Ideal para testes de XSS, SQL Injection e autenticação quebrada em ambiente HTTPS.</p>
                <div class="access-links">
                    <a href="http://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_PORT}" class="btn btn-http" target="_blank">🌐 HTTP</a>
                    <a href="https://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_HTTPS_PORT}" class="btn btn-https" target="_blank">🔒 HTTPS</a>
                    <a href="http://juiceshop.local" class="btn btn-burp" target="_blank">📡 Via Proxy</a>
                </div>
            </div>
            
            <div class="target-card https">
                <h3>🕷️ DVWA <span class="ssl-badge">HTTPS</span></h3>
                <p>Damn Vulnerable Web Application com suporte HTTPS. Perfeita para praticar técnicas de pentest web através do Burp Suite em conexões SSL.</p>
                <div class="access-links">
                    <a href="/dvwa" class="btn btn-http" target="_blank">🌐 HTTP</a>
                    <a href="https://$(hostname -I | awk '{print $1}')/dvwa" class="btn btn-https" target="_blank">🔒 HTTPS</a>
                    <a href="https://dvwa.local" class="btn btn-burp" target="_blank">📡 Via Domain</a>
                </div>
            </div>
            
            <div class="target-card https">
                <h3>🐐 WebGoat <span class="ssl-badge">HTTPS</span></h3>
                <p>Aplicação educacional da OWASP com proxy HTTPS. Lições interativas sobre segurança web com tráfego SSL interceptável pelo Burp Suite.</p>
                <div class="access-links">
                    <a href="http://$(hostname -I | awk '{print $1}'):8080/WebGoat" class="btn btn-http" target="_blank">🌐 HTTP</a>
                    <a href="https://webgoat.local/WebGoat" class="btn btn-https" target="_blank">🔒 HTTPS</a>
                </div>
            </div>
            
            <div class="target-card https">
                <h3>🦟 Mutillidae II <span class="ssl-badge">HTTPS</span></h3>
                <p>Aplicação PHP extremamente vulnerável com HTTPS. Múltiplas vulnerabilidades para interceptação e análise de tráfego SSL com Burp Suite.</p>
                <div class="access-links">
                    <a href="/mutillidae" class="btn btn-http" target="_blank">🌐 HTTP</a>
                    <a href="https://$(hostname -I | awk '{print $1}')/mutillidae" class="btn btn-https" target="_blank">🔒 HTTPS</a>
                    <a href="https://mutillidae.local" class="btn btn-burp" target="_blank">📡 Via Domain</a>
                </div>
            </div>
        </div>
        
        <div class="burp-section">
            <h3>🔥 Workflow de Interceptação HTTPS com Burp Suite</h3>
            <div class="burp-steps">
                <div class="step">
                    <h4>1. 🚀 Conectar no Kali</h4>
                    <p>Acesse o Kali Linux via VNC e execute:</p>
                    <code>burp-start</code>
                    <p>Isso iniciará o Burp Suite e instalará o certificado CA automaticamente.</p>
                </div>
                
                <div class="step">
                    <h4>2. 🌐 Configurar Browser</h4>
                    <p>Use o Firefox pré-configurado:</p>
                    <code>firefox-pentest</code>
                    <p>Ou configure manualmente: Proxy 127.0.0.1:8080</p>
                </div>
                
                <div class="step">
                    <h4>3. 🎯 Definir Target</h4>
                    <p>No terminal do Kali:</p>
                    <code>target $(hostname -I | awk '{print $1}')</code>
                    <p>Isso configura variáveis de ambiente para o alvo.</p>
                </div>
                
                <div class="step">
                    <h4>4. 🔒 Interceptar HTTPS</h4>
                    <p>Ative Intercept no Burp e navegue para:</p>
                    <code>https://$(hostname -I | awk '{print $1}'):${JUICE_SHOP_HTTPS_PORT}</code>
                    <p>Aceite o certificado e veja as requisições no Burp!</p>
                </div>
                
                <div class="step">
                    <h4>5. 🔍 Analisar Tráfego</h4>
                    <p>Use as ferramentas do Burp:</p>
                    <ul>
                        <li><strong>Proxy:</strong> Interceptar e modificar</li>
                        <li><strong>Repeater:</strong> Reenviar requisições</li>
                        <li><strong>Intruder:</strong> Ataques automatizados</li>
                        <li><strong>Scanner:</strong> Detectar vulnerabilidades</li>
                    </ul>
                </div>
                
                <div class="step">
                    <h4>6. 📊 Gerar Relatórios</h4>
                    <p>Documente descobertas:</p>
                    <code>~/pentest-lab/reports/</code>
                    <p>Exporte resultados do Burp Scanner e Target > Site map</p>
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>📋 Informações do Sistema</h3>
            <div class="info-grid">
                <div class="info-item">
                    <strong>🎯 IP do Alvo:</strong><br>
                    $(hostname -I | awk '{print $1}') (Interno)<br>
                    $(curl -s http://169.254.169.254/latest/meta-data/public-ipv4) (Externo)
                </div>
                <div class="info-item">
                    <strong>🔥 Burp Suite Proxy:</strong><br>
                    ${KALI_IP}:8080<br>
                    CA: http://${KALI_IP}:8080/cert
                </div>
                <div class="info-item">
                    <strong>🔒 Certificados SSL:</strong><br>
                    Auto-assinados para lab<br>
                    CN: juice-shop.lab
                </div>
                <div class="info-item">
                    <strong>⏰ Sistema:</strong><br>
                    $(uptime -p)<br>
                    $(date)
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>🔧 Status dos Serviços</h3>
            <div class="info-grid">
                <div class="info-item">
                    <strong>Nginx:</strong> <span class="status-online">✅ Ativo</span><br>
                    HTTP + HTTPS configurado
                </div>
                <div class="info-item">
                    <strong>Juice Shop HTTP:</strong> <span class="status-online">✅ Porta ${JUICE_SHOP_PORT}</span><br>
                    <strong>Juice Shop HTTPS:</strong> <span class="status-online">✅ Porta ${JUICE_SHOP_HTTPS_PORT}</span>
                </div>
                <div class="info-item">
                    <strong>MySQL:</strong> <span class="status-online">✅ Ativo</span><br>
                    Bancos: dvwa, webgoat, mutillidae
                </div>
                <div class="info-item">
                    <strong>PHP-FPM:</strong> <span class="status-online">✅ Ativo</span><br>
                    SSL/TLS habilitado
                </div>
            </div>
        </div>
        
        <div class="info-section">
            <h3>📚 Recursos para Burp Suite</h3>
            <div class="info-grid">
                <div class="info-item">
                    <strong>🎓 Burp Academy:</strong><br>
                    <a href="https://portswigger.net/web-security" target="_blank">portswigger.net/web-security</a>
                </div>
                <div class="info-item">
                    <strong>📖 SSL/TLS Testing:</strong><br>
                    <a href="https://owasp.org/www-project-web-security-testing-guide/" target="_blank">OWASP Testing Guide</a>
                </div>
                <div class="info-item">
                    <strong>🔒 Certificate Analysis:</strong><br>
                    Use Burp Target > Site map para analisar certificados
                </div>
                <div class="info-item">
                    <strong>⚡ Extensões Burp:</strong><br>
                    Logger++, Param Miner, Active Scan++
                </div>
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh de status a cada 30 segundos
        setInterval(function() {
            // Implementar verificações via JavaScript se necessário
        }, 30000);
        
        // Avisos sobre HTTPS
        document.addEventListener('DOMContentLoaded', function() {
            if (location.protocol === 'https:') {
                console.log('🔒 Você está acessando via HTTPS - perfeito para interceptação com Burp Suite!');
            }
        });
    </script>
</body>
</html>
EOF

# =============================================================================
# CONFIGURAÇÕES FINAIS
# =============================================================================

# Configurar PHP para permitir vulnerabilidades
log "🐘 Configurando PHP para testes de segurança..."
sed -i 's/allow_url_include = Off/allow_url_include = On/' /etc/php/*/fpm/php.ini
sed -i 's/display_errors = Off/display_errors = On/' /etc/php/*/fpm/php.ini
sed -i 's/expose_php = On/expose_php = On/' /etc/php/*/fpm/php.ini

# Reiniciar serviços
systemctl restart php*-fpm
systemctl restart nginx
systemctl restart mysql

# Habilitar serviços
systemctl enable nginx
systemctl enable mysql
systemctl enable php*-fpm
systemctl enable juice-shop-http

if [ "${ENABLE_HTTPS}" = "true" ]; then
    systemctl enable juice-shop-https
fi

systemctl enable webgoat

# Iniciar aplicações vulneráveis
log "🚀 Iniciando aplicações vulneráveis com HTTPS..."
systemctl start juice-shop-http

if [ "${ENABLE_HTTPS}" = "true" ]; then
    sleep 5
    systemctl start juice-shop-https
fi

sleep 10
systemctl start webgoat

# Configurar firewall para HTTPS
log "🔥 Configurando firewall para HTTPS..."
ufw --force enable
ufw allow 22/tcp comment 'SSH'
ufw allow #!/bin/bash
# =============================================================================
# TARGET_SETUP.SH - Configuração de alvos vulneráveis para pentest
# OWASP Juice Shop + DVWA + WebGoat com suporte HTTPS para Burp Suite
# =============================================================================

set -e
exec > >(tee /var/log/target-setup.log) 2>&1

# Variáveis do template
STUDENT_NAME="${student_name}"
LAB_NAME="${lab_name}"
JUICE_SHOP_PORT="${juice_shop_port}"
JUICE_SHOP_HTTPS_PORT="${juice_shop_https_port}"
ENABLE_HTTPS="${enable_https}"
KALI_IP="${kali_ip}"

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

log "🎯 Iniciando configuração de alvos vulneráveis com HTTPS para ${STUDENT_NAME}"
log "📝 Laboratório: ${LAB_NAME}"
log "🔒 HTTPS habilitado: ${ENABLE_HTTPS}"
log "🔥 Kali IP (Burp Suite): ${KALI_IP}"

# Atualizar sistema
log "📦 Atualizando sistema Ubuntu..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y

# Instalar dependências essenciais para HTTPS
log "🔧 Instalando dependências com suporte SSL/TLS..."
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
    docker-compose \
    openssl \
    ca-certificates \
    certbot \
    python3-certbot-nginx

# Configurar MySQL
log "🗄️ Configurando MySQL..."
systemctl start mysql
systemctl enable mysql

# Configurar usuário MySQL para aplicações vulneráveis
mysql -e "CREATE DATABASE dvwa;"
mysql -e "CREATE DATABASE webgoat;"
mysql -e "CREATE DATABASE mutillidae;"
mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa_password';"
mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
mysql -e "CREATE USER 'webgoat'@'localhost' IDENTIFIED BY 'webgoat_password';"
mysql -e "GRANT ALL PRIVILEGES ON webgoat.* TO 'webgoat'@'localhost';"
mysql -e "CREATE USER 'mutillidae'@'localhost' IDENTIFIED BY 'mutillidae';"
mysql -e "GRANT ALL PRIVILEGES ON mutillidae.* TO 'mutillidae'@'localhost';"
mysql -e "FLUSH PRIVILEGES;"

# Instalar Node.js (versão LTS)
log "🟢 Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
apt-get install -y nodejs

# Verificar instalações
node_version=$(node --version)
npm_version=$(npm --version)
log "✅ Node.js ${node_version} e npm ${npm_version} instalados"

# =============================================================================
# CONFIGURAÇÃO DE CERTIFICADOS SSL PARA HTTPS
# =============================================================================

log "🔒 Configurando certificados SSL para interceptação Burp Suite..."

# Criar diretório para certificados
mkdir -p /etc/ssl/lab-certs
mkdir -p /var/log/ssl

# Gerar certificado auto-assinado para o laboratório
log "📜 Gerando certificados SSL auto-assinados..."

# Criar CA raiz para o laboratório
cat > /tmp/ca.conf << EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[req_distinguished_name]
C = BR
ST = Lab
L = Cybersec Lab
O = Pentest Laboratory
OU = Security Training
CN = Lab Root CA

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always
EOF

# Gerar chave e certificado CA
openssl genrsa -out /etc/ssl/lab-certs/lab-ca.key 4096
openssl req -new -x509 -days 365 -key /etc/ssl/lab-certs/lab-ca.key \
    -out /etc/ssl/lab-certs/lab-ca.crt -config /tmp/ca.conf

# Criar certificado para Juice Shop HTTPS
cat > /tmp/juiceshop.conf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = BR
ST = Lab
L = Cybersec Lab
O = OWASP Juice Shop
OU = Vulnerable Application
CN = juice-shop.lab

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = juice-shop.lab
DNS.2 = juiceshop.local
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = $(hostname -I | awk '{print $1}')
EOF

# Gerar chave e CSR para Juice Shop
openssl genrsa -out /etc/ssl/lab-certs/juiceshop.key 2048
openssl req -new -key /etc/ssl/lab-certs/juiceshop.key \
    -out /etc/ssl/lab-certs/juiceshop.csr -config /tmp/juiceshop.conf

# Assinar certificado Juice Shop com CA do lab
openssl x509 -req -in /etc/ssl/lab-certs/juiceshop.csr \
    -CA /etc/ssl/lab-certs/lab-ca.crt \
    -CAkey /etc/ssl/lab-certs/lab-ca.key \
    -CAcreateserial -out /etc/ssl/lab-certs/juiceshop.crt \
    -days 365 -extensions v3_req -extfile /tmp/juiceshop.conf

# Configurar permissões dos certificados
chmod 600 /etc/ssl/lab-certs/*.key
chmod 644 /etc/ssl/lab-certs/*.crt
chown root:root /etc/ssl/lab-certs/*

# Instalar CA do laboratório no sistema
cp /etc/ssl/lab-certs/lab-ca.crt /usr/local/share/ca-certificates/lab-ca.crt
update-ca-certificates

log "✅ Certificados SSL configurados para interceptação HTTPS"

# =============================================================================
# OWASP JUICE SHOP COM HTTPS
# =============================================================================

log "🧃 Configurando OWASP Juice Shop com suporte HTTPS..."

# Criar usuário para Juice Shop
useradd -m -s /bin/bash juiceshop
usermod -aG sudo juiceshop

# Diretório de instalação
JUICE_SHOP_DIR="/opt/juice-shop"
mkdir -p ${JUICE_SHOP_DIR}
chown juiceshop:juiceshop ${JUICE_SHOP_DIR}

# Clonar repositório do Juice Shop
cd ${JUICE_SHOP_DIR}
sudo -u juiceshop git clone https://github.com/juice-shop/juice-shop.git .

# Instalar dependências do Juice Shop
log "📦 Instalando dependências do Juice Shop..."
sudo -u juiceshop npm install --production

# Configuração personalizada com HTTPS
cat > ${JUICE_SHOP_DIR}/config/custom.yml << EOF
application:
  name: 'OWASP Juice Shop - Lab ${STUDENT_NAME} (HTTPS)'
  welcomeBanner:
    showOnFirstStart: true
    title: 'Laboratório de Pentest HTTPS'
    message: 'Bem-vindo ao ambiente de teste HTTPS, ${STUDENT_NAME}! Configure o Burp Suite para interceptar este tráfego.'

server:
  port: ${JUICE_SHOP_PORT}

challenges:
  showHints: true
  showMitigations: true
  
ctf:
  showFlagsInNotifications: true

hackingInstructor:
  isEnabled: true
EOF

chown juiceshop:juiceshop ${JUICE_SHOP_DIR}/config/custom.yml

# Criar script de inicialização HTTP
cat > /opt/juice-shop/start-juice-shop-http.sh << EOF
#!/bin/bash
cd /opt/juice-shop
export NODE_ENV=custom
export PORT=${JUICE_SHOP_PORT}
npm start
EOF

chmod +x /opt/juice-shop/start-juice-shop-http.sh
chown juiceshop:juiceshop /opt/juice-shop/start-juice-shop-http.sh

# Criar script de inicialização HTTPS
if [ "${ENABLE_HTTPS}" = "true" ]; then
    log "🔒 Configurando Juice Shop HTTPS na porta ${JUICE_SHOP_HTTPS_PORT}..."
    
    cat > /opt/juice-shop/start-juice-shop-https.sh << EOF
#!/bin/bash
cd /opt/juice-shop
export NODE_ENV=custom
export PORT=${JUICE_SHOP_HTTPS_PORT}
export HTTPS_PORT=${JUICE_SHOP_HTTPS_PORT}
export SSL_KEY=/etc/ssl/lab-certs/juiceshop.key
export SSL_CERT=/etc/ssl/lab-certs/juiceshop.crt

# Modificar package.json para suportar HTTPS
cp package.json package.json.backup
sed -i 's/"start": "node app"/"start": "node app --https-port=${JUICE_SHOP_HTTPS_PORT} --ssl-key=${SSL_KEY} --ssl-cert=${SSL_CERT}"/' package.json

npm start
EOF

    chmod +x /opt/juice-shop/start-juice-shop-https.sh
    chown juiceshop:juiceshop /opt/juice-shop/start-juice-shop-https.sh

    # Criar versão modificada do app.js para suportar HTTPS
    cat > /opt/juice-shop/app-https.js << 'EOF'
const fs = require('fs')
const https = require('https')
const app = require('./app')

const options = {
  key: fs.readFileSync(process.env.SSL_KEY || '/etc/ssl/lab-certs/juiceshop.key'),
  cert: fs.readFileSync(process.env.SSL_CERT || '/etc/ssl/lab-certs/juiceshop.crt')
}

const port = process.env.HTTPS_PORT || 3443

https.createServer(options, app).listen(port, () => {
  console.log(`Juice Shop HTTPS server listening on port ${port}`)
})
EOF

    chown juiceshop:juiceshop /opt/juice-shop/app-https.js
fi

# Criar serviços systemd
cat > /etc/systemd/system/juice-shop-http.service << EOF
[Unit]
Description=OWASP Juice Shop HTTP
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/opt/juice-shop
ExecStart=/opt/juice-shop/start-juice-shop-http.sh
Restart=always
RestartSec=10
Environment=NODE_ENV=custom
Environment=PORT=${JUICE_SHOP_PORT}

[Install]
WantedBy=multi-user.target
EOF

if [ "${ENABLE_HTTPS}" = "true" ]; then
    cat > /etc/systemd/system/juice-shop-https.service << EOF
[Unit]
Description=OWASP Juice Shop HTTPS
After=network.target

[Service]
Type=simple
User=juiceshop
WorkingDirectory=/opt/juice-shop
ExecStart=/usr/bin/node app-https.js
Restart=always
RestartSec=10
Environment=NODE_ENV=custom
Environment=HTTPS_PORT=${JUICE_SHOP#!/bin/bash
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