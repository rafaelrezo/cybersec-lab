# Laboratório de Cybersecurity - Arquitetura Isolada
# Instância 1: Kali Linux + Burp Suite (Atacante)
# Instância 2: Ubuntu + Juice Shop (Alvo) - Isolada

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider AWS
provider "aws" {
  region = var.aws_region
}

# Variáveis
variable "aws_region" {
  description = "Região AWS"
  type        = string
  default     = "us-east-1"
}

variable "attacker_instance_type" {
  description = "Tipo da instância do atacante (Kali)"
  type        = string
  default     = "t3.medium"
}

variable "target_instance_type" {
  description = "Tipo da instância alvo (Juice Shop)"
  type        = string
  default     = "t3.small"
}

variable "key_name" {
  description = "Nome da chave SSH (deve existir na AWS)"
  type        = string
}

variable "allowed_cidr" {
  description = "CIDR permitido para acesso SSH e VNC ao Kali"
  type        = string
  default     = "0.0.0.0/0"
}

variable "lab_name" {
  description = "Nome do laboratório"
  type        = string
  default     = "cybersec-lab"
}

variable "vnc_password" {
  description = "Senha para acesso VNC"
  type        = string
  default     = "vncpassword"
  sensitive   = true
}

variable "rdp_password" {
  description = "Senha para acesso RDP (usuário ubuntu)"
  type        = string
  default     = "cybersec2024"
  sensitive   = true
}

# VPC Principal
resource "aws_vpc" "cybersec_vpc" {
  cidr_block           = "172.16.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.lab_name}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "cybersec_igw" {
  vpc_id = aws_vpc.cybersec_vpc.id

  tags = {
    Name = "${var.lab_name}-igw"
  }
}

# Subnet Pública - Para Kali (Atacante)
resource "aws_subnet" "attacker_subnet" {
  vpc_id                  = aws_vpc.cybersec_vpc.id
  cidr_block              = "172.16.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.lab_name}-attacker-subnet"
  }
}

# Subnet Privada - Para Juice Shop (Alvo)
resource "aws_subnet" "target_subnet" {
  vpc_id            = aws_vpc.cybersec_vpc.id
  cidr_block        = "172.16.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "${var.lab_name}-target-subnet"
  }
}

# Route Table para Subnet Pública (Atacante)
resource "aws_route_table" "attacker_rt" {
  vpc_id = aws_vpc.cybersec_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cybersec_igw.id
  }

  tags = {
    Name = "${var.lab_name}-attacker-rt"
  }
}

# Route Table para Subnet Privada (Alvo)
resource "aws_route_table" "target_rt" {
  vpc_id = aws_vpc.cybersec_vpc.id

  tags = {
    Name = "${var.lab_name}-target-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "attacker_rt_assoc" {
  subnet_id      = aws_subnet.attacker_subnet.id
  route_table_id = aws_route_table.attacker_rt.id
}

resource "aws_route_table_association" "target_rt_assoc" {
  subnet_id      = aws_subnet.target_subnet.id
  route_table_id = aws_route_table.target_rt.id
}

# Security Group - Kali (Atacante)
resource "aws_security_group" "attacker_sg" {
  name        = "${var.lab_name}-attacker-sg"
  description = "Security group para instancia atacante (Kali)"
  vpc_id      = aws_vpc.cybersec_vpc.id

  # SSH do mundo externo
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # VNC do mundo externo
  ingress {
    from_port   = 5901
    to_port     = 5901
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # RDP do mundo externo
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # Comunicação interna com subnet alvo
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["172.16.2.0/24"]
  }

  # Saída para internet
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-attacker-sg"
  }
}

# Security Group - Juice Shop (Alvo)
resource "aws_security_group" "target_sg" {
  name        = "${var.lab_name}-target-sg"
  description = "Security group para instancia alvo (Juice Shop)"
  vpc_id      = aws_vpc.cybersec_vpc.id

  # HTTP apenas da subnet do atacante
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["172.16.1.0/24"]
  }

  # SSH apenas da subnet do atacante
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["172.16.1.0/24"]
  }

  # Qualquer porta TCP da subnet do atacante (para testes)
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["172.16.1.0/24"]
  }

  # ICMP da subnet do atacante
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["172.16.1.0/24"]
  }

  # Saída limitada - apenas para subnet do atacante
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["172.16.1.0/24"]
  }

  # Permitir saída para internet apenas para downloads iniciais
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-target-sg"
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

# AMI do Ubuntu para ambas as instâncias
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
}

# User Data Scripts
locals {
  attacker_user_data = base64encode(<<-EOT
#!/bin/bash
export LAB_NAME="${var.lab_name}"
export TARGET_IP="${aws_instance.target.private_ip}"
export VNC_PASSWORD="${var.vnc_password}"
export RDP_PASSWORD="${var.rdp_password}"
export LOG_FILE="/var/log/attacker-setup.log"
export MAIN_USER="ubuntu"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE; }

log "=== CONFIGURANDO ARSENAL WEB SECURITY ==="
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y && apt-get upgrade -y

# Ferramentas essenciais
sudo apt-get install -y curl wget git vim ubuntu-desktop-minimal tightvncserver firefox openjdk-11-jdk python3-pip nmap sqlmap hydra gobuster nikto xrdp

# Configurar usuario com senha personalizada
sudo usermod -aG sudo $MAIN_USER
sudo echo "$MAIN_USER:$RDP_PASSWORD" | chpasswd

# Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
sudo echo "deb [signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list
sudo apt-get update -y && apt-get install -y docker-ce
sudo systemctl enable docker && systemctl start docker
sudo usermod -aG docker $MAIN_USER

# Burp Suite
cd /opt
wget -O burpsuite_community.jar "https://portswigger.net/burp/releases/download?product=community&type=jar"
echo '#!/bin/bash' > /usr/local/bin/burpsuite
echo 'cd /opt' >> /usr/local/bin/burpsuite
echo 'java -jar burpsuite_community.jar "$@"' >> /usr/local/bin/burpsuite
chmod +x /usr/local/bin/burpsuite

# VNC com senha personalizada - método mais robusto
log "Configurando VNC com senha personalizada..."

# Instalar expect para automação
sudo apt-get install -y expect

# Configurar VNC como usuário ubuntu
sudo -u $MAIN_USER bash << 'VNCSETUP'
# Criar diretório VNC
mkdir -p ~/.vnc

# Método 1: Usar vncpasswd com expect
expect << EOF
set timeout 10
spawn vncpasswd
expect "Password:"
send "$VNC_PASSWORD\r"
expect "Verify:"
send "$VNC_PASSWORD\r" 
expect "Would you like to enter a view-only password*"
send "n\r"
expect eof
EOF

# Se o método acima falhar, usar método direto
if [ ! -f ~/.vnc/passwd ]; then
  echo '$VNC_PASSWORD' | vncpasswd -f > ~/.vnc/passwd
  chmod 600 ~/.vnc/passwd
fi

# Criar xstartup
cat > ~/.vnc/xstartup << 'XSTART'
#!/bin/bash
unset SESSION_MANAGER
unset DBUS_SESSION_BUS_ADDRESS
export XDG_CURRENT_DESKTOP="ubuntu:GNOME"
export XDG_SESSION_DESKTOP="ubuntu"
export XDG_SESSION_TYPE="x11"

# Aguardar X11 estar pronto
sleep 2

# Iniciar GNOME
exec gnome-session
XSTART

chmod +x ~/.vnc/xstartup

# Parar qualquer VNC existente
vncserver -kill :1 >/dev/null 2>&1 || true

# Aguardar um pouco
sleep 2

# Iniciar VNC server
sudo vncserver :1 -geometry 1440x900 -depth 24 -localhost no

# Verificar se iniciou
sleep 3
if netstat -tlnp 2>/dev/null | grep -q 5901; then
  echo "VNC iniciado com sucesso na porta 5901"
else
  echo "ERRO: VNC não conseguiu iniciar"
  # Tentar novamente com configurações diferentes
  vncserver -kill :1 >/dev/null 2>&1 || true
  sleep 2
  DISPLAY=:1 vncserver :1 -geometry 1440x900 -depth 24 -localhost no
fi
VNCSETUP

# Configurar XRDP
sudo systemctl enable xrdp && systemctl start xrdp
sudo adduser xrdp ssl-cert

# Wordlists
mkdir -p /usr/share/wordlists/passwords
echo -e "admin\npassword\n123456\npassword123\nadmin123\nroot\ntest\nguest" > /usr/share/wordlists/passwords/common.txt

mkdir -p /usr/share/wordlists/xss
echo -e "<script>alert('XSS')</script>\n<img src=x onerror=alert('XSS')>\n<svg onload=alert('XSS')>" > /usr/share/wordlists/xss/basic.txt

mkdir -p /usr/share/wordlists/directories
echo -e "admin\nadministrator\nlogin\napi\nrest\nbackup\nconfig\ntest\ndev" > /usr/share/wordlists/directories/common.txt

# Desktop shortcuts
sudo -u $MAIN_USER mkdir -p /home/$MAIN_USER/Desktop/WebAttacks

cat > /home/$MAIN_USER/Desktop/TARGET-JuiceShop.desktop << 'DESKTOP1'
[Desktop Entry]
Name=TARGET - Juice Shop
Exec=firefox http://$TARGET_IP:3000
Icon=firefox
Terminal=false
Type=Application
DESKTOP1

cat > /home/$MAIN_USER/Desktop/WebAttacks/BurpSuite.desktop << 'DESKTOP2'
[Desktop Entry]
Name=Burp Suite
Exec=burpsuite
Icon=applications-internet
Terminal=false
Type=Application
DESKTOP2

cat > /home/$MAIN_USER/Desktop/WebAttacks/OWASP-ZAP.desktop << 'DESKTOP3'
[Desktop Entry]
Name=OWASP ZAP
Exec=zaproxy
Icon=applications-internet
Terminal=false
Type=Application
DESKTOP3

chmod +x /home/$MAIN_USER/Desktop/*.desktop /home/$MAIN_USER/Desktop/*/*.desktop
chown -R $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/

# Aliases
sudo -u $MAIN_USER bash -c "
  echo 'export TARGET_IP=\"$TARGET_IP\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias target=\"firefox http://$TARGET_IP:3000 &\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias burp=\"burpsuite &\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias zap=\"zaproxy &\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias sql-test=\"sqlmap -u http://$TARGET_IP:3000 --batch\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias dir-scan=\"gobuster dir -u http://$TARGET_IP:3000 -w /usr/share/wordlists/directories/common.txt\"' >> /home/$MAIN_USER/.bashrc
  echo 'alias arsenal=\"echo WEB TOOLS: sqlmap, burp, zap, hydra, gobuster, nikto\"' >> /home/$MAIN_USER/.bashrc
"

# Attack script
cat > /home/$MAIN_USER/Desktop/attack_suite.sh << 'ATTACK1'
#!/bin/bash
echo "=== JUICE SHOP ATTACK SUITE ==="
echo "1) SQL Injection test"
echo "2) Directory scan"
echo "3) Nikto vulnerability scan"
read -p "Select (1-3): " choice
case $choice in
  1) sqlmap -u "http://$TARGET_IP:3000/rest/user/login" --batch ;;
  2) gobuster dir -u http://$TARGET_IP:3000 -w /usr/share/wordlists/directories/common.txt ;;
  3) nikto -h http://$TARGET_IP:3000 ;;
esac
ATTACK1

chmod +x /home/$MAIN_USER/Desktop/attack_suite.sh
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/attack_suite.sh

# Criar arquivo com informacoes de acesso
cat > /home/$MAIN_USER/Desktop/ACESSO_LAB.txt << ACCESSINFO
=== INFORMACOES DE ACESSO DO LABORATORIO ===

VNC (Recomendado):
- Endereco: IP_PUBLICO:5901
- Senha: $VNC_PASSWORD

RDP (Alternativo):
- Endereco: IP_PUBLICO:3389
- Usuario: ubuntu
- Senha: $RDP_PASSWORD

SSH:
- Comando: ssh -i chave.pem ubuntu@IP_PUBLICO
- Senha: $RDP_PASSWORD

TARGET:
- Juice Shop: http://$TARGET_IP:3000
- O alvo so e acessivel internamente

COMANDOS UTEIS:
- target: Abre Juice Shop
- burp: Abre Burp Suite
- arsenal: Lista ferramentas
- lab-status: Status do laboratorio
ACCESSINFO

chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/Desktop/ACESSO_LAB.txt

# Firewall
ufw --force enable
ufw allow ssh && ufw allow 5901/tcp && ufw allow 3389/tcp

# Status script
cat > /usr/local/bin/lab-status << 'STATUS1'
#!/bin/bash
echo "=== LAB STATUS ==="
netstat -tlnp | grep -q 5901 && echo "VNC: ACTIVE" || echo "VNC: INACTIVE"
netstat -tlnp | grep -q 3389 && echo "RDP: ACTIVE" || echo "RDP: INACTIVE"
ping -c 1 $TARGET_IP >/dev/null 2>&1 && echo "Target: OK" || echo "Target: FAIL"

echo ""
echo "=== VNC DETAILS ==="
if netstat -tlnp | grep -q 5901; then
  echo "VNC está rodando na porta 5901"
  echo "Senha configurada: $VNC_PASSWORD"
  ls -la /home/ubuntu/.vnc/passwd 2>/dev/null && echo "Arquivo de senha existe" || echo "ERRO: Arquivo de senha não encontrado"
else
  echo "VNC NÃO está rodando"
  echo "Logs do VNC:"
  tail -5 /home/ubuntu/.vnc/*.log 2>/dev/null || echo "Nenhum log encontrado"
fi

echo ""
echo "=== COMANDOS PARA RESTART VNC ==="
echo "sudo -u ubuntu vncserver -kill :1"
echo "sudo -u ubuntu vncserver :1 -geometry 1440x900 -depth 24 -localhost no"
STATUS1
chmod +x /usr/local/bin/lab-status

# Criar script para resetar VNC se necessario
cat > /usr/local/bin/reset-vnc << 'RESETVNC'
#!/bin/bash
echo "=== RESETANDO VNC ==="

# Parar VNC
sudo -u ubuntu vncserver -kill :1 >/dev/null 2>&1 || true
sleep 2

# Recriar senha
sudo -u ubuntu bash -c "
  echo '$VNC_PASSWORD' | vncpasswd -f > ~/.vnc/passwd
  chmod 600 ~/.vnc/passwd
"

# Restart VNC
sudo -u ubuntu vncserver :1 -geometry 1440x900 -depth 24 -localhost no

# Verificar
sleep 3
if netstat -tlnp | grep -q 5901; then
  echo "✓ VNC resetado com sucesso"
  echo "Endereço: $(curl -s ifconfig.me):5901"
  echo "Senha: $VNC_PASSWORD"
else
  echo "✗ Falha ao resetar VNC"
  echo "Logs:"
  tail -10 /home/ubuntu/.vnc/*.log 2>/dev/null
fi
RESETVNC
chmod +x /usr/local/bin/reset-vnc

# Verificação final e logs
log "=== ARSENAL CONFIGURADO ==="
log "VNC: IP:5901 (senha: $VNC_PASSWORD)"
log "RDP: IP:3389 (usuario: ubuntu, senha: $RDP_PASSWORD)"

# Verificar status final do VNC
if netstat -tlnp | grep -q 5901; then
  log "✓ VNC ATIVO e funcionando"
else
  log "✗ VNC FALHOU - execute 'lab-status' para debug"
  # Tentar restart automático
  log "Tentando restart automático do VNC..."
  sudo -u $MAIN_USER vncserver -kill :1 >/dev/null 2>&1 || true
  sleep 2
  sudo -u $MAIN_USER vncserver :1 -geometry 1440x900 -depth 24 -localhost no
  sleep 3
  netstat -tlnp | grep -q 5901 && log "✓ VNC FUNCIONOU após restart" || log "✗ VNC ainda com problema"
fi
EOT
  )

  target_user_data = base64encode(<<-EOT
#!/bin/bash
export LOG_FILE="/var/log/target-setup.log"
export MAIN_USER="ubuntu"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE; }

log "=== CONFIGURANDO ALVO ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y && apt-get upgrade -y

apt-get install -y curl wget git vim net-tools fail2ban

usermod -aG sudo $MAIN_USER
echo "$MAIN_USER:target2024" | chpasswd

# Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list
apt-get update -y && apt-get install -y docker-ce
systemctl enable docker && systemctl start docker

# Juice Shop
docker pull bkimminich/juice-shop:latest
docker run -d --name juice-shop --restart unless-stopped -p 3000:3000 bkimminich/juice-shop:latest

# Firewall
ufw --force enable
ufw allow from 172.16.1.0/24 to any port 22
ufw allow from 172.16.1.0/24 to any port 3000
ufw deny from any to any

systemctl enable fail2ban && systemctl start fail2ban

echo "ALVO: Juice Shop na porta 3000" > /home/$MAIN_USER/TARGET_INFO.txt
chown $MAIN_USER:$MAIN_USER /home/$MAIN_USER/TARGET_INFO.txt

log "=== ALVO CONFIGURADO ==="
EOT
  )
}

# Instância Atacante - Kali Linux
resource "aws_instance" "attacker" {
  ami                    = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type          = var.attacker_instance_type
  key_name              = var.key_name
  vpc_security_group_ids = [aws_security_group.attacker_sg.id]
  subnet_id             = aws_subnet.attacker_subnet.id
  user_data             = local.attacker_user_data

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = {
    Name = "${var.lab_name}-attacker"
    Type = "cybersec-attacker"
    OS   = "Ubuntu + Pentesting Tools"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Instância Alvo - Juice Shop
resource "aws_instance" "target" {
  ami                    = data.aws_ssm_parameter.ubuntu_ami.value
  instance_type          = var.target_instance_type
  key_name              = var.key_name
  vpc_security_group_ids = [aws_security_group.target_sg.id]
  subnet_id             = aws_subnet.target_subnet.id
  user_data             = local.target_user_data

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name = "${var.lab_name}-target"
    Type = "cybersec-target"
    OS   = "Ubuntu + Juice Shop"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Outputs
output "attacker_public_ip" {
  description = "IP público da instância atacante (Kali)"
  value       = aws_instance.attacker.public_ip
}

output "attacker_private_ip" {
  description = "IP privado da instância atacante"
  value       = aws_instance.attacker.private_ip
}

output "target_private_ip" {
  description = "IP privado da instância alvo (Juice Shop)"
  value       = aws_instance.target.private_ip
}

output "ssh_attacker_command" {
  description = "Comando SSH para conectar no atacante"
  value       = "ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker.public_ip}"
}

output "vnc_connection" {
  description = "Conexão VNC para desktop remoto"
  value       = "${aws_instance.attacker.public_ip}:5901"
}

output "rdp_connection" {
  description = "Conexão RDP para desktop remoto"
  value       = "${aws_instance.attacker.public_ip}:3389"
}

output "juice_shop_url_from_attacker" {
  description = "URL do Juice Shop (acesso interno do Kali)"
  value       = "http://${aws_instance.target.private_ip}:3000"
}

output "access_credentials" {
  description = "Credenciais de acesso ao laboratório"
  value = {
    vnc_address  = "${aws_instance.attacker.public_ip}:5901"
    vnc_password = var.vnc_password
    rdp_address  = "${aws_instance.attacker.public_ip}:3389"
    rdp_username = "ubuntu"
    rdp_password = var.rdp_password
    ssh_command  = "ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker.public_ip}"
  }
  sensitive = true
}

output "lab_instructions" {
  description = "Instruções para usar o laboratório"
  value = <<-EOT
    === LABORATÓRIO DE CYBERSECURITY ===
    
    ARQUITETURA:
    - Atacante (Kali): ${aws_instance.attacker.public_ip} (público)
    - Alvo (Juice Shop): ${aws_instance.target.private_ip} (privado)
    
    ACESSO RECOMENDADO - VNC:
    1. Endereço: ${aws_instance.attacker.public_ip}:5901
    2. Senha: ${var.vnc_password}
    3. Cliente: RealVNC, TightVNC, Remmina
    
    ACESSO ALTERNATIVO - RDP:
    1. Endereço: ${aws_instance.attacker.public_ip}:3389
    2. Usuário: ubuntu
    3. Senha: ${var.rdp_password}
    
    ACESSO SSH:
    ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker.public_ip}
    Senha: ${var.rdp_password}
    
    ALVO (INTERNO):
    - Juice Shop: http://${aws_instance.target.private_ip}:3000
    - Só acessível da instância atacante
    
    FERRAMENTAS NO ATACANTE:
    - Burp Suite: comando 'burp'
    - OWASP ZAP: comando 'zap'  
    - SQLMap: comando 'sql-test'
    - Gobuster: comando 'dir-scan'
    - Arsenal completo: comando 'arsenal'
    
    COMANDOS ÚTEIS:
    - target: Abre Juice Shop no Firefox
    - lab-status: Verifica status do laboratório
    - reset-vnc: Reinicia VNC se necessário
    - attack_suite.sh: Script interativo de ataques
  EOT
  sensitive = true
}