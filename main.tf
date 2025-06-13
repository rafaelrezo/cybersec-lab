# =============================================================================
# MAIN.TF - Laboratório de Cibersegurança com Kali Linux + OWASP Juice Shop
# AWS Academy Compatible - Configurado para Burp Suite HTTPS Intercept
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Provider AWS configurado para AWS Academy
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CyberSec-Lab"
      Environment = var.environment
      Student     = var.student_name
      Course      = "Pentest-Training"
      Lab         = "Kali-JuiceShop-Burp"
    }
  }
}

# Data sources
data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# AMI do Kali Linux (oficial)
data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"] # Kali Linux Official

  filter {
    name   = "name"
    values = ["kali-linux-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

# AMI do Ubuntu para Juice Shop
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# =============================================================================
# NETWORKING
# =============================================================================

# VPC para o laboratório
resource "aws_vpc" "lab_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.lab_name}-vpc"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.lab_vpc.id

  tags = {
    Name = "${var.lab_name}-igw"
  }
}

# Subnet para Kali (atacante)
resource "aws_subnet" "kali_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.kali_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.lab_name}-kali-subnet"
    Type = "Attacker"
  }
}

# Subnet para Juice Shop (alvo)
resource "aws_subnet" "target_subnet" {
  vpc_id                  = aws_vpc.lab_vpc.id
  cidr_block              = var.target_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.lab_name}-target-subnet"
    Type = "Target"
  }
}

# Route table pública
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab_igw.id
  }

  tags = {
    Name = "${var.lab_name}-public-rt"
  }
}

# Associações das subnets com route table
resource "aws_route_table_association" "kali_rta" {
  subnet_id      = aws_subnet.kali_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "target_rta" {
  subnet_id      = aws_subnet.target_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

# Security Group para Kali Linux
resource "aws_security_group" "kali_sg" {
  name_prefix = "${var.lab_name}-kali-sg"
  vpc_id      = aws_vpc.lab_vpc.id
  description = "Security group for Kali Linux - Attacker machine with Burp Suite"

  # SSH
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # VNC para acesso remoto gráfico
  ingress {
    description = "VNC"
    from_port   = 5901
    to_port     = 5910
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # RDP (opcional)
  ingress {
    description = "RDP"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Burp Suite Proxy (8080)
  ingress {
    description = "Burp Suite Proxy"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Burp Collaborator (opcional)
  ingress {
    description = "Burp Collaborator"
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # HTTP/HTTPS para ferramentas web
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Acesso interno entre máquinas do lab
  ingress {
    description = "Internal Lab Access"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Saída irrestrita
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-kali-sg"
    Type = "Attacker"
  }
}

# Security Group para Juice Shop (alvo vulnerável)
resource "aws_security_group" "target_sg" {
  name_prefix = "${var.lab_name}-target-sg"
  vpc_id      = aws_vpc.lab_vpc.id
  description = "Security group for vulnerable targets with HTTPS support"

  # SSH (para administração)
  ingress {
    description = "SSH Admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # Juice Shop HTTP
  ingress {
    description = "Juice Shop HTTP"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.allowed_cidr_blocks[0]]
  }

  # Juice Shop HTTPS
  ingress {
    description = "Juice Shop HTTPS"
    from_port   = 3443
    to_port     = 3443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.allowed_cidr_blocks[0]]
  }

  # HTTP/HTTPS padrão
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.allowed_cidr_blocks[0]]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr, var.allowed_cidr_blocks[0]]
  }

  # Portas adicionais para outros alvos vulneráveis
  ingress {
    description = "Additional Vulnerable Services"
    from_port   = 8000
    to_port     = 8999
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Acesso interno do laboratório
  ingress {
    description = "Internal Lab Access"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  # Saída restrita (apenas essencial)
  egress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-target-sg"
    Type = "Target"
  }
}

# =============================================================================
# INSTÂNCIAS EC2
# =============================================================================

# Key Pair para acesso SSH
resource "aws_key_pair" "lab_key" {
  count      = var.ssh_public_key != "" ? 1 : 0
  key_name   = "${var.lab_name}-keypair"
  public_key = var.ssh_public_key

  tags = {
    Name = "${var.lab_name}-keypair"
  }
}

# User data para Kali Linux
locals {
  kali_user_data = base64encode(templatefile("${path.module}/kali_setup.sh", {
    student_name   = var.student_name
    vnc_password   = var.vnc_password
    lab_name       = var.lab_name
    burp_proxy_ip  = aws_instance.kali_linux.private_ip
    target_ip      = aws_instance.vulnerable_targets.private_ip
    enable_burp_pro = var.enable_burp_professional
  }))

  target_user_data = base64encode(templatefile("${path.module}/target_setup.sh", {
    student_name      = var.student_name
    lab_name          = var.lab_name
    juice_shop_port   = var.juice_shop_port
    juice_shop_https_port = var.juice_shop_https_port
    enable_https      = var.enable_https_targets
    kali_ip          = aws_instance.kali_linux.private_ip
  }))
}

# Instância Kali Linux (Atacante)
resource "aws_instance" "kali_linux" {
  ami                     = data.aws_ami.kali_linux.id
  instance_type          = var.kali_instance_type
  key_name               = var.ssh_public_key != "" ? aws_key_pair.lab_key[0].key_name : null
  vpc_security_group_ids = [aws_security_group.kali_sg.id]
  subnet_id              = aws_subnet.kali_subnet.id
  user_data_base64       = local.kali_user_data

  root_block_device {
    volume_type           = "gp3"
    volume_size          = var.kali_disk_size
    delete_on_termination = true
    encrypted            = true

    tags = {
      Name = "${var.lab_name}-kali-volume"
    }
  }

  tags = {
    Name = "${var.lab_name}-kali-linux"
    Type = "Attacker"
    OS   = "Kali Linux"
  }
}

# Instância para alvos vulneráveis (Juice Shop + outros)
resource "aws_instance" "vulnerable_targets" {
  ami                     = data.aws_ami.ubuntu.id
  instance_type          = var.target_instance_type
  key_name               = var.ssh_public_key != "" ? aws_key_pair.lab_key[0].key_name : null
  vpc_security_group_ids = [aws_security_group.target_sg.id]
  subnet_id              = aws_subnet.target_subnet.id
  user_data_base64       = local.target_user_data

  root_block_device {
    volume_type           = "gp3"
    volume_size          = var.target_disk_size
    delete_on_termination = true
    encrypted            = true

    tags = {
      Name = "${var.lab_name}-target-volume"
    }
  }

  tags = {
    Name = "${var.lab_name}-vulnerable-targets"
    Type = "Target"
    OS   = "Ubuntu"
  }
}

# Elastic IPs (opcionais)
resource "aws_eip" "kali_eip" {
  count    = var.use_elastic_ip ? 1 : 0
  instance = aws_instance.kali_linux.id
  domain   = "vpc"

  tags = {
    Name = "${var.lab_name}-kali-eip"
  }

  depends_on = [aws_internet_gateway.lab_igw]
}

resource "aws_eip" "target_eip" {
  count    = var.use_elastic_ip ? 1 : 0
  instance = aws_instance.vulnerable_targets.id
  domain   = "vpc"

  tags = {
    Name = "${var.lab_name}-target-eip"
  }

  depends_on = [aws_internet_gateway.lab_igw]
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "lab_summary" {
  description = "Resumo do laboratório criado"
  value = {
    student_name = var.student_name
    lab_name     = var.lab_name
    aws_region   = var.aws_region
    vpc_id       = aws_vpc.lab_vpc.id
    burp_configured = "Burp Suite configurado para interceptação HTTPS"
  }
}

output "kali_linux_access" {
  description = "Informações de acesso ao Kali Linux"
  value = {
    public_ip = var.use_elastic_ip ? aws_eip.kali_eip[0].public_ip : aws_instance.kali_linux.public_ip
    private_ip = aws_instance.kali_linux.private_ip
    ssh_command = var.ssh_public_key != "" ? (
      var.use_elastic_ip ?
      "ssh -i ~/.ssh/lab_key.pem kali@${aws_eip.kali_eip[0].public_ip}" :
      "ssh -i ~/.ssh/lab_key.pem kali@${aws_instance.kali_linux.public_ip}"
    ) : "SSH key not configured"
    vnc_access = var.use_elastic_ip ? 
      "VNC Viewer -> ${aws_eip.kali_eip[0].public_ip}:5901" :
      "VNC Viewer -> ${aws_instance.kali_linux.public_ip}:5901"
    vnc_password = "Configure com a variável vnc_password"
    burp_proxy = "${aws_instance.kali_linux.private_ip}:8080"
  }
}

output "target_access" {
  description = "Informações de acesso aos alvos vulneráveis"
  value = {
    public_ip = var.use_elastic_ip ? aws_eip.target_eip[0].public_ip : aws_instance.vulnerable_targets.public_ip
    private_ip = aws_instance.vulnerable_targets.private_ip
    juice_shop_http = var.use_elastic_ip ?
      "http://${aws_eip.target_eip[0].public_ip}:${var.juice_shop_port}" :
      "http://${aws_instance.vulnerable_targets.public_ip}:${var.juice_shop_port}"
    juice_shop_https = var.enable_https_targets ? (
      var.use_elastic_ip ?
      "https://${aws_eip.target_eip[0].public_ip}:${var.juice_shop_https_port}" :
      "https://${aws_instance.vulnerable_targets.public_ip}:${var.juice_shop_https_port}"
    ) : "HTTPS disabled"
    ssh_command = var.ssh_public_key != "" ? (
      var.use_elastic_ip ?
      "ssh -i ~/.ssh/lab_key.pem ubuntu@${aws_eip.target_eip[0].public_ip}" :
      "ssh -i ~/.ssh/lab_key.pem ubuntu@${aws_instance.vulnerable_targets.public_ip}"
    ) : "SSH key not configured"
  }
}

output "burp_suite_setup" {
  description = "Configurações do Burp Suite para interceptação HTTPS"
  value = {
    proxy_listener = "${aws_instance.kali_linux.private_ip}:8080"
    ca_certificate = "Baixar em: http://${aws_instance.kali_linux.private_ip}:8080/cert"
    browser_proxy = "Configure browser para usar ${aws_instance.kali_linux.private_ip}:8080"
    https_intercept = "Configurado automaticamente para interceptar HTTPS"
    target_hosts = [
      "${aws_instance.vulnerable_targets.private_ip}:${var.juice_shop_port}",
      var.enable_https_targets ? "${aws_instance.vulnerable_targets.private_ip}:${var.juice_shop_https_port}" : null
    ]
  }
}

output "lab_network" {
  description = "Informações da rede do laboratório"
  value = {
    vpc_cidr = var.vpc_cidr
    kali_subnet = var.kali_subnet_cidr
    target_subnet = var.target_subnet_cidr
    internal_access = "Kali pode acessar targets diretamente via IPs privados"
    burp_network = "Tráfego roteado via Burp Suite proxy em ${aws_instance.kali_linux.private_ip}:8080"
  }
}

output "security_warnings" {
  description = "Avisos importantes de segurança"
  value = {
    warning1 = "⚠️  Este laboratório contém aplicações VULNERÁVEIS por design"
    warning2 = "⚠️  Use apenas para fins educacionais em ambiente isolado"
    warning3 = "⚠️  Burp Suite está configurado para interceptar tráfego HTTPS"
    warning4 = "⚠️  Certificados SSL são auto-assinados (aceite warnings do browser)"
    warning5 = "⚠️  Monitore custos na AWS - destrua o lab quando não usar"
  }
}

output "burp_suite_instructions" {
  description = "Instruções para usar o Burp Suite"
  value = {
    step1 = "1. Conecte via VNC no Kali Linux"
    step2 = "2. Abra Burp Suite (ícone na área de trabalho)"
    step3 = "3. Configure browser proxy: ${aws_instance.kali_linux.private_ip}:8080"
    step4 = "4. Baixe certificado CA: http://${aws_instance.kali_linux.private_ip}:8080/cert"
    step5 = "5. Instale certificado no browser"
    step6 = "6. Acesse targets HTTPS e intercete requisições"
    step7 = "7. Use Burp Scanner, Intruder e Repeater para análise"
  }
}

output "next_steps" {
  description = "Próximos passos após o deploy"
  value = {
    step1 = "Aguarde 10-15 minutos para conclusão da instalação"
    step2 = "Acesse o Kali via VNC usando as credenciais configuradas"
    step3 = "Configure Burp Suite proxy no browser (instruções no output)"
    step4 = "Teste interceptação HTTPS no Juice Shop"
    step5 = "Inicie os exercícios de pentest com Burp Suite"
    step6 = "Execute 'terraform destroy' quando terminar para evitar custos"
  }
}