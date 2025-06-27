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

# User Data para Kali (Atacante)
locals {
  attacker_user_data = base64encode(templatefile("${path.module}/setup_attacker.sh", {
    lab_name       = var.lab_name
    target_ip      = aws_instance.target.private_ip
  }))
  
  target_user_data = base64encode(templatefile("${path.module}/setup_target.sh", {
    lab_name = var.lab_name
  }))
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
    OS   = "Kali Linux Tools"
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
  description = "Conexão VNC para desktop do atacante"
  value       = "${aws_instance.attacker.public_ip}:5901"
}

output "rdp_connection" {
  description = "Conexão RDP para desktop do atacante"
  value       = "${aws_instance.attacker.public_ip}:3389"
}

output "juice_shop_url_from_attacker" {
  description = "URL do Juice Shop (acesso interno do Kali)"
  value       = "http://${aws_instance.target.private_ip}:3000"
}

output "lab_instructions" {
  description = "Instruções para usar o laboratório"
  value = <<-EOT
    === LABORATÓRIO DE CYBERSECURITY ===
    
    ARQUITETURA:
    - Atacante (Kali): ${aws_instance.attacker.public_ip} (público)
    - Alvo (Juice Shop): ${aws_instance.target.private_ip} (privado)
    
    ACESSO:
    1. SSH no Kali: ssh -i ${var.key_name}.pem ubuntu@${aws_instance.attacker.public_ip}
    2. VNC: ${aws_instance.attacker.public_ip}:5901 (senha: vncpassword)
    3. RDP: ${aws_instance.attacker.public_ip}:3389 (ubuntu:cybersec2024)
    
    TESTES:
    - Do Kali, acesse: http://${aws_instance.target.private_ip}:3000
    - O Juice Shop só é acessível internamente do Kali
    
    FERRAMENTAS NO KALI:
    - Burp Suite: comando 'burpsuite'
    - Metasploit: comando 'msfconsole'  
    - Nmap, nikto, sqlmap, etc.
  EOT
}