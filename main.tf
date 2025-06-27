# Laboratório de Cybersecurity - AWS EC2 com Terraform
# Kali Linux + OWASP Juice Shop + Burp Suite

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

variable "instance_type" {
  description = "Tipo da instância EC2"
  type        = string
  default     = "t3.medium"
}

variable "key_name" {
  description = "Nome da chave SSH (deve existir na AWS)"
  type        = string
}

variable "allowed_cidr" {
  description = "CIDR permitido para acesso SSH e HTTP"
  type        = string
  default     = "0.0.0.0/0"
}

variable "lab_name" {
  description = "Nome do laboratório"
  type        = string
  default     = "cybersec-lab"
}

# VPC
resource "aws_vpc" "cybersec_vpc" {
  cidr_block           = "10.0.0.0/16"
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

# Subnet Pública
resource "aws_subnet" "cybersec_subnet" {
  vpc_id                  = aws_vpc.cybersec_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.lab_name}-subnet"
  }
}

# Route Table
resource "aws_route_table" "cybersec_rt" {
  vpc_id = aws_vpc.cybersec_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cybersec_igw.id
  }

  tags = {
    Name = "${var.lab_name}-rt"
  }
}

# Route Table Association
resource "aws_route_table_association" "cybersec_rt_assoc" {
  subnet_id      = aws_subnet.cybersec_subnet.id
  route_table_id = aws_route_table.cybersec_rt.id
}

# Security Group
resource "aws_security_group" "cybersec_sg" {
  name        = "${var.lab_name}-sg"
  description = "Security group para laboratorio de cybersecurity"
  vpc_id      = aws_vpc.cybersec_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # HTTP para Juice Shop
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # HTTPS para Juice Shop
  ingress {
    from_port   = 3001
    to_port     = 3001
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # VNC para acesso remoto ao desktop
  ingress {
    from_port   = 5901
    to_port     = 5901
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # Burp Suite Proxy
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  # XRDP para Remote Desktop
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.lab_name}-sg"
  }
}

# Data source para pegar as zonas de disponibilidade
data "aws_availability_zones" "available" {
  state = "available"
}

# Data source para pegar a AMI do Kali Linux mais recente
data "aws_ami" "kali_linux" {
  most_recent = true
  owners      = ["679593333241"] # Kali Linux official

  filter {
    name   = "name"
    values = ["kali-linux-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# User Data Script para configurar o ambiente
locals {
  user_data = base64encode(templatefile("${path.module}/setup_lab.sh", {
    lab_name = var.lab_name
  }))
}

# Instância EC2 com Kali Linux
resource "aws_instance" "cybersec_lab" {
  ami                    = data.aws_ami.kali_linux.id
  instance_type          = var.instance_type
  key_name              = var.key_name
  vpc_security_group_ids = [aws_security_group.cybersec_sg.id]
  subnet_id             = aws_subnet.cybersec_subnet.id
  user_data             = local.user_data

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  tags = {
    Name = "${var.lab_name}-instance"
    Type = "cybersec-lab"
  }

  # Aguarda a instância estar rodando
  lifecycle {
    create_before_destroy = true
  }
}

# Outputs
output "instance_public_ip" {
  description = "IP público da instância"
  value       = aws_instance.cybersec_lab.public_ip
}

output "instance_dns" {
  description = "DNS público da instância"
  value       = aws_instance.cybersec_lab.public_dns
}

output "ssh_command" {
  description = "Comando SSH para conectar"
  value       = "ssh -i ${var.key_name}.pem kali@${aws_instance.cybersec_lab.public_ip}"
}

output "juice_shop_url" {
  description = "URL do OWASP Juice Shop"
  value       = "http://${aws_instance.cybersec_lab.public_ip}:3000"
}

output "vnc_connection" {
  description = "Conexão VNC para desktop remoto"
  value       = "${aws_instance.cybersec_lab.public_ip}:5901"
}

output "rdp_connection" {
  description = "Conexão RDP para desktop remoto"
  value       = "${aws_instance.cybersec_lab.public_ip}:3389"
}