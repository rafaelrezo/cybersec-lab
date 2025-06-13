# =============================================================================
# VARIABLES.TF - Variáveis do Laboratório de Cibersegurança
# Configurações para AWS Academy
# =============================================================================

# Configurações da AWS Academy
variable "aws_region" {
  description = "Região AWS (configurada automaticamente no AWS Academy)"
  type        = string
  default     = "us-east-1"
  
  validation {
    condition = contains([
      "us-east-1", "us-east-2", "us-west-1", "us-west-2",
      "eu-west-1", "eu-west-2", "eu-central-1",
      "ap-southeast-1", "ap-southeast-2", "ap-northeast-1"
    ], var.aws_region)
    error_message = "Região deve ser uma das suportadas pelo AWS Academy."
  }
}

# Informações do Estudante
variable "student_name" {
  description = "Nome do estudante (usado em tags e identificação)"
  type        = string
  
  validation {
    condition     = length(var.student_name) > 0 && length(var.student_name) <= 50
    error_message = "Nome deve ter entre 1 e 50 caracteres."
  }
}

variable "lab_name" {
  description = "Nome do laboratório (prefixo para recursos)"
  type        = string
  default     = "cybersec-lab"
  
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.lab_name))
    error_message = "Nome deve conter apenas letras minúsculas, números e hífens."
  }
}

variable "environment" {
  description = "Ambiente do laboratório"
  type        = string
  default     = "academy"
  
  validation {
    condition     = contains(["academy", "lab", "training"], var.environment)
    error_message = "Ambiente deve ser: academy, lab ou training."
  }
}

# Configurações de Rede
variable "vpc_cidr" {
  description = "CIDR block para a VPC do laboratório"
  type        = string
  default     = "10.0.0.0/16"
  
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "CIDR deve ser válido."
  }
}

variable "kali_subnet_cidr" {
  description = "CIDR para subnet do Kali Linux (atacante)"
  type        = string
  default     = "10.0.1.0/24"
  
  validation {
    condition     = can(cidrhost(var.kali_subnet_cidr, 0))
    error_message = "CIDR da subnet Kali deve ser válido."
  }
}

variable "target_subnet_cidr" {
  description = "CIDR para subnet dos alvos vulneráveis"
  type        = string
  default     = "10.0.2.0/24"
  
  validation {
    condition     = can(cidrhost(var.target_subnet_cidr, 0))
    error_message = "CIDR da subnet target deve ser válido."
  }
}

variable "allowed_cidr_blocks" {
  description = "CIDRs permitidos para acesso externo (seu IP)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
  
  validation {
    condition = length(var.allowed_cidr_blocks) > 0 && alltrue([
      for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "Todos os CIDRs devem ser válidos."
  }
}

# Configurações das Instâncias
variable "kali_instance_type" {
  description = "Tipo da instância para Kali Linux"
  type        = string
  default     = "t3.medium"
  
  validation {
    condition = contains([
      "t3.small", "t3.medium", "t3.large", "t3.xlarge",
      "m5.large", "m5.xlarge", "m5.2xlarge"
    ], var.kali_instance_type)
    error_message = "Tipo deve ser adequado para Kali Linux (mín. t3.medium recomendado)."
  }
}

variable "target_instance_type" {
  description = "Tipo da instância para alvos vulneráveis"
  type        = string
  default     = "t3.small"
  
  validation {
    condition = contains([
      "t3.micro", "t3.small", "t3.medium", "t3.large",
      "m5.large", "m5.xlarge"
    ], var.target_instance_type)
    error_message = "Tipo de instância deve ser suportado."
  }
}

variable "kali_disk_size" {
  description = "Tamanho do disco para Kali Linux (GB)"
  type        = number
  default     = 30
  
  validation {
    condition     = var.kali_disk_size >= 25 && var.kali_disk_size <= 100
    error_message = "Disco do Kali deve ter entre 25 e 100 GB."
  }
}

variable "target_disk_size" {
  description = "Tamanho do disco para alvos (GB)"
  type        = number
  default     = 20
  
  validation {
    condition     = var.target_disk_size >= 15 && var.target_disk_size <= 50
    error_message = "Disco dos alvos deve ter entre 15 e 50 GB."
  }
}

variable "use_elastic_ip" {
  description = "Usar Elastic IP (recomendado para labs longos)"
  type        = bool
  default     = false  # False por padrão no Academy para economia
}

# Configurações de Acesso
variable "ssh_public_key" {
  description = "Chave SSH pública para acesso às instâncias"
  type        = string
  default     = ""
  
  validation {
    condition = var.ssh_public_key == "" || can(regex("^(ssh-rsa|ssh-ed25519|ecdsa-sha2)", var.ssh_public_key))
    error_message = "Chave SSH deve estar em formato válido ou vazia."
  }
}

variable "vnc_password" {
  description = "Senha para acesso VNC ao Kali Linux"
  type        = string
  default     = "kalilab123"
  sensitive   = true
  
  validation {
    condition     = length(var.vnc_password) >= 8 && length(var.vnc_password) <= 20
    error_message = "Senha VNC deve ter entre 8 e 20 caracteres."
  }
}

# Configurações do Juice Shop
variable "juice_shop_port" {
  description = "Porta para o OWASP Juice Shop"
  type        = number
  default     = 3000
  
  validation {
    condition     = var.juice_shop_port > 1024 && var.juice_shop_port < 65536
    error_message = "Porta deve estar entre 1024 e 65535."
  }
}

# Configurações do Laboratório
variable "enable_additional_targets" {
  description = "Habilitar alvos vulneráveis adicionais (DVWA, WebGoat)"
  type        = bool
  default     = true
}

variable "enable_kali_gui" {
  description = "Habilitar interface gráfica no Kali via VNC"
  type        = bool
  default     = true
}

variable "install_additional_tools" {
  description = "Instalar ferramentas extras de pentest"
  type        = bool
  default     = true
}

# Configurações AWS Academy específicas
variable "aws_academy_session_duration" {
  description = "Duração da sessão AWS Academy (horas)"
  type        = number
  default     = 4
  
  validation {
    condition     = var.aws_academy_session_duration >= 1 && var.aws_academy_session_duration <= 8
    error_message = "Sessão deve durar entre 1 e 8 horas."
  }
}

variable "auto_shutdown_enabled" {
  description = "Habilitar desligamento automático antes do fim da sessão"
  type        = bool
  default     = true
}

variable "shutdown_warning_minutes" {
  description = "Minutos de aviso antes do desligamento automático"
  type        = number
  default     = 30
  
  validation {
    condition     = var.shutdown_warning_minutes >= 10 && var.shutdown_warning_minutes <= 60
    error_message = "Aviso deve ser entre 10 e 60 minutos."
  }
}

# Configurações de Monitoramento
variable "enable_cloudwatch" {
  description = "Habilitar CloudWatch (pode gerar custos no Academy)"
  type        = bool
  default     = false
}

variable "enable_flow_logs" {
  description = "Habilitar VPC Flow Logs para análise de tráfego"
  type        = bool
  default     = false
}

# Configurações de Backup
variable "enable_snapshot" {
  description = "Criar snapshot das instâncias para backup"
  type        = bool
  default     = false
}

variable "snapshot_retention_days" {
  description = "Dias para manter snapshots"
  type        = number
  default     = 7
  
  validation {
    condition     = var.snapshot_retention_days >= 1 && var.snapshot_retention_days <= 30
    error_message = "Retenção deve ser entre 1 e 30 dias."
  }
}

# Configurações de Curso
variable "course_module" {
  description = "Módulo do curso (influencia configurações)"
  type        = string
  default     = "basic"
  
  validation {
    condition     = contains(["basic", "intermediate", "advanced"], var.course_module)
    error_message = "Módulo deve ser: basic, intermediate ou advanced."
  }
}

variable "lab_scenario" {
  description = "Cenário específico do laboratório"
  type        = string
  default     = "web-app-pentest"
  
  validation {
    condition = contains([
      "web-app-pentest", "network-pentest", "wireless-pentest", 
      "social-engineering", "forensics", "malware-analysis"
    ], var.lab_scenario)
    error_message = "Cenário deve ser um dos disponíveis."
  }
}

# Configurações de Compliance
variable "enable_encryption" {
  description = "Forçar criptografia em todos os volumes"
  type        = bool
  default     = true
}

variable "enable_detailed_monitoring" {
  description = "Habilitar monitoramento detalhado (CloudWatch)"
  type        = bool
  default     = false
}

# Configurações Experimentais
variable "enable_ipv6" {
  description = "Habilitar suporte IPv6 (experimental)"
  type        = bool
  default     = false
}

variable "enable_spot_instances" {
  description = "Usar Spot Instances para economia (experimental)"
  type        = bool
  default     = false
}

variable "spot_max_price" {
  description = "Preço máximo para Spot Instances (USD/hora)"
  type        = string
  default     = "0.05"
}