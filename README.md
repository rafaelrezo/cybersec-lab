
# 🔥 Laboratório Burp Suite - Interceptação HTTPS

Este projeto Terraform cria um ambiente completo de cibersegurança na AWS Academy, especialmente configurado para  **interceptação de tráfego HTTPS com Burp Suite** . Inclui Kali Linux com Burp Suite pré-configurado e múltiplas aplicações vulneráveis com suporte SSL/TLS.

## 🎯 O que este laboratório oferece

### 🔥 **Interceptação HTTPS com Burp Suite**

* **Burp Suite Community** pré-configurado para interceptação SSL/TLS
* **Certificados auto-assinados** especialmente para pentest
* **Proxy automático** configurado para capturar tráfego HTTPS
* **CA Certificate** instalado automaticamente nos browsers

### 🖥️ **Máquina Atacante (Kali Linux)**

* **Kali Linux** com interface gráfica via VNC (resolução 1920x1080)
* **Burp Suite** com configuração otimizada para HTTPS
* **Firefox pré-configurado** com proxy Burp Suite
* **Ferramentas de pentest** completas (Metasploit, Nmap, SQLMap, etc.)
* **Scripts automáticos** para setup e interceptação

### 🎯 **Alvos Vulneráveis com HTTPS**

* **OWASP Juice Shop** - HTTP (porta 3000) + HTTPS (porta 3443)
* **DVWA** - Aplicação PHP com SSL habilitado
* **WebGoat** - Lições OWASP com proxy HTTPS
* **Mutillidae II** - Aplicação extremamente vulnerável em HTTPS
* **Dashboard centralizado** com links para todos os alvos

### 🔒 **Certificados SSL Configurados**

* **CA raiz** do laboratório para assinatura
* **Certificados SSL** auto-assinados para cada aplicação
* **Configuração automática** no Burp Suite
* **Instalação automática** nos browsers

## 📋 Pré-requisitos

### 1. **Conta AWS Academy**

* Acesso ao AWS Academy Learner Lab
* Session ativa com credenciais temporárias
* Créditos suficientes (~$1-2 por sessão de 4 horas)

### 2. **Ferramentas Locais**

```bash
# Terraform (versão >= 1.0)
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# VNC Viewer para acessar Kali GUI
sudo apt install tigervnc-viewer  # Linux
# Ou baixe RealVNC Viewer para Windows/macOS
```

### 3. **Hardware Recomendado**

* **Internet** : Conexão estável para VNC remoto
* **Resolução** : Monitor de pelo menos 1366x768
* **Recursos** : Suficiente para VNC Viewer + browser

## 🚀 Configuração Completa Passo a Passo

### **Passo 1: Preparar Ambiente**

1. **Clone o repositório:**

```bash
git clone <URL_DO_REPOSITORIO>
cd burp-suite-lab-terraform
```

2. **Configure AWS CLI com credenciais Academy:**

No AWS Academy, clique em **"AWS Details"** → **"Show"** → **"Download PEM"** e copie as credenciais:

```bash
# Método automático (recomendado)
aws configure

# Insira quando solicitado:
# AWS Access Key ID: ASIA...
# AWS Secret Access Key: ...
# Session Token: (cole o token completo)
# Default region: us-east-1
```

 **⚠️ IMPORTANTE** : Credenciais do AWS Academy são temporárias (expiram em ~4 horas)!

### **Passo 2: Configurar Variáveis**

```bash
# Copiar arquivo de exemplo
cp terraform.tfvars.example terraform.tfvars

# Editar configurações
nano terraform.tfvars  # ou vim, code, etc.
```

**Configurações OBRIGATÓRIAS no terraform.tfvars:**

```hcl
# 1. SEU NOME (usado em tags)
student_name = "João Silva"

# 2. NOME ÚNICO DO LAB 
lab_name = "burp-https-joao"

# 3. SEU IP PÚBLICO (CRÍTICO para segurança!)
allowed_cidr_blocks = ["201.23.45.67/32"]  # Seu IP aqui!

# 4. SENHA VNC
vnc_password = "BurpSuite123!"

# 5. CHAVE SSH (altamente recomendado)
ssh_public_key = "ssh-ed25519 AAAAC3..."  # Sua chave pública
```

### **Passo 3: Descobrir seu IP Público**

```bash
# Qualquer um destes comandos:
curl ifconfig.me
curl ipinfo.io/ip
curl whatismyipaddress.com/ip

# Use o resultado no formato: SEU.IP.AQUI/32
```

### **Passo 4: Gerar Chaves SSH (se não tiver)**

```bash
# Gerar par de chaves Ed25519 (recomendado)
ssh-keygen -t ed25519 -C "seu-email@exemplo.com"

# Visualizar chave pública para terraform.tfvars
cat ~/.ssh/id_ed25519.pub

# Copie toda a linha que começa com "ssh-ed25519..."
```

### **Passo 5: Deploy do Laboratório**

```bash
# Inicializar Terraform
terraform init

# Verificar plano (recomendado)
terraform plan

# Criar laboratório
terraform apply
# Digite 'yes' quando solicitado
```

 **⏱️ Tempo de criação** : 10-15 minutos para setup completo

### **Passo 6: Aguardar Instalação**

O Terraform criará as instâncias, mas os scripts de instalação continuarão rodando:

```bash
# Ver progresso da instalação
terraform output

# As instâncias estarão "running" mas ainda instalando
# Aguarde 10-15 minutos para conclusão completa
```

## 🔥 Acessando e Usando o Burp Suite

### **1. Conectar no Kali Linux**

Após o `terraform apply`, você verá outputs como:

```
kali_linux_access = {
  "vnc_access" = "VNC Viewer -> 54.123.45.67:5901"
  "burp_proxy" = "10.0.1.100:8080"
}
```

**Via VNC (Interface Gráfica - RECOMENDADO):**

1. Abra o **VNC Viewer**
2. Conecte em: `IP_KALI:5901`
3. Senha: valor configurado em `vnc_password`
4. Resolução: 1920x1080 (ajustável)

**Via SSH (Terminal):**

```bash
ssh -i ~/.ssh/id_ed25519 kali@IP_KALI
```

### **2. Iniciar Burp Suite**

No desktop do Kali (via VNC):

```bash
# Método automático (RECOMENDADO)
burp-start

# Isso fará:
# ✅ Iniciar Burp Suite
# ✅ Baixar e instalar certificado CA
# ✅ Configurar browsers automaticamente
# ✅ Preparar ambiente para interceptação HTTPS
```

 **OU use o ícone no desktop** : "Burp Suite"

### **3. Configurar Target**

```bash
# Definir IP do alvo (substitua pelo IP real)
target 10.0.2.100

# Isso configura variáveis de ambiente:
# ✅ TARGET_IP=10.0.2.100
# ✅ URLs HTTP e HTTPS prontas
```

### **4. Configurar Browser para Interceptação**

**Método automático (Firefox pré-configurado):**

```bash
# Abrir Firefox já configurado para Burp
firefox-pentest
```

**OU configure manualmente qualquer browser:**

* Proxy HTTP: `127.0.0.1:8080`
* Proxy HTTPS: `127.0.0.1:8080`
* Sem proxy para: (deixar vazio)

### **5. Interceptar Tráfego HTTPS**

1. **No Burp Suite:**
   * Vá para aba **Proxy**
   * Clique em **"Intercept is off"** → **"Intercept is on"**
2. **No Firefox:**
   * Navegue para: `https://IP_TARGET:3443`
   * **Aceite o certificado SSL do Burp** (warnings são normais!)
3. **No Burp Suite:**
   * Veja a requisição interceptada na aba **Proxy**
   * Clique **"Forward"** para enviar ou **"Drop"** para descartar
   * Analise o tráfego na aba **HTTP history**

## 🎯 Alvos Disponíveis para Interceptação HTTPS

### **🧃 OWASP Juice Shop**

```
HTTP:  http://IP_TARGET:3000
HTTPS: https://IP_TARGET:3443  ← PRINCIPAL PARA BURP
```

* Aplicação moderna Node.js
* OWASP Top 10 completo
* Desafios gamificados
* **Perfeito para interceptação HTTPS**

### **🕷️ DVWA (Damn Vulnerable Web Application)**

```
HTTP:  http://IP_TARGET/dvwa
HTTPS: https://IP_TARGET/dvwa
```

* Login: `admin` / `password`
* Vulnerabilidades clássicas PHP
* Níveis de segurança ajustáveis

### **🐐 WebGoat**

```
HTTP:  http://IP_TARGET:8080/WebGoat
HTTPS: https://webgoat.local/WebGoat (via proxy Nginx)
```

* Lições interativas OWASP
* Criar conta na primeira vez
* Tutoriais passo-a-passo

### **🦟 Mutillidae II**

```
HTTP:  http://IP_TARGET/mutillidae
HTTPS: https://IP_TARGET/mutillidae
```

* Aplicação extremamente vulnerável
* OWASP Top 10 + vulnerabilidades extras
* Login opcional: `admin` / `admin`

## 🔒 Workflow Completo de Interceptação HTTPS

### **1. Setup Inicial (uma vez)**

```bash
# No Kali Linux (via VNC)
burp-start                    # Iniciar Burp + certificados
target 10.0.2.100            # Definir alvo
firefox-pentest              # Browser configurado
```

### **2. Interceptação Básica**

```bash
# 1. No Burp: Proxy > Intercept ON
# 2. No Firefox: https://10.0.2.100:3443
# 3. Aceitar certificado do Burp
# 4. Ver requisições interceptadas no Burp
```

### **3. Análise com Burp Tools**

**Proxy Tab:**

* **HTTP history** : Ver todo tráfego HTTPS capturado
* **Intercept** : Modificar requisições em tempo real
* **Options** : Configurar regras de interceptação

**Target Tab:**

* **Site map** : Mapeamento automático do site HTTPS
* **Scope** : Definir escopo do teste
* **Issue definitions** : Tipos de vulnerabilidades

**Repeater Tab:**

* Modificar e reenviar requisições HTTPS
* Testar payloads manualmente
* Comparar respostas

**Intruder Tab:**

* Ataques automatizados (brute force, fuzzing)
* Wordlists para parameters/paths
* Análise de timing attacks

**Scanner Tab (Community Edition limitado):**

* Scan passivo automático
* Detectar vulnerabilidades básicas
* Relatórios de segurança

### **4. Técnicas Avançadas**

**Bypass SSL/TLS:**

```bash
# Testar diferentes versões TLS
# Analisar cipher suites
# Verificar certificate pinning bypass
```

**Session Management:**

```bash
# Interceptar cookies de sessão
# Testar session fixation
# Analisar JWT tokens em HTTPS
```

**Input Validation:**

```bash
# SQL Injection via HTTPS
# XSS em formulários SSL
# File upload vulnerabilities
```

## 🔧 Scripts Utilitários

### **No Kali Linux:**

```bash
burp-start              # Iniciar Burp Suite + certificados
target <IP>             # Definir IP do alvo
firefox-pentest         # Firefox configurado para Burp
install-ca              # Instalar certificado CA manualmente
lab-status              # Status do laboratório
cat LAB_INFO.txt        # Informações completas do lab
```

### **No Target (debug/admin):**

```bash
./target-status.sh           # Status HTTPS dos alvos
./restart-targets.sh         # Reiniciar aplicações
./test-burp-intercept.sh     # Testar interceptação Burp
cat TARGET_INFO.txt          # Informações dos alvos
```

## 🐛 Solução de Problemas

### **❌ VNC não conecta**

```bash
# Verificar se IP está correto em allowed_cidr_blocks
# Testar conectividade
telnet IP_KALI 5901

# SSH no Kali e verificar VNC
ssh kali@IP_KALI
sudo systemctl status vncserver@1
sudo systemctl restart vncserver@1
```

### **❌ Burp Suite não intercepta HTTPS**

```bash
# 1. Verificar se CA está instalado
install-ca

# 2. Verificar configuração proxy browser
# Proxy: 127.0.0.1:8080

# 3. Testar via curl
curl -k --proxy http://127.0.0.1:8080 https://target

# 4. Verificar se Burp está escutando
netstat -tnl | grep 8080
```

### **❌ Certificado SSL inválido**

```bash
# NORMAL para laboratório! 
# Certificados são auto-assinados
# Aceite warnings do browser
# Burp substitui certificados automaticamente
```

### **❌ Aplicações não carregam**

```bash
# Aguardar 5-10 minutos após terraform apply
# Scripts ainda podem estar instalando

# Verificar status
./target-status.sh

# Reiniciar se necessário
./restart-targets.sh
```

### **❌ Performance lenta**

```bash
# Aumentar tipo de instância no terraform.tfvars:
kali_instance_type = "t3.large"  # Mais performance
burp_memory_allocation = 4096    # Mais memória para Burp

# Aplicar mudanças
terraform apply
```

### **❌ Credenciais AWS expiradas**

```bash
# Renovar no AWS Academy
# Copiar novas credenciais
aws configure

# OU atualizar arquivo
nano ~/.aws/credentials
```

## 💰 Gestão de Custos

### **💡 Configurações por Orçamento**

**Economia (~$0.24/sessão 4h):**

```hcl
kali_instance_type = "t3.medium"      # Mínimo para Burp
target_instance_type = "t3.micro"
use_elastic_ip = false
enable_burp_extensions = false
```

**Recomendado (~$0.28/sessão 4h):**

```hcl
kali_instance_type = "t3.medium"
target_instance_type = "t3.small"
use_elastic_ip = false
enable_burp_extensions = true
```

**Performance (~$0.54/sessão 4h):**

```hcl
kali_instance_type = "t3.large"
target_instance_type = "t3.medium"
use_elastic_ip = true
enable_burp_extensions = true
```

### **📊 Monitoramento de Custos**

```bash
# Via AWS CLI
aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity DAILY --metrics BlendedCost

# Via Console AWS Academy
# Billing & Cost Management (se disponível)
```

### **🛑 Parar/Destruir Laboratório**

```bash
# Parar temporariamente (via AWS Console)
# EC2 → Instances → Stop

# Destruir permanentemente
terraform destroy
# Digite 'yes' para confirmar
# ⚠️ Isso apagará TUDO!
```

## 📚 Recursos de Aprendizado Burp Suite

### **📖 Documentação Oficial**

* [Burp Suite Documentation](https://portswigger.net/burp/documentation)
* [Web Security Academy](https://portswigger.net/web-security)
* [Burp Extensions](https://portswigger.net/bappstore)

### **🎓 Cursos e Tutoriais**

* [PortSwigger Web Security Academy](https://portswigger.net/web-security) (GRATUITO)
* [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
* [Burp Suite Certified Practitioner](https://portswigger.net/web-security/certification)

### **🛠️ Extensões Úteis (instaladas automaticamente)**

* **Active Scan++** : Scanner de vulnerabilidades avançado
* **Logger++** : Log avançado de requisições
* **Param Miner** : Descoberta de parâmetros ocultos
* **JSON Beautifier** : Formatação de JSON
* **Retire.js** : Detecção de bibliotecas JavaScript vulneráveis

## 🏆 Exercícios Práticos Sugeridos

### **🥇 Nível Iniciante**

1. **Setup Básico:**
   * Conectar VNC no Kali
   * Iniciar Burp Suite
   * Interceptar requisição HTTP simples
2. **Primeiro HTTPS:**
   * Configurar proxy no browser
   * Aceitar certificado do Burp
   * Interceptar login no Juice Shop HTTPS
3. **Análise Básica:**
   * Ver histórico de requisições
   * Usar Repeater para modificar requests
   * Identificar cookies de sessão

### **🥈 Nível Intermediário**

1. **SQL Injection via HTTPS:**
   * Interceptar formulário de login
   * Testar payloads SQL via Repeater
   * Usar Intruder para automatizar
2. **XSS em HTTPS:**
   * Interceptar formulários de comentário
   * Testar payloads XSS
   * Analisar CSP headers
3. **Session Management:**
   * Interceptar cookies de autenticação
   * Testar session fixation
   * Analisar JWT tokens

### **🥉 Nível Avançado**

1. **Advanced HTTPS Analysis:**
   * Analisar certificate chain
   * Testar SSL/TLS configurations
   * Bypass certificate pinning
2. **Automated Scanning:**
   * Configurar Burp Scanner
   * Analisar resultados de scan
   * Gerar relatórios profissionais
3. **Custom Extensions:**
   * Instalar extensões adicionais
   * Configurar Logger++ para auditoria
   * Usar Param Miner para discovery

## 🔒 Considerações de Segurança

### **⚠️ Avisos Importantes**

* **Aplicações são VULNERÁVEIS por design**
* **Certificados SSL são auto-assinados** (aceite warnings)
* **Tráfego HTTPS é descriptografado** pelo Burp Suite
* **Use apenas para fins educacionais** em ambiente isolado

### **🛡️ Proteções Implementadas**

* VPC isolada com subnets segregadas
* Security Groups restritivos por função
* Firewall UFW configurado em ambas as instâncias
* Logs de auditoria habilitados
* Criptografia EBS forçada

### **✅ Boas Práticas**

1. **Configure** `allowed_cidr_blocks` com seu IP específico
2. **Use** chaves SSH ao invés de senhas
3. **Monitore** custos AWS Academy regularmente
4. **Destrua** laboratório após uso: `terraform destroy`
5. **Documente** descobertas para aprendizado
6. **Nunca** use contra alvos não autorizados

---

## 📝 Licença e Disclaimer

Este projeto é para fins  **exclusivamente educacionais** .

### ✅ **Uso Permitido**

* Aprendizado de cibersegurança e interceptação HTTPS
* Treinamento em ambiente acadêmico controlado
* Desenvolvimento de habilidades éticas de pentest
* Estudo de vulnerabilidades web em ambiente isolado

### ❌ **Uso Pro# 🛡️ Laboratório de Cibersegurança - Kali Linux + Alvos Vulneráveis

Este projeto Terraform cria um ambiente completo de aprendizado de cibersegurança na AWS Academy, com Kali Linux para pentest e múltiplas aplicações vulneráveis como alvos.

## 🎯 O que este laboratório inclui

### 🖥️ Máquina Atacante (Kali Linux)

* **Kali Linux** com interface gráfica via VNC
* **Ferramentas de pentest** pré-instaladas (Burp Suite, Metasploit, Nmap, SQLMap, etc.)
* **Ambiente desktop** XFCE acessível remotamente
* **Scripts personalizados** para o laboratório

### 🎯 Máquina de Alvos (Ubuntu)

* **OWASP Juice Shop** - Aplicação moderna vulnerável
* **DVWA** - Damn Vulnerable Web Application
* **WebGoat** - Aplicação educacional da OWASP
* **Mutillidae II** - Aplicação extremamente vulnerável
* **Dashboard centralizado** para acesso fácil

## 📋 Pré-requisitos

### 1. Conta AWS Academy

* Acesso ao AWS Academy Learner Lab
* Session ativa com credenciais temporárias
* Créditos suficientes para laboratório

### 2. Ferramentas no seu computador

```bash
# Terraform
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/

# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Git
sudo apt update && sudo apt install git  # Ubuntu/Debian
```

### 3. VNC Viewer (para acessar Kali GUI)

```bash
# Ubuntu/Debian
sudo apt install tigervnc-viewer

# Windows/macOS
# Baixe RealVNC Viewer: https://www.realvnc.com/pt/connect/download/viewer/
```

## 🚀 Configuração Passo a Passo

### Passo 1: Clonar o Repositório

```bash
git clone <URL_DO_REPOSITORIO>
cd cybersec-lab-terraform
```

### Passo 2: Configurar AWS CLI com Credenciais Academy

No AWS Academy, clique em **"AWS Details"** e copie as credenciais:

```bash
# Configurar credenciais (método 1 - interativo)
aws configure

# OU criar arquivo de credenciais (método 2)
mkdir -p ~/.aws
cat > ~/.aws/credentials << EOF
[default]
aws_access_key_id = ASIA...
aws_secret_access_key = ...
aws_session_token = ...
EOF

cat > ~/.aws/config << EOF
[default]
region = us-east-1
output = json
EOF
```

 **⚠️ IMPORTANTE** : As credenciais do AWS Academy são temporárias e expiram! Você precisará atualizá-las a cada nova sessão.

### Passo 3: Configurar Variáveis do Laboratório

```bash
# Copiar arquivo de exemplo
cp terraform.tfvars.example terraform.tfvars

# Editar configurações (use seu editor preferido)
nano terraform.tfvars
```

**Configurações obrigatórias no terraform.tfvars:**

```hcl
# SEU NOME (obrigatório)
student_name = "João Silva"

# NOME ÚNICO DO LAB (obrigatório) 
lab_name = "cybersec-joao"

# SEU IP PÚBLICO (obrigatório para segurança)
allowed_cidr_blocks = ["201.23.45.67/32"]  # Descubra em: https://whatismyipaddress.com/

# SENHA VNC (obrigatório)
vnc_password = "MinhaSenh@123"

# CHAVE SSH (recomendado)
ssh_public_key = "ssh-ed25519 AAAAC3..."  # Conteúdo do arquivo .pub
```

### Passo 4: Gerar Chaves SSH (se não tiver)

```bash
# Gerar par de chaves
ssh-keygen -t ed25519 -C "seu-email@exemplo.com"

# Visualizar chave pública para colocar no terraform.tfvars
cat ~/.ssh/id_ed25519.pub
```

### Passo 5: Descobrir seu IP Público

```bash
# Método 1
curl ifconfig.me

# Método 2  
curl ipinfo.io/ip

# Método 3
curl whatismyipaddress.com/ip
```

Use este IP no formato `SEU.IP.AQUI/32` no arquivo `terraform.tfvars`.

### Passo 6: Deploy do Laboratório

```bash
# Inicializar Terraform
terraform init

# Verificar plano (opcional, mas recomendado)
terraform plan

# Criar laboratório (confirme com 'yes')
terraform apply
```

 **⏱️ Tempo estimado** : 10-15 minutos para criação completa.

## 🖥️ Acessando o Laboratório

Após o `terraform apply` concluir, você verá outputs similares a:

```
kali_linux_access = {
  "public_ip" = "54.123.45.67"
  "vnc_access" = "VNC Viewer -> 54.123.45.67:5901"
  "ssh_command" = "ssh -i ~/.ssh/id_ed25519 kali@54.123.45.67"
}

target_access = {
  "public_ip" = "34.567.89.10"
  "juice_shop_url" = "http://34.567.89.10:3000"
}
```

### Acesso ao Kali Linux

#### Via VNC (Interface Gráfica)

1. Abra o VNC Viewer
2. Conecte em: `IP_KALI:5901`
3. Use a senha configurada em `vnc_password`

#### Via SSH (Terminal)

```bash
ssh -i ~/.ssh/id_ed25519 kali@IP_KALI
```

### Acesso aos Alvos Vulneráveis

#### Dashboard Principal

* **URL** : `http://IP_TARGET`
* Página com links para todas as aplicações

#### Aplicações Individuais

* **Juice Shop** : `http://IP_TARGET:3000`
* **DVWA** : `http://IP_TARGET/dvwa` (admin/password)
* **WebGoat** : `http://IP_TARGET:8080/WebGoat`
* **Mutillidae** : `http://IP_TARGET/mutillidae`

## 🛠️ Usando o Laboratório

### No Kali Linux

```bash
# Verificar status do laboratório
./lab-status.sh

# Ver informações completas
cat LAB_INFO.txt

# Definir alvo para ferramentas
target IP_DO_TARGET

# Scan rápido
scan_quick IP_DO_TARGET

# Scan completo
scan_full IP_DO_TARGET

# Navegar para diretório de trabalho
lab
```

### Ferramentas Principais Instaladas

#### Web Application Testing

* **Burp Suite** - Proxy de interceptação
* **OWASP ZAP** - Scanner de vulnerabilidades
* **Nikto** - Scanner web
* **SQLMap** - Automação SQL Injection
* **Gobuster** - Directory brute force

#### Network Testing

* **Nmap** - Port scanner
* **Masscan** - Fast port scanner
* **Wireshark** - Packet analyzer
* **Netcat** - Network utility

#### Exploitation

* **Metasploit** - Exploitation framework
* **SearchSploit** - Exploit database
* **BeEF** - Browser exploitation

#### Password Attacks

* **Hashcat** - Password recovery
* **John the Ripper** - Password cracker
* **Hydra** - Login brute forcer

### Diretórios de Trabalho

```
/home/kali/pentest-lab/
├── tools/          # Ferramentas personalizadas
├── wordlists/      # Dicionários e wordlists
├── exploits/       # Exploits e payloads
├── reports/        # Relatórios de pentest
└── scripts/        # Scripts customizados
```

## 📚 Exercícios Sugeridos

### 1. Reconnaissance (Reconhecimento)

```bash
# No Kali Linux
target IP_TARGET
nmap -sC -sV $TARGET_IP
gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirb/common.txt
```

### 2. OWASP Juice Shop

* Acesse `http://IP_TARGET:3000`
* Explore as funcionalidades
* Tente SQL Injection no login
* Procure por XSS nas reviews
* Teste upload de arquivos

### 3. DVWA

* Acesse `http://IP_TARGET/dvwa`
* Login: admin/password
* Configure Security Level: Low
* Teste SQL Injection
* Pratique Command Injection
* Explore File Upload vulnerabilities

### 4. WebGoat

* Acesse `http://IP_TARGET:8080/WebGoat`
* Crie uma conta
* Siga as lições interativas
* Complete os exercícios guiados

## 🔧 Solução de Problemas

### Credenciais AWS Expiradas

```bash
# Renovar credenciais no AWS Academy
# Copiar novas credenciais
aws configure

# OU atualizar arquivo
nano ~/.aws/credentials
```

### VNC não conecta

```bash
# SSH no Kali e verificar VNC
ssh kali@IP_KALI
sudo systemctl status vncserver@1
sudo systemctl restart vncserver@1
```

### Aplicações não respondem

```bash
# SSH no target e verificar serviços
ssh ubuntu@IP_TARGET
./target-status.sh
./restart-targets.sh
```

### Erro de conectividade

1. Verifique se `allowed_cidr_blocks` está correto
2. Confirme se Security Groups estão aplicados
3. Teste conectividade: `telnet IP_TARGET 3000`

### Problemas de performance

* Aumente o tipo de instância no `terraform.tfvars`
* Execute `terraform apply` para atualizar

## 💰 Gerenciamento de Custos

### Monitorar Gastos

```bash
# Via AWS CLI
aws ce get-cost-and-usage --time-period Start=2024-01-01,End=2024-01-31 --granularity MONTHLY --metrics BlendedCost

# Via Console AWS
# Billing & Cost Management > Cost Explorer
```

### Otimizar Custos

```bash
# Parar instâncias quando não usar
aws ec2 stop-instances --instance-ids i-xxxxxxxxx

# Reiniciar quando precisar  
aws ec2 start-instances --instance-ids i-xxxxxxxxx

# Destruir completamente (CUIDADO!)
terraform destroy
```

### Estimativas (US East 1)

* **t3.medium + t3.small** : ~$0.07/hora (~$0.28/sessão 4h)
* **t3.large + t3.medium** : ~$0.13/hora (~$0.52/sessão 4h)
* **EBS 50GB** : ~$0.007/hora
* **Elastic IP** : $0.005/hora (se desanexado)

## 🧹 Limpeza do Ambiente

### Destruir Laboratório Completamente

```bash
# ⚠️ ATENÇÃO: Isso apagará TUDO permanentemente!
terraform destroy
# Digite 'yes' para confirmar
```

### Parar Temporariamente (via AWS Console)

1. EC2 Console → Instances
2. Selecionar instâncias → Actions → Stop
3. Para reiniciar: Actions → Start

### Backup de Dados Importantes

```bash
# No Kali, antes de destruir
cd ~/pentest-lab
tar -czf ~/lab-backup-$(date +%Y%m%d).tar.gz reports/ scripts/

# No Target
./backup-targets.sh
```

## 🔒 Considerações de Segurança

### ⚠️ Avisos Importantes

* **Aplicações são VULNERÁVEIS por design**
* **Use apenas para aprendizado em ambiente controlado**
* **Configure `allowed_cidr_blocks` com seu IP específico**
* **Não exponha para internet sem proteção**

### Proteções Implementadas

* VPC isolada com subnets privadas
* Security Groups restritivos
* Firewall UFW configurado
* Fail2ban para proteção SSH
* Criptografia EBS habilitada

### Boas Práticas

1. **Sempre** configure IP específico em `allowed_cidr_blocks`
2. **Use** chaves SSH ao invés de senhas
3. **Monitore** custos regularmente
4. **Destrua** laboratório quando não precisar
5. **Documente** descobertas para aprendizado

## 📞 Suporte e Troubleshooting

### Logs Importantes

```bash
# Setup logs no Kali
sudo tail -f /var/log/kali-setup.log

# Setup logs no Target  
sudo tail -f /var/log/target-setup.log

# Terraform logs
export TF_LOG=DEBUG
terraform apply
```

### Comandos de Debug

```bash
# Verificar estado do Terraform
terraform show

# Refresh do estado
terraform refresh

# Verificar conectividade AWS
aws sts get-caller-identity

# Listar instâncias
aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,State.Name,PublicIpAddress]'
```

### Problemas Comuns

| Problema               | Causa Provável     | Solução                         |
| ---------------------- | ------------------- | --------------------------------- |
| VNC não conecta       | Firewall/SG         | Verificar `allowed_cidr_blocks` |
| SSH falha              | Chave errada        | Verificar `ssh_public_key`      |
| Apps não carregam     | Ainda instalando    | Aguardar 10-15 min                |
| Custo alto             | Instâncias grandes | Reduzir tipos de instância       |
| Credenciais inválidas | Academy expirou     | Renovar credenciais               |

## 📚 Recursos de Aprendizado

### Documentação Oficial

* [OWASP Top 10](https://owasp.org/www-project-top-ten/)
* [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
* [Kali Linux Documentation](https://www.kali.org/docs/)

### Tutoriais e Cursos

* [PortSwigger Web Security Academy](https://portswigger.net/web-security)
* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
* [VulnHub](https://www.vulnhub.com/)

### Metodologias

* [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)
* [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
* [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)

---

## 📝 Licença e Disclaimer

Este projeto é para fins  **exclusivamente educacionais** .

### ✅ Uso Permitido

* Aprendizado pessoal de cibersegurança
* Treinamento em ambiente acadêmico
* Desenvolvimento de habilidades éticas de pentest

### ❌ Uso Proibido

* Atacar sistemas sem autorização
* Qualquer atividade ilegal ou maliciosa
* Uso em ambiente de produção

**O usuário é totalmente responsável pelo uso adequado desta ferramenta.**

---

*Desenvolvido para AWS Academy - Laboratório de Cibersegurança 🛡️*git s
