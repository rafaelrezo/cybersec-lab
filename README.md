# 🛡️ Laboratório de Cibersegurança - Kali Linux + Alvos Vulneráveis

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
git clone git@github.com:rafaelrezo/cybersec-lab.git
cd cybersec-lab
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

**git@github.com:rafaelrezo/cybersec-lab.gitConfigurações obrigatórias no terraform.tfvars:**

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

*Desenvolvido para AWS Academy - Laboratório de Cibersegurança 🛡️*
