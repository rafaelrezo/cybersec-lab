# Laboratório de Cybersecurity - AWS EC2

Este projeto cria um laboratório completo de cybersecurity na AWS usando Terraform, incluindo:

- **Kali Linux** (sistema operacional para pentesting)
- **OWASP Juice Shop** (aplicação web vulnerável para testes)
- **Burp Suite Community** (proxy para testes de segurança web)
- **Metasploit Framework** (framework de pentesting)
- **Ferramentas adicionais** (nmap, nikto, sqlmap, etc.)

## 📋 Pré-requisitos

1. **Conta AWS** com permissões para criar recursos EC2, VPC, etc.
2. **[Terraform](https://developer.hashicorp.com/terraform/install)** instalado (versão 1.0+)
3. **[AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)** configurado com suas credenciais
4. **Par de chaves SSH** criado na AWS

## 🚀 Como usar

### 1. Preparar o ambiente

Escolha um direteório para armazenar o repositório do Lab.

```bash
# Clone ou baixe os arquivos do projeto
git clone git@github.com:rafaelrezo/cybersec-lab.git
cd cybersec-git
```
Para usar o Terraform, é importante instalar o AWS CLI, e configurar as [credenciais de curto prazo](https://docs-aws-amazon-com.translate.goog/cli/latest/userguide/getting-started-quickstart.html?_x_tr_sl=en&_x_tr_tl=pt&_x_tr_hl=pt&_x_tr_pto=tc). 

Para localizar suas credenciais no ambiente Vocarium do AWS Academy, inicie o "Laboratório de Aprendizagem", e localicalize o conteúdo do botão "show" e a região utilizada, conforme figura:

![Credenciais para configuração AWS CLI](images/credenciais.png)

Após configurar suas credencias e parâmetros do AWS CLI, teste tentando listar os arquivos no S3, deve executar sem retornar erro nenhum. Cada vez que o Laboratório de Aprendizagem do AWS Academy é iniciado, as credenciais do AWS CLI mudam.

```bash
$ aws s3 ls
$
# Se retornar algum erro, verifique os 
# arquivos ~/.aws/credentials e ~/.aws/config.
```

### 2. Criar a chave SSH na AWS

Para acessar suas máquinas por ssh, será necessário configurar a chave de acesso.

```bash
# No AWS Console:
# EC2 > Key Pairs > Create Key Pair
# Ou via CLI:
aws ec2 create-key-pair --key-name minha-chave-cybersec --query 'KeyMaterial' --output text > minha-chave-cybersec.pem
chmod 400 minha-chave-cybersec.pem
```
Para verificar esta etapa, verifique se a chave existe com a permissão "-r--------"

```bash
$ ls -lah | grep minha-chave-cybersec.pem
-r--------  1 seu_usuario seu_usuario 1.7K Jun 27 14:32 minha-chave-cybersec.pem

```
### 3. Configurar variáveis Terraform

```bash
# Copie o arquivo de exemplo
cp terraform.tfvars.example terraform.tfvars

# Edite o arquivo com suas configurações com seu editor de texto preferido
vim terraform.tfvars

#ou

nano terraform.tfvars

#ou

code terraform.tfvars
```

**Configurações importantes no terraform.tfvars:**
- `key_name`: Nome da sua chave SSH na AWS
- `allowed_cidr`: IP permitido para acesso (recomendado: seu IP/32)
- `aws_region`: Região AWS desejada
- `instance_type`: Tipo da instância (mínimo t3.medium)



### 4. Deploy da infraestrutura

```bash
# Inicializar Terraform
terraform init

# Verificar o plano de execução
terraform plan
```

Deve retornar algo similar a 

```bash
...
Plan: 7 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + instance_dns       = (known after apply)
  + instance_public_ip = (known after apply)
  + juice_shop_url     = (known after apply)
  + rdp_connection     = (known after apply)
  + ssh_command        = (known after apply)
  + vnc_connection     = (known after apply)

```

```bash
# Aplicar as configurações
terraform apply -auto-approve
```

### 5. Aguardar a configuração

O processo completo leva cerca de **10-15 minutos**. A instância será reiniciada automaticamente ao final da configuração.

## 🔧 Acessando o laboratório

Após o deploy, o Terraform exibirá as informações de acesso:

### SSH
```bash
ssh -i sua-chave.pem kali@IP_PUBLICO
```

### Aplicações Web
- **OWASP Juice Shop**: `http://IP_PUBLICO:3000`
- **Burp Suite Proxy**: Configurar proxy para `IP_PUBLICO:8080`

### Acesso Remoto ao Desktop
- **VNC**: `IP_PUBLICO:5901` (senha: `vncpassword`)
- **RDP**: `IP_PUBLICO:3389` (usuário: `kali`, senha: `kali2024`)

## 🛠️ Ferramentas incluídas

### Análise de Rede
- **nmap**: Scanner de rede e portas
- **nikto**: Scanner de vulnerabilidades web
- **dirb/gobuster**: Descoberta de diretórios

### Teste de Aplicações Web
- **Burp Suite Community**: Proxy interceptador
- **sqlmap**: Exploração de SQL Injection
- **OWASP Juice Shop**: Aplicação vulnerável para testes

### Frameworks de Pentesting
- **Metasploit Framework**: Exploração de vulnerabilidades
- **John the Ripper**: Quebra de senhas
- **Hydra**: Ataques de força bruta

### Análise de Tráfego
- **Wireshark**: Análise de pacotes
- **tcpdump**: Captura de tráfego de rede

## 📚 Exercícios sugeridos

### 1. Reconhecimento
```bash
# Fazer scan da própria máquina
nmap -sV localhost

# Descobrir serviços na rede
nmap -sn 10.0.1.0/24
```

### 2. Teste de Aplicação Web
1. Acesse o Juice Shop em `http://IP:3000`
2. Configure o Burp Suite como proxy
3. Explore vulnerabilidades (XSS, SQL Injection, etc.)

### 3. Análise de Tráfego
```bash
# Capturar tráfego HTTP
tcpdump -i any -w captura.pcap port 3000

# Analisar no Wireshark
wireshark captura.pcap
```

## 🔍 Comandos úteis

```bash
# Verificar status do laboratório
lab-status

# Reiniciar Juice Shop
docker restart juice-shop

# Executar Burp Suite
burpsuite

# Abrir Metasploit
msfconsole

# Ver logs de configuração
tail -f /var/log/cybersec-lab-setup.log
```

## 💰 Custos estimados

- **t3.medium**: ~$0.04/hora (~$30/mês se ficar ligado 24/7)
- **Armazenamento**: ~$3/mês (30GB)
- **Transferência de dados**: Depende do uso

⚠️ **Importante**: Lembre-se de destruir os recursos quando não estiver usando!

```bash
terraform destroy
```

## 🔒 Considerações de segurança

1. **Restrinja o acesso**: Use seu IP específico no `allowed_cidr`
2. **Monitore os custos**: Configure alertas de billing na AWS
3. **Destrua quando não usar**: Execute `terraform destroy`
4. **Senhas padrão**: Altere as senhas padrão em produção
5. **Atualizações**: Mantenha o sistema atualizado

## 🐛 Solução de problemas

### Instância não inicia
- Verifique se a chave SSH existe na região especificada
- Confirme as permissões da sua conta AWS

### Não consegue acessar via SSH
- Verifique o Security Group e o `allowed_cidr`
- Confirme que está usando a chave correta

### Juice Shop não abre
- Aguarde alguns minutos após o boot da instância
- Verifique se o Docker está rodando: `docker ps`

### VNC/RDP não conecta
- Aguarde a configuração completa (10-15 min)
- Verifique se as portas estão abertas: `netstat -tlnp`

## 📞 Suporte

Para problemas específicos:
1. Verifique os logs: `/var/log/cybersec-lab-setup.log`
2. Execute: `lab-status`
3. Reinicie a instância se necessário

## 📄 Licença

Este projeto é para fins educacionais. Use responsavelmente e apenas em ambientes autorizados.

---

**⚠️ Aviso Legal**: Este laboratório contém ferramentas de pentesting. Use apenas para aprendizado e em ambientes controlados. O uso inadequado pode violar leis locais.