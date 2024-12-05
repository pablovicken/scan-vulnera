# Scan de Vulnerabilidades 👾
Este é um projeto simples de scanner de vulnerabilidades para páginas web, desenvolvido em Python, que visa detectar algumas vulnerabilidades comuns, como SQL Injection, XSS (Cross-Site Scripting), LFI (Local File Inclusion), RFI (Remote File Inclusion), Command Injection, e CSRF (Cross-Site Request Forgery). O scanner envia requisições HTTP para a página de destino e tenta identificar possíveis falhas de segurança.

## Tecnologias Usadas 🖥
- Python 3.x
- Requests: Para enviar requisições HTTP.
- BeautifulSoup: Para analisar o conteúdo HTML das respostas.
- Re (expressões regulares): Para identificar padrões e comportamentos específicos.

## Vulnerabilidades Detectadas 🕷
O scanner verifica as seguintes vulnerabilidades comuns:

- SQL Injection: Verifica falhas relacionadas a comandos SQL não tratados corretamente no backend da aplicação.
- Cross-Site Scripting (XSS): Detecta falhas em que um atacante pode injetar scripts maliciosos no navegador da vítima.
- Local File Inclusion (LFI): Verifica se é possível incluir arquivos locais no servidor, o que pode levar a vazamento de informações sensíveis.
- Remote File Inclusion (RFI): Testa se o servidor permite incluir arquivos de fontes externas, o que pode ser explorado para executar código malicioso.
- Command Injection: Verifica se um atacante pode executar comandos no servidor através da aplicação.
- Cross-Site Request Forgery (CSRF): Testa a vulnerabilidade de a aplicação permitir que um atacante faça requisições em nome de um usuário autenticado.

## Instalação 🧷
Para rodar o projeto, você precisa de um ambiente com Python 3.x e algumas dependências que podem ser instaladas via pip:

1. Clone o repositório
```
git clone https://github.com/pablovicken/scan-vulnera.git
```
2. Instale as dependências 📌
- Dentro do diretório do projeto, crie um ambiente virtual (opcional) e instale as dependências necessárias:
```
python3 -m venv venv
```
```
source venv/bin/activate  # No Windows, use: venv\Scripts\activate
```
```
pip install -r requirements.txt
```
Caso não tenha o arquivo requirements.txt, instale as bibliotecas manualmente:
```
pip install requests beautifulsoup4
```
## Como Usar 📑
Após a instalação, o script pode ser executado diretamente a partir do terminal. Para usar o scanner de vulnerabilidades, execute o seguinte comando:
```
python scan-vulnera.py
```
Você será solicitado a informar a URL da página a ser escaneada. 
- Exemplo: Digite a URL da página a ser escaneada (ex: http://www.example.com/vulnerable_page): http://www.exemplo.com/pagina
- O script irá executar a varredura nas vulnerabilidades mencionadas acima e exibir os resultados no terminal.

## Exemplo de Saída 🔎
A saída no terminal será parecida com a seguinte:

```
Escaneando vulnerabilidades na URL: http://www.exemplo.com/pagina
```
- Verificando vulnerabilidade de SQL Injection em http://www.exemplo.com/pagina
[!] Possível vulnerabilidade de SQL Injection detectada em http://www.exemplo.com/pagina' OR 1=1 --
[*] Nenhuma vulnerabilidade de SQL Injection detectada.

- Verificando vulnerabilidade de XSS em http://www.exemplo.com/pagina
[!] Possível vulnerabilidade de XSS detectada em http://www.exemplo.com/pagina<script>alert("XSS")</script>
[*] Nenhuma vulnerabilidade de XSS detectada.

- Verificando vulnerabilidade de LFI em http://www.exemplo.com/pagina
[*] Nenhuma vulnerabilidade de LFI detectada.

...

### Parâmetros de Configuração 🔐
Você pode configurar os testes de vulnerabilidade modificando os payloads dentro de cada função correspondente (check_sql_injection, check_xss, etc.). Caso queira adicionar novas verificações, basta incluir mais testes conforme necessário.

### Contribuindo 🧮
Contribuições são bem-vindas! Se você quiser melhorar este projeto, por favor, siga os passos abaixo:
- Faça um fork deste repositório.
- Crie uma nova branch para sua funcionalidade (git checkout -b feature/nova-funcionalidade).
- Realize as alterações e faça os commits (git commit -am 'Adiciona nova funcionalidade').
- Faça o push para sua branch (git push origin feature/nova-funcionalidade).
- Abra um pull request.


