import nmap

def scan_network(ip_range):
    # Caminho do executável do Nmap
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"  # Altere para o caminho correto no seu sistema

    # Cria um objeto scanner do Nmap
    try:
        nm = nmap.PortScanner(nmap_search_path=[nmap_path])
        print("Scanner Nmap inicializado com sucesso.")
    except Exception as e:
        print(f"Erro ao inicializar o Nmap: {e}")
        return

    # Realiza a varredura da rede
    print(f"Escaneando o IP {ip_range}...")
    try:
        nm.scan(hosts=ip_range, arguments='-sP')  # -sP para scan de ping
        print("Varredura realizada com sucesso.")
    except Exception as e:
        print(f"Erro ao realizar varredura: {e}")
        return

    # Lista os hosts encontrados
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    print(f"Hosts encontrados: {hosts_list}")
    for host, status in hosts_list:
        print(f"Host encontrado: {host} ({status})")
        scan_ports(host, nmap_path)  # Escaneia as portas do host

def scan_ports(ip, nmap_path):
    # Cria um objeto scanner do Nmap
    try:
        nm = nmap.PortScanner(nmap_search_path=[nmap_path])
        print("Scanner Nmap inicializado para portas.")
    except Exception as e:
        print(f"Erro ao inicializar o Nmap para escaneamento de portas: {e}")
        return

    # Escaneia as portas específicas (21, 22, 23, 80, 443, 3306, 3389, 53, 4433, 8080)
    print(f"Escaneando as portas específicas no host {ip}...")
    try:
        nm.scan(ip, arguments='-p 21,22,23,80,443,3306,3389,53,4433,8080')
        print("Escaneamento de portas realizado com sucesso.")
    except Exception as e:
        print(f"Erro ao escanear portas: {e}")
        return

    # Lista as portas abertas
    for proto in nm[ip].all_protocols():
        print(f"Protocolo: {proto}")
        ports = nm[ip][proto].keys()
        for port in ports:
            state = nm[ip][proto][port]['state']
            print(f"Porta {port}: {state}")
            if state == 'open':
                print_security_tips(port)

def print_security_tips(port):
    # Dicas de segurança para proteger portas abertas
    tips = {
        21: "Porta 21 (FTP): Certifique-se de usar FTP sobre TLS (FTPS) para encriptar os dados e proteger senhas.",
        22: "Porta 22 (SSH): Habilite a autenticação por chave SSH e desative a autenticação por senha.",
        23: "Porta 23 (Telnet): Evite usar Telnet, pois ele transmite dados em texto simples. Use SSH no lugar.",
        80: "Porta 80 (HTTP): Considere implementar HTTPS para proteger a comunicação e garantir a privacidade dos dados.",
        443: "Porta 443 (HTTPS): Verifique se o certificado SSL/TLS é válido e atualizado para evitar vulnerabilidades.",
        3306: "Porta 3306 (MySQL): Limite o acesso remoto ao MySQL e utilize senhas fortes para proteger o banco de dados.",
        3389: "Porta 3389 (RDP): Use autenticação multifatorial (MFA) e altere senhas padrão para proteger o RDP.",
        53: "Porta 53 (DNS): Utilize DNSSEC para garantir a integridade das respostas de DNS e evitar ataques como o DNS spoofing.",
        4433: "Porta 4433 (Custom SSL): Certifique-se de que o certificado SSL/TLS é configurado corretamente e use uma chave forte para criptografia.",
        8080: "Porta 8080 (HTTP Alternativo): Esta porta é comumente usada para servidores web. Certifique-se de que o acesso a essa porta é controlado por firewall e autenticado."
    }
    
    if port in tips:
        print(f"\n[!] Dica de segurança para a porta {port}:\n{tips[port]}\n")
    else:
        print(f"\n[!] Nenhuma dica disponível para a porta {port}. Pesquise por boas práticas de segurança\n") 

if __name__ == "__main__":
    ip_range = "192.168.1.0/24"  # Altere para o IP desejado
    scan_network(ip_range)
