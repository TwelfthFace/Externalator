import subprocess
import os
import json
import re
from ftplib import FTP, FTP_TLS
from modules import json_parser as vuln_json

ip_data = {}

def add_vulnerability(vuln_name, vuln_def_desc="NULL"):
    sp_desc = vuln_json.load_vuln_desc_from_sp(vuln_name) 

    if sp_desc == "NULL":
        sp_desc = vuln_def_desc

    if current_ip not in ip_data:
        ip_data[current_ip] = []

    ip_data[current_ip].append({
        "port": current_port,
        "vuln_name": vuln_json.normalise_vuln_to_sp(vuln_name),
        "vuln_desc": sp_desc,
        'q_a_line': "{}|{}|{}".format(current_ip,current_port[1],current_port[0]) 
    })

   # print(ip_data)

def print_None_if_empty(string):
    if string == "":
        return None
    return string

def print_service_details(nmap_host, port):
    service = nmap_host.get_service(port[0], protocol=port[1])
    print('='*100)
    print(f"Service Name: {print_None_if_empty(service.service)}")
    print(f"Port: {print_None_if_empty(service.port)}")
    print(f"Protocol: {print_None_if_empty(service.protocol)}")
    print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
    print(f"Banner?: {print_None_if_empty(service.banner)}")
    print(' ')

def ssl_tunnel_routine():
#    #enum ciphers: check for CBC ciphers (Lucky13) - BEAST CONDITIONS - SWEET32 - testssl OR sslscan OR nMap
#    #check for other vulns (Heartbleed, CCS,Ticketbleed, ROBOT, Secure_Renegotiation, Secure_Client-Initiated_Renegotiation, CRIME, BREACH POODLE, TLS_FALLBACK_SCSV, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, RC4)
    ssl_checks_to_do = ['PROTOCOL', 'CERTIFICATE','VULNERABILITY']
    for check in ssl_checks_to_do:
        check_file = current_path + '/' + check.lower() + '_test_' + current_ip + '_' + str(current_port[0])
        check_proc_params = [["testssl", "-p", "-oj", check_file, '-q', current_ip + ':' + str(current_port[0])],
                             ["testssl", "-S", "-oj", check_file, '-q', current_ip + ':' + str(current_port[0])],
                             ["testssl", "-U", "-oj", check_file, '-q', current_ip + ':' + str(current_port[0])]]
        check_returncode = 0
        if not os.path.isfile(check_file):
            if check is ssl_checks_to_do[0]:
                check_proc = subprocess.run(check_proc_params[0], input='no'.encode('utf-8'))
            if check is ssl_checks_to_do[1]:
                check_proc = subprocess.run(check_proc_params[1], input='no'.encode('utf-8'))
            if check is ssl_checks_to_do[2]:
                check_proc = subprocess.run(check_proc_params[2], input='no'.encode('utf-8'))
        else:
            check_returncode = 0
    
        print('#'*50 + check + ' ERRORS' + ('#' * (50 - len(check))))
        if not check_returncode >= 242:
            with open(check_file, "r") as f:
                check_json = json.load(f)
                for check_entry in check_json:
                    if check_entry['severity'] not in ['WARN', 'OK', 'INFO']:
                        print(f"VULNERABLE: {vuln_json.normalise_vuln_to_sp(check_entry['id'])} FINDING: {check_entry['finding']}")
                        add_vulnerability(check_entry['id'], check_entry['finding'])
                        
        else:
            print("!!!SKIPPED DUE TO ERROR!!!")
            break

def ftp_routine():
    #check for STARTTLS support / unencrypted login
    #check for anonymous login
    #enumerate version information from banner, try and determine if the service is out of date. // publically disclosed vulnerabilties.
    #tools like nMap scripts / scrape output
    try:
        with FTP(current_ip, timeout=5) as ftp:
            add_vulnerability("BANNER", ftp.getwelcome())
            login_resp = ftp.login()
            if "230" in login_resp:
                print('#'*50 + ' ERRORS' + ('#' * (50 - len('ERRORS'))))
                print(f"ANON LOGIN: {login_resp}")
                add_vulnerability("Anonymous FTP Enabled")
    
        service = current_nmap_host.get_service(current_port[0], protocol=current_port[1])

        service_scripts = service.scripts_results
        
        for scripts in service_scripts:
            if scripts['id'] == 'ssl-cert':
                print('FTP advertises ssl-cert: probable explicit FTP support')
                return
            else:
                add_vulnerability("Cleartext FTP Protocol Detection")
    except Exception as e:
        print(f'Error checking FTP: {e}')

def ssh_routine():
#    #check for SSHv1 
#    #check for outdated SSH version in banner.
#    #check for publically disclosed vulnerabilities.
#    #ssh-audit to look for insecure kex algo
#    #check for password authentication
    try:
        result = subprocess.run(['nc', '-w', '2', '-v', current_ip, str(current_port[0])], input='X'.encode('utf-8'), capture_output=True)
        banner = result.stdout.decode()
        add_vulnerability("BANNER")
        match = re.search(r'SSH-(\d+\.\d+)-', banner)
        if match:
            version = float(match.group(1))
            if version < 2.0:
                print(f"[!] {current_ip}:{current_port[0]} has outdated SSH version: {version}")
                add_vulnerability("Outdated and Unsupported Software")

        ssh_audit = subprocess.run(['ssh-audit', '-j', current_ip, str(current_port[0])], capture_output=True)
        ssh_audit_results = json.loads(ssh_audit.stdout.decode())
        
        #critical_kex_names = [item["name"] for item in ssh_audit_results["recommendations"]["critical"]["del"]["kex"]]

        for outer in ssh_audit_results:
            if outer == "recommendations":
                for recommendation in ssh_audit_results['recommendations']:
                    if "critical" in recommendation:
                        for ops in ssh_audit_results['recommendations'][recommendation]:
                            for keys in ssh_audit_results['recommendations'][recommendation][ops]:
                                if keys == "kex":
                                    for keys in ssh_audit_results['recommendations'][recommendation][ops][keys]:
                                        add_vulnerability("SSH Weak Key Exchange Algorithms Enabled")
                                        return
            else:
                print("No Recommendations Found...")

    except Exception as e:
        print(f"Error checking SSH: {e}")

#def telnet_routine():
#    #Check software version via server banner for vulnerabilities/outdated software
#    #Check for interesting access/functionality
#    #Check for NTLM information disclosure
#
def expected_port_service(nmap_host, ip, port, path):
    global current_nmap_host, current_ip, current_port, current_path
    current_nmap_host = nmap_host
    current_path = path
    current_ip = ip 
    current_port = port
    try:    
        match port[0], port[1]:
            case 21, 'tcp':
                print_service_details(nmap_host, port)
                ftp_routine()
            case 22, 'tcp':
                print_service_details(nmap_host, port)
                ssh_routine()
            case 23, 'tcp':
                print_service_details(nmap_host, port)
            case 25, 'tcp':
                print_service_details(nmap_host, port)
            case 69, 'udp':
                print_service_details(nmap_host, port)
            case 110, 'tcp':
                print_service_details(nmap_host, port)
            case 143, 'tcp':
                print_service_details(nmap_host, port)
            case 161, 'udp':
                print_service_details(nmap_host, port)
            case 162, 'udp':
                print_service_details(nmap_host, port)
            case 80, 'tcp':
                print_service_details(nmap_host, port)
            case 443, 'tcp':
                print_service_details(nmap_host, port)
                ssl_tunnel_routine()
            case 53, 'udp':
                print_service_details(nmap_host, port)
            case 445, 'tcp':
                print_service_details(nmap_host, port)
            case 388, 'tcp':
                print_service_details(nmap_host, port)
            case 993, 'tcp':
                print_service_details(nmap_host, port)
                ssl_tunnel_routine()
            case 636, 'tcp':
                print_service_details(nmap_host, port)
            case 135, 'tcp':
                print_service_details(nmap_host, port)
            case 3389, 'tcp':
                print_service_details(nmap_host, port)
            case 1433, 'tcp':
                print_service_details(nmap_host, port)
            case 4022, 'tcp':
                print_service_details(nmap_host, port)
            case 135, 'tcp':
                print_service_details(nmap_host, port)
            case 1434, 'tcp':
                print_service_details(nmap_host, port)
            case 1434, 'udp':
                print_service_details(nmap_host, port)
            case 123, 'udp':
                print_service_details(nmap_host, port)
                add_vulnerability("Network Time Protocol (NTP) Mode 6 Scanner")
            case _:
                print_service_details(nmap_host, port)
                service = nmap_host.get_service(port[0], protocol=port[1])
                if "ssl" in service.tunnel:
                    ssl_tunnel_routine()
    except Exception as e:
        print(repr(e))
