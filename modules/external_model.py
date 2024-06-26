import subprocess
import os
import json
import re
import requests
import pexpect
from datetime import datetime, timedelta
from urllib3.exceptions import InsecureRequestWarning
from ftplib import FTP, FTP_TLS
from modules import json_parser as vuln_json

ip_data = {}
missing_headers_table = []
version_headers_table = []
ssh_failed_kex_table = []

def add_vulnerability(vuln_name, vuln_def_desc="NULL"):
    #sp_desc = vuln_json.load_vuln_desc_from_sp(vuln_name) 

    #if sp_desc == "NULL":
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

def print_service_details():
    print('='*100)
    print(f"Service Name: {print_None_if_empty(service.service)}")
    print(f"Port: {print_None_if_empty(service.port)}")
    print(f"Protocol: {print_None_if_empty(service.protocol)}")
    print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
    print(f"Banner?: {print_None_if_empty(service.banner)}")
    print()

def check_headers(url):
    try:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        response = requests.get(url, timeout=8, verify=False, allow_redirects=False)
        print()
        print("!! Checking Security Headers !!")
        
        # floor division // 
        if response.status_code // 100 == 2 or response.status_code == 403 or response.status_code == 302:
            headers_to_check = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options']
            common_version_headers = [
                 "Server",
                 "X-Powered-By",
                 "X-AspNet-Version",
                 "X-Runtime",
                 "X-Drupal-Cache",
                 "X-Joomla-Cache",
                 "X-Pingback",
                 "X-Version",
                 "X-Generator",
                 "X-Powered-CMS",
                 "X-Wix-Renderer-Server",
                 "X-Wix-Server-Architecture",
                 "X-Wix-Application-Instance-Id",
                 "X-Owa-Version",
                 "X-Aspnetmvc-Version"
            ]

            if "X-XSS-Protection" in response.headers:
                add_vulnerability("Deprecated Header In Use: X-XSS Protection")

            #| Host | Strict-Transport-Security | Content-Security-Policy | X-Content-Type-Options | X-Frame-Options |
            missing_headers = {"Strict-Transport-Security": "", "Content-Security-Policy": "", "X-Content-Type-Options": "", "X-Frame-Options": ""}

            for header in headers_to_check:
                if header.lower() not in (h.lower() for h in response.headers.keys()):
                    missing_headers[header] = "[Missing](#high)"
                else:
                    missing_headers[header] = "[Present](#info)"

            if any(value == "[Missing](#high)" for value in missing_headers.values()):
                add_vulnerability("Missing HTTP Security Headers")
                missing_headers_table.append(f"| {url} | {'| '.join(missing_headers.values())} |")
            else:
                print(f"All security headers are present for {url}.")

            for version_header in common_version_headers:
                if version_header.lower() in (h.lower() for h in response.headers.keys()):
                    version_headers_table.append(f"| {url} | {version_header} | {response.headers[version_header]} |")
                    add_vulnerability("Software Version Disclosure")
        else:
            print(f"Error: {response.status_code} - Unable to fetch the URL {url}.")
    except requests.RequestException as e:
        print(f"Error: {e} at: {url}")

def ssl_tunnel_routine():
#    #enum ciphers: check for CBC ciphers (Lucky13) - BEAST CONDITIONS - SWEET32 - testssl OR sslscan OR nMap
#    #check for other vulns (Heartbleed, CCS,Ticketbleed, ROBOT, Secure_Renegotiation, Secure_Client-Initiated_Renegotiation, CRIME, BREACH POODLE, TLS_FALLBACK_SCSV, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, RC4)
    ssl_checks_to_do = ['PROTOCOL', 'CERTIFICATE', 'VULNERABILITY']
    for check in ssl_checks_to_do:
        check_file = current_path + '/' + check.lower() + '_test_' + current_ip + '_' + str(current_port[0])
        # Modify check_proc_params to construct a command string that includes the tee command.
        check_proc_params = [
            f"testssl --nodns min -p -q  -oj {check_file} {current_ip}:{current_port[0]} | tee {check_file + '_colour_out'}",
            f"testssl --nodns min -S -q  -oj {check_file} {current_ip}:{current_port[0]} | tee {check_file + '_colour_out'}",
            f"testssl --nodns min -U -q  -oj {check_file} {current_ip}:{current_port[0]} | tee {check_file + '_colour_out'}"
        ]
        check_returncode = 0
        if not os.path.isfile(check_file):
            if check == ssl_checks_to_do[0]:  # Use == for string comparison
                check_proc = subprocess.run(check_proc_params[0], shell=True, input='no'.encode('utf-8'))
            elif check == ssl_checks_to_do[1]:
                check_proc = subprocess.run(check_proc_params[1], shell=True, input='no'.encode('utf-8'))
            elif check == ssl_checks_to_do[2]:
                check_proc = subprocess.run(check_proc_params[2], shell=True, input='no'.encode('utf-8'))
            # Check the return code directly from the subprocess call
            check_returncode = check_proc.returncode
        else:
            print(f"{check} check already performed. File exists: {check_file}") 
        print('#'*50 + check + ' ERRORS' + ('#' * (50 - len(check))))
        if not check_returncode >= 242:
            with open(check_file, "r") as f:
                check_json = json.load(f)
                
                for check_entry in check_json:
                    if check_entry['id'] == 'cert_extlifeSpan':
                        if check_entry['severity'] != 'OK':
                            cert_lifespan = check_entry['finding'].split()[0].strip()

                            if int(cert_lifespan) > 825:
                                print(f"VULNERABLE: {check_entry['id']} FINDING: {check_entry['finding']}")
                                add_vulnerability("Excessive SSL/TLS Certificate Validity")
                        else:
                            print("Certificate doesn't have excessive validity")

                    
                    if check_entry['id'] == 'cert_commonName':
                        # check for wildcard in CN
                        if '*' in check_entry['finding']:
                            print(f"VULNERABLE: {check_entry['id']} FINDING: {check_entry['finding']}")
                            add_vulnerability("Wildcard TLS Certificate in Use")
                    if check_entry['severity'] not in ['WARN', 'OK', 'INFO']:
                        if check_entry['id'] == 'cert_expirationStatus':
                            if 'expired' in check_entry['finding']:
                                print("VULNERABLE: Certificate has expired!")
                                add_vulnerability("TLS Certificate has expired!")
                                continue
                        if check_entry['id'] == 'cert_chain_of_trust':
                            if 'expired' in check_entry['finding']:
                                continue
                        print(f"VULNERABLE: {vuln_json.normalise_vuln_to_sp(check_entry['id'])} FINDING: {check_entry['finding']}")
                        add_vulnerability(check_entry['id'], check_entry['finding'])
                #print(json.dumps(check_json, indent=4))
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
            add_vulnerability("BANNER " + ftp.getwelcome())
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
    #check for SSHv1 
    #check for outdated SSH version in banner.
    #check for publically disclosed vulnerabilities.
    #ssh-audit to look for insecure kex algo
    #check for password authentication
    try:
        result = subprocess.run(['nc', '-w', '2', '-v', current_ip, str(current_port[0])], input='X'.encode('utf-8'), capture_output=True)
        banner = result.stdout.decode()
        add_vulnerability("BANNER: " + banner.strip())

        match = re.search(r'SSH-(\d+\.\d+)-', banner)
        if banner != '':
            if match:
                version = float(match.group(1))
                if version < 2.0:
                    print(f"[!] {current_ip}:{current_port[0]} has outdated SSH version: {version}")
                    add_vulnerability("Outdated and Unsupported Software")
            else:
                print("Unable to determine SSH version.")
        else:
            print("Empty banner!")

        child = pexpect.spawn(f'ssh root@{current_ip} -p{str(current_port[0])}')
        try:
            index = child.expect(['password:', 'continue connecting (yes/no)?'], timeout=10)
            if index == 0:
                print("Password prompt found. Password authentication is supported.")
                add_vulnerability("Public-Facing SSH Service with Password Protection")
            elif index == 1:
                child.sendline('yes')
                index = child.expect(['password:', pexpect.EOF], timeout=10)
                if index == 0:
                    print("Password prompt found after accepting key. Password authentication is supported.")
                    add_vulnerability("Public-Facing SSH Service with Password Protection")
        except pexpect.exceptions.TIMEOUT:
            print("Connection attempt timed out.")
        except pexpect.exceptions.EOF:
            print("Connection closed unexpectedly.")
        finally:
            child.close()

        ssh_audit = subprocess.run(['ssh-audit', '-j', current_ip, '-p', str(current_port[0])], capture_output=True)
        ssh_audit_results = json.loads(ssh_audit.stdout.decode())
        
        failed_kex_algos = []

        for kex in ssh_audit_results.get("kex", []):
            if "fail" in kex.get("notes", []):
                failed_kex_algos.append(kex['algorithm'])
        
        for algo in failed_kex_algos:
            ssh_failed_kex_table.append(f"| {current_ip}:{current_port[0]} | {algo} |")

        if failed_kex_algos:
            add_vulnerability("Insecure KEX Algoritm Supported")

    except Exception as e:
        print(f"Error checking SSH: {e}")

def telnet_routine():
    #Check software version via server banner for vulnerabilities/outdated software
    #Check for interesting access/functionality
    #Check for NTLM information disclosure
    add_vulnerability("Unencrypted Telnet Server")

    service_scripts = service.scripts_results

    for scripts in service_scripts:
        if scripts['id'] == "telnet-ntlm-info":
            print(scripts['id'])
            if scripts['id'] != '':
                add_vulnerability("Public-Facing NTLM Login")

def expected_port_service(nmap_host, ip, port, path):
    global current_nmap_host, current_ip, current_port, current_path, service
    current_nmap_host = nmap_host
    current_path = path
    current_ip = ip 
    current_port = port
    service = nmap_host.get_service(port[0], protocol=port[1])
    try:    
        match port[0], port[1]:
            case 21, 'tcp':
                print_service_details()
                ftp_routine()
            case 22, 'tcp':
                print_service_details()
                ssh_routine()
            case 23, 'tcp':
                print_service_details()
                telnet_routine()
            #case 25, 'tcp':
            #    print_service_details()
            #case 69, 'udp':
            #    print_service_details()
            #case 110, 'tcp':
            #    print_service_details()
            #case 143, 'tcp':
            #    print_service_details()
            #case 161, 'udp':
            #    print_service_details()
            #case 162, 'udp':
            #    print_service_details()
            case 80, 'tcp':
                print_service_details()
                check_headers("http://" + current_ip + ':' + str(current_port[0]))
            case 443, 'tcp':
                print_service_details()
                ssl_tunnel_routine()
                if "http" in service.service:
                    check_headers("https://" + current_ip + ':' + str(current_port[0]))
            #case 53, 'udp':
            #    print_service_details()
            #case 445, 'tcp':
            #    print_service_details()
            #case 388, 'tcp':
            #    print_service_details()
            #case 993, 'tcp':
            #    print_service_details()
            #    ssl_tunnel_routine()
            #case 636, 'tcp':
            #    print_service_details()
            #case 135, 'tcp':
            #    print_service_details()
            #case 3389, 'tcp':
            #    print_service_details()
            #case 1433, 'tcp':
            #    print_service_details()
            #case 4022, 'tcp':
            #    print_service_details()
            #case 135, 'tcp':
            #    print_service_details()
            #case 1434, 'tcp':
            #    print_service_details()
            #case 1434, 'udp':
            #    print_service_details()
            case 123, 'udp':
                print_service_details()
                add_vulnerability("Network Time Protocol (NTP) Mode 6 Scanner")
            case _:
                print_service_details()
                if "ssl" in service.tunnel:
                    ssl_tunnel_routine()
                    if "http" in service.service:
                        check_headers("https://" + current_ip + ':' + str(current_port[0]))
                else:
                    if "http" in service.service:
                        check_headers("http://" + current_ip + ':' + str(current_port[0]))

                if "ssh" in service.service:
                    ssh_routine()

    except Exception as e:
        print(repr(e))
