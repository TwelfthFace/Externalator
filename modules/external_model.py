import subprocess
import os
import json

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
    #check for deprecated version support
    proto_check_file = current_path + '/proto_test_' + current_ip + '_' + str(current_port[0])
    proto_returncode = 0
    # got to do this because of a testssl bug (or lack of feature) if file exists the json file will be invalidated as ssltest will append errors to the json file incorrectly
    if not os.path.isfile(proto_check_file):
        proto_check = subprocess.run(["testssl","-p", "-oj", proto_check_file, current_ip + ':' + str(current_port[0])])
        proto_checkcode = proto_check.returncode
    else:
        proto_returncode = 0
    print('#'*50 + 'PROTOCOL ERRORS' + ('#' * (50 - len('PROTOCOL ERRORS'))))
    if not proto_returncode >= 242:
        with open(proto_check_file, "r") as f:
            proto_json = json.load(f)
            for proto_entry in proto_json:
                if proto_entry['severity'] not in ['WARN', 'OK', 'INFO']:
                    print(f"VULNERABLE: {proto_entry['id']} FINDING: {proto_entry['finding']}")

    #validate certificates: expirery, wildcards, NOT self-signed valid CA
    cert_check_file = current_path + '/cert_test_' + current_ip + '_' + str(current_port[0])
    cert_returncode = 0
    # got to do this because of a testssl bug (or lack of feature) if file exists the json file will be invalidated as ssltest will append errors to the json file incorrectly
    if not os.path.isfile(cert_check_file):
        cert_check = subprocess.run(["testssl","-S", "-oj", cert_check_file, current_ip + ':' + str(current_port[0])])
        cert_checkcode = cert_check.returncode
    else:
        cert_returncode = 0
    print('#'*50 + 'CERTIFICATE ERRORS' + ('#' * (50 - len('CERTIFICATE ERRORS'))))
    if not cert_returncode >= 242:
        with open(cert_check_file, "r") as f:
            cert_json = json.load(f)
            for cert_entry in cert_json:
                if cert_entry['severity'] not in ['WARN', 'OK', 'INFO']:
                    print(f"VULNERABLE: {cert_entry['id']} FINDING: {cert_entry['finding']}")

    #enum ciphers: check for CBC ciphers (Lucky13) - BEAST CONDITIONS - SWEET32 - testssl OR sslscan OR nMap
    #check for other vulns (Heartbleed, CCS,Ticketbleed, ROBOT, Secure_Renegotiation, Secure_Client-Initiated_Renegotiation, CRIME, BREACH POODLE, TLS_FALLBACK_SCSV, SWEET32, FREAK, DROWN, LOGJAM, BEAST, LUCKY13, Winshock, RC4)
    vuln_check_file = current_path + '/vuln_test_' + current_ip + '_' + str(current_port[0])
    vuln_returncode = 0
    # got to do this because of a testssl bug (or lack of feature) if file exists the json file will be invalidated as ssltest will append errors to the json file incorrectly
    if not os.path.isfile(vuln_check_file):
        vuln_check = subprocess.run(["testssl","-U", "-oj", vuln_check_file, current_ip + ':' + str(current_port[0])])
        vuln_checkcode = vuln_check.returncode
    else:
        vuln_returncode = 0
    print('#'*50 + 'VULNERABILITY ERRORS' + ('#' * (50 - len('VULNERABILITY ERRORS'))))
    if not vuln_returncode >= 242:
        with open(vuln_check_file, "r") as f:
            vulns_json = json.load(f)
            for vuln_entry in vulns_json:
                if vuln_entry['severity'] not in ['WARN', 'OK', 'INFO']:
                    print(f"VULNERABLE: {vuln_entry['id']} FINDING: {vuln_entry['finding']}")


#def ftp_routine():
    #check for STARTTLS support / unencrypted login
    #check for anonymous login
    #enumerate version information from banner, try and determine if the service is out of date. // publically disclosed vulnerabilties.
    #tools like nMap scripts / scrape output

#def ssh_routine():
#    #check for SSHv1 
#    #check for outdated SSH version in banner.
#    #check for publically disclosed vulnerabilities.
#    #ssh-audit to look for insecure kex algo
#    #check for password authentication
#
#def telnet_routine():
#    #Check software version via server banner for vulnerabilities/outdated software
#    #Check for interesting access/functionality
#    #Check for NTLM information disclosure
#
def expected_port_service(nmap_host, ip, port, path):
    global current_ip, current_port, current_path
    current_path = path
    current_ip = ip 
    current_port = port
    try:    
        match port[0], port[1]:
            case 21, 'tcp':
                print_service_details(nmap_host, port)
            case 22, 'tcp':
                print_service_details(nmap_host, port)
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
            case _:
                print_service_details(nmap_host, port)
                service = nmap_host.get_service(port[0], protocol=port[1])
                if "ssl" in service.tunnel:
                    ssl_tunnel_routine()
    except Exception as e:
        print(repr(e))

