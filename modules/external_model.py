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
                        print(f"VULNERABLE: {check_entry['id']} FINDING: {check_entry['finding']}")
        else:
            print("!!!SKIPPED DUE TO ERROR!!!")
            break



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

