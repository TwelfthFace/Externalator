def print_None_if_empty(string):
    if string == "":
        return None
    return string

def print_service_details(nmap_host, port):
    service = nmap_host.get_service(port[0], protocol=port[1])
    print(f"Service Name: {print_None_if_empty(service.service)}")
    print(f"Port: {print_None_if_empty(service.port)}")
    print(f"Protocol: {print_None_if_empty(service.protocol)}")
    print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
    print(f"Banner?: {print_None_if_empty(service.banner)}")
    print('='*100)

def expected_port_service(nmap_host, ip, port):
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
            case 53, 'udp':
                print_service_details(nmap_host, port)
            case 445, 'tcp':
                print_service_details(nmap_host, port)
            case 388, 'tcp':
                print_service_details(nmap_host, port)
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
    except Exception as e:
        print(repr(e))

