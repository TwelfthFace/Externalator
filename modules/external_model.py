def print_None_if_empty(string):
    if string == "":
        return None
    return string

def expected_port_service(nmap_host, ip, port):
    print('-'*100)
    try:    
        match port[0], port[1]:
            case 21, 'tcp':
                print("")
            case 22, 'tcp':
                print("")
            case 23, 'tcp':
                print("")
            case 25, 'tcp':
                print("")
            case 69, 'udp':
                print("")
            case 110, 'tcp':
                print("")
            case 143, 'tcp':
                print("")
            case 161, 'udp':
                print("")
            case 162, 'udp':
                print("")
            case 80, 'tcp':
                service = nmap_host.get_service(port[0], protocol=port[1])
                print(f"Service Name: {print_None_if_empty(service.service)}")
                print(f"Port: {print_None_if_empty(service.port)}")
                print(f"Protocol: {print_None_if_empty(service.protocol)}")
                print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
                print(f"Banner?: {print_None_if_empty(service.banner)}")
            case 443, 'tcp':
                service = nmap_host.get_service(port[0], protocol=port[1])
                print(f"Service Name: {print_None_if_empty(service.service)}")
                print(f"Port: {print_None_if_empty(service.port)}")
                print(f"Protocol: {print_None_if_empty(service.protocol)}")
                print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
                print(f"Banner?: {print_None_if_empty(service.banner)}")
            case 53, 'udp':
                print("")
            case 445, 'tcp':
                print("")
            case 389, 'tcp':
                print("")
            case 636, 'tcp':
                print("")
            case 135, 'tcp':
                print("")
            case 3389, 'tcp':
                print("")
            case 1433, 'tcp':
                print("")
            case 4022, 'tcp':
                print("")
            case 135, 'tcp':
                print("")
            case 1434, 'tcp':
                print("")
            case 1434, 'udp':
                print("")
            case _:
                service = nmap_host.get_service(port[0], protocol=port[1])
                print(f"Service Name: {print_None_if_empty(service.service)}")
                print(f"Port: {print_None_if_empty(service.port)}")
                print(f"Protocol: {print_None_if_empty(service.protocol)}")
                print(f"Tunnel?: {print_None_if_empty(service.tunnel)}")
                print(f"Banner?: {print_None_if_empty(service.banner)}")
    except Exception as e:
        print(repr(e))

    print('-'*100)
