def expected_port_service(ip, port):
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
                print("")
            case 443, 'tcp':
                print("")
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
                raise NotImplementedError(f"PORT:{port[0]} NOT IMPLEMENTED! Yet...")
    except NotImplementedError as e:
        print(repr(e))
