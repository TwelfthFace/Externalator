def expected_port_service(port):
    port_port = port[0]
    port_protocol = port[1]
    try:    
        match port[0]:
            case 21:
                print(f"{port[0]}")
            case 22:
                print(f"{port[0]}")
            case 23:
                print(f"{port[0]}")
            case 25:
                print(f"{port[0]}")
            case 69:
                print(f"{port[0]}")
            case 110:
                print(f"{port[0]}")
            case 143:
                print(f"{port[0]}")
            case 161:
                print(f"{port[0]}")
            case 162:
                print(f"{port[0]}")
            case 80:
                print(f"{port}")
            case 443:
                print(f"{port}")
            case 445:
                print(f"{port}")
            case 389:
                print(f"{port}")
            case 636:
                print(f"{port}")
            case 135:
                print(f"{port}")
            case 3389:
                print(f"{port}")
            case 1433:
                print(f"{port}")
            case 4022:
                print(f"{port}")
            case 135:
                print(f"{port}")
            case 1434:
                print(f"{port}")
            case _:
                raise NotImplementedError(f"PORT:{port[0]} NOT IMPLEMENTED! Yet...")
    except NotImplementedError as e:
        print(repr(e))
