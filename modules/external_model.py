def expected_port_service(port):
    match port:
        case 21:
            print(f"{port}")
        case 22:
            print(f"{port}")
        case 23:
            print(f"{port}")
        case 25:
            print(f"{port}")
        case 69:
            print(f"{port}")
        case 110:
            print(f"{port}")
        case 143:
            print(f"{port}")
        case 161:
            print(f"{port}")
        case 162:
            print(f"{port}")
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
            #raise Exception("NOT IMPLEMENTED! yet...")
            print("HEHE")
