#!/bin/env python

import argparse
import subprocess
import os
from libnmap.parser import NmapParser
from modules import banner

def main():

    with open('scope.txt') as f:
        scope_ip = [line.rstrip('\n') for line in f]
        nmap_report = NmapParser.parse_fromfile("{}-tcpscan-0.xml".format(scope_ip[0]))
        
        print(f"{nmap_report.hosts[0]}"+100*"-")
        
        ssl_ports = []
    
        for host in nmap_report.hosts:
            for service in host.services:
                if service.open() and "ssl" in service.tunnel:
                    print(f"{service.tunnel} found for service: {service.service} on port {service.port}")
                    ssl_ports.append(service.port)
            run_sslscan(host.address, ssl_ports)

        print(ssl_ports[0])        

def run_sslscan(ip, port_list):
    for port in port_list:
        if not os.path.isfile(f"./{ip}-sslscan-{port}"):
            f = open(f"./{ip}-sslscan-{port}")
            subprocess.run(["sslscan",f"{ip}:{port}"], check=True, stdout=f, stderr=f)
    else:
        print("FILE EXISTS")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    #parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    #parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
   
    args = parser.parse_args()

    banner.print_banner()

    main()
