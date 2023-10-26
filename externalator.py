#!/bin/env python

import argparse
import subprocess
import os
from termcolor import colored
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
            run_testssl(host.address, ssl_ports)

def run_testssl(ip, port_list):
    deprecated_protocols = ["SSLv2", "SSLv3", "TLS 1", "TLS 1.1"]

    for port in port_list:
        filename = f"./{ip}-testssl-{port}"
        if not filename:
            f = open(filename)
            subprocess.run(["testssl", "--color", "0", f"{ip}:{port}"], check=True, stdout=f, stderr=f)
    else:
        with open(filename) as file:
            for line in file:
                line = line.strip()
                if "offered (deprecated)" in line:
                    for protocol in deprecated_protocols:
                        if protocol in line:
                            line = colored(line, 'white', 'on_red')
                            break
                print(line) 

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    #parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    #parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
   
    args = parser.parse_args()

    banner.print_banner()

    main()
