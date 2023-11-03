#!/bin/env python

import argparse
import subprocess
import os
from libnmap.parser import NmapParser
from modules import banner, external_model as em

def main():

    with open('scope.txt') as f:
        scope_ip = [line.rstrip('\n') for line in f]
        for ip in scope_ip:
            nmap_report = NmapParser.parse_fromfile("{}-tcpscan-0.xml".format(ip))
            
            print(f"{ip}"+100*"-")
            
            ssl_ports = []
    
            for host in nmap_report.hosts:
                for port in host.get_open_ports():
                    print(port[0])
                    em.expected_port_service(port)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    #parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    #parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
   
    args = parser.parse_args()

    banner.print_banner()

    main()
