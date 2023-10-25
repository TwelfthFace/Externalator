#!/bin/env python

import argparse
from libnmap.parser import NmapParser
from modules import banner

def main():

    with open('scope.txt') as f:
        scope_list = [line.rstrip('\n') for line in f]
        nmap_report = NmapParser.parse_fromfile("{}-tcpscan-0.xml".format(scope_list[0]))
        for host in nmap_report.hosts:
            for service in host.services:
                if service.open() and "ssl" in service.tunnel:
                    print(f"{service.tunnel} found for service: {service.service} on port {service.port}")


    print("Nmap scan summary: {0}".format(nmap_report.summary))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
    
    args = parser.parse_args()

    banner.print_banner()

    main()
