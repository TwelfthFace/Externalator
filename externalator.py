#!/bin/env python

import argparse
import subprocess
import os
from libnmap.parser import NmapParser
from modules import banner, external_model as em

def main(): 
    print("main")   
   # with open('scope.txt') as f:
   #     scope_ip = [line.rstrip('\n') for line in f]
   #     for ip in scope_ip:
   #         nmap_report = NmapParser.parse_fromfile("{}-tcpscan-0.xml".format(ip))
   #         
   #         print(f"{ip}"+100*"-")
   #         
   #         ssl_ports = []
   # 
   #         for host in nmap_report.hosts:
   #             for port in host.get_open_ports():
   #                 print(port[0])
   #                 em.expected_port_service(port)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    parser.add_argument('work_dir', action='store', metavar='work_dir', help='Working Directory, should pertain to a single clients Nmap files.')
    #parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    #parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
   

    args = parser.parse_args()

    working_dir = os.getcwd() + '/' +args.work_dir

    banner.print_banner()
    
    if os.path.isdir(working_dir):
        print(f'{args.work_dir}: exists...')
        main()
    else:
        print(f'{args.work_dir}: doesn\'t  exist... create the directory (Y/n): ')
        x = input()
        if x == 'y' or x == 'Y' or x == '':
            os.mkdir(working_dir)
            main()

        if x == 'n' or x == 'N':
            exit(1)

