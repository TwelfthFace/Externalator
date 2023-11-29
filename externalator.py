#!/bin/env python

import argparse
import subprocess
import os
import inspect, os.path
from libnmap.parser import NmapParser
from modules import banner, external_model as em, json_parser as json
def main(): 
    errors = []
    xml_files = [os.path.join(working_dir, name) for name in os.listdir(working_dir)]

    for file in xml_files:
        try:
            nmap_report = NmapParser.parse_fromfile(file)
            for host in nmap_report.hosts:
                if host.get_open_ports():
                    print('-'*50 + f'{host.address} ' + '-' * ( 49 - len(host.address)))
                    for port in host.get_open_ports():
                       service = host.get_service(port[0], protocol=port[1])
                       em.expected_port_service(host, host.address, port)
        except Exception as e:
            errors.append(f"Invalid XML in {working_dir} : {file} : {e}")
    
    json.load_vulns_from_files(path)

    [print(error) for error in errors]

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    parser.add_argument('work_dir', action='store', metavar='work_dir', help='Working Directory, should pertain to a single clients Nmap files.')

    args = parser.parse_args()
    
    working_dir = os.getcwd() + '/' +args.work_dir
    filename = inspect.getframeinfo(inspect.currentframe()).filename
    path     = os.path.dirname(os.path.abspath(filename))

    banner.print_banner()
    
    if os.path.isdir(working_dir):
        print(f'{args.work_dir}: exists...')
        main()
    else:
        print(f'{args.work_dir}: doesn\'t  exist... create the directory (Y/n): ', end='')
        x = input()
        if x == 'y' or x == 'Y' or x == '':
            os.mkdir(working_dir)
            main()

        if x == 'n' or x == 'N':
            exit(1)

