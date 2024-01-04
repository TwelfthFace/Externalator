#!/bin/env python

import argparse
import subprocess
import os
import inspect, os.path
import json
from libnmap.parser import NmapParser
from modules import banner, external_model as em, json_parser as vuln_json
def main(): 
    errors = []
    xml_files = [os.path.join(working_dir + '/xml', name) for name in os.listdir(working_dir + '/xml/')]

    for file in xml_files:
        try:
            nmap_report = NmapParser.parse_fromfile(file)
            for host in nmap_report.hosts:
                if host.get_open_ports():
                    print('')
                    print('-'*50 + f'{host.address} ' + '-' * ( 49 - len(host.address)))
                    for port in host.get_open_ports():
                        if host.hostnames:
                            for hostname in host.hostnames:
                                print("URL: " +  hostname)
                                em.expected_port_service(host, hostname, port, working_dir)
                        else:
                            em.expected_port_service(host, host.address, port, working_dir)
        except Exception as e:
            errors.append(f"Invalid XML in {working_dir} : {file} : {e}")

    grouped_data = {}

    for ip, vulnerabilities in em.ip_data.items():
        for vulnerability in vulnerabilities:
            vuln_name = vulnerability["vuln_name"]
            q_a_line = vulnerability["q_a_line"]
            ip_protocol, protocol, port = q_a_line.split('|')
    
            if vuln_name not in grouped_data:
                grouped_data[vuln_name] = {}
    
            if ip_protocol not in grouped_data[vuln_name]:
                grouped_data[vuln_name][ip_protocol] = {}
    
            if protocol not in grouped_data[vuln_name][ip_protocol]:
                grouped_data[vuln_name][ip_protocol][protocol] = []
    
            grouped_data[vuln_name][ip_protocol][protocol].append(port)
    
    for vuln_name, info in grouped_data.items():
        print()
        print(f"Vulnerability Name: {vuln_name}")
        print("Q&A Lines:")
        for ip_protocol, protocol_info in info.items():
            for protocol, ports in protocol_info.items():
                print(f"{ip_protocol}|{protocol}|{','.join(ports)}")

    print()
    print("IPs: ")
    print("\n".join([ips[0] for ips in em.ip_data.items()]))
    print()

    if em.missing_headers_table:
        print("Missing Headers!")
        print()
        print("| Host | Strict-Transport-Security | Content-Security-Policy | X-Content-Type-Options | X-Frame-Options |")
        print("|------|---------------------------|-------------------------|------------------------|-----------------|")
        for header in em.missing_headers_table:
            print(header)
    print()
        
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
            os.mkdir(working_dir+'/xml')
            main()

        if x == 'n' or x == 'N':
            exit(1)

