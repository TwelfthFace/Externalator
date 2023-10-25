#!/bin/env python

import argparse
from libnmap.parser import NmapParser
from modules import banner

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='External Infrastructure automator for usage inside PentestPeople.')
    parser.add_argument('IP', metavar='ip', help='IP address to aim at.')
    parser.add_argument('Port', metavar='port', type=int, help='Port to aim at.')
    
    args = parser.parse_args()

    banner.print_banner()
