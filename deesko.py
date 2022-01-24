#!/usr/bin/python3

import sys, getopt, os
from scripts import core

argv = sys.argv[1:]

short_options = 'd:P:t:s:c:p:l' 
long_options =  ['discover=','Ports=','timeout=','sweeps=','count=','port=','lookup']

try:
    opts, args = getopt.getopt(argv,short_options,long_options)
except getopt.error as err:
    print('ERROR! disko.py -d <what to deesKover> -P <string of comma-separated ports, or range> -t <timeout (optional, defaults to 1s)> -s <ping sweep types, defaults to "icmp"> -c <ping count, defaults to 1> -p <TCP or UDP port, defaults to 443> -l <to perform OUI lookup, defaults to False>')
    print(str(err))
    sys.exit()

list_of_options_passed = []
for item in opts:
    list_of_options_passed.append(item[0])

if ('-d' not in list_of_options_passed) and ('--discover' not in list_of_options_passed):
    print('ERROR! disko.py -d <what to deesKover> -P <string of comma-separated ports, or range> -t <timeout (optional, defaults to 1s)> -s <ping sweep types, defaults to "icmp"> -c <ping count, defaults to 1> -p <TCP or UDP port, defaults to 443> -l <to perform OUI lookup, defaults to False>')
    print('Missing required argument -d or --discover <10.0.0.0/24 or interface name>')
    sys.exit()

# Set some defaults for the optional arguments
target_tcp_ports_to_scan = '21,22,23,53,80,443,3306,8080'
target_timeout_seconds = 1
target_ping_sweep_types = 'icmp'
target_ping_count = 1
target_tcp_udp_port = 443
target_oui_lookup = False

for opt, arg in opts:
    if opt in ('-d', '--discover'):
        target_to_discover = str(arg)
    elif opt in ('-P', '--Ports'):
        target_tcp_ports_to_scan = str(arg)
    elif opt in ('-t', '--timeout'):
        target_timeout_seconds = int(arg)
    elif opt in ('-s', '--sweeps'):
        target_ping_sweep_types = str(arg)
    elif opt in ('-c', '--count'):
        target_ping_count = int(arg)
    elif opt in ('-p', '--port'):
        target_tcp_udp_port = int(arg)
    elif opt in ('-l', '--lookup'):
        target_oui_lookup = True
    else:
        print('ERROR! disko.py -d <what to deesKover> -P <string of comma-separated ports, or range> -t <timeout (optional, defaults to 1s)> -s <ping sweep types, defaults to "icmp"> -c <ping count, defaults to 1> -p <TCP or UDP port, defaults to 443> -l <to perform OUI lookup, defaults to False>')
        sys.exit()

#print('target_to_discover',target_to_discover)
#print('target_timeout_seconds',target_timeout_seconds)
#print('target_ping_sweep_types',target_ping_sweep_types)
#print('target_ping_count',target_ping_count)
#print('target_tcp_udp_port',target_tcp_udp_port)
#print('target_oui_lookup',target_oui_lookup)

host = core.system()
host.discover(
        option = target_to_discover,
        tcp_ports_to_scan = target_tcp_ports_to_scan,
        timeout_seconds=target_timeout_seconds,
        ping_sweeps=target_ping_sweep_types, 
        ping_count=target_ping_count, 
        tcp_udp_port=target_tcp_udp_port,
        oui_lookup=target_oui_lookup
    )
host.export('scans')