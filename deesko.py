#!/usr/bin/python3

import sys, getopt, os
from scripts import core
import pdb

host = core.system()

argv = sys.argv[1:]

short_options = 'd:P:t:s:c:p:o:lv' 
long_options =  ['discover=','Ports=','timeout=','sweeps=','count=','port=','output=','lookup','verbose']

try:
    opts, args = getopt.getopt(argv,short_options,long_options)
except getopt.error as err:
    print('ERROR!')
    print('Usage: deesko.py -d <IP address, or CIDR range, or local interface name>')
    print('\t'+'-P <string of comma-separated ports, or range>')
    print('\t'+'-o <full path to output file for the downloaded scan report in .json format, default False (no report)>')
    print('\t'+'-t <timeout (optional, default 1s)>')
    print('\t'+'-s <ping sweep types, default "icmp">')
    print('\t'+'-c <ping count, default 1>')
    print('\t'+'-p <TCP port used for TCP ping sweep, default 443>')
    print('\t'+'-l <to perform OUI lookup, default False>')
    print('\t'+'-v <to be verbose and show "Closed" and "Filtered" ports, default False>')
    print(str(err))
    sys.exit()

list_of_options_passed = []
for item in opts:
    list_of_options_passed.append(item[0])

if ('-d' not in list_of_options_passed) and ('--discover' not in list_of_options_passed):
    print('ERROR!')
    print('Missing required argument -d or --discover <10.0.0.0/24 or interface name>')
    print('')
    print('Usage: deesko.py -d <IP address, or CIDR range, or local interface name>')
    print('\t'+'-P <string of comma-separated ports, or range>')
    print('\t'+'-o <full path to output file for the downloaded scan report in .json format, default False (no report)>')
    print('\t'+'-t <timeout (optional, default 1s)>')
    print('\t'+'-s <ping sweep types, default "icmp">')
    print('\t'+'-c <ping count, default 1>')
    print('\t'+'-p <TCP port used for TCP ping sweep, default 443>')
    print('\t'+'-l <to perform OUI lookup, default False>')
    print('\t'+'-v <to be verbose and show "Closed" and "Filtered" ports, default False>')
    print('')
    print('Local interface options to scan a local/directly-connected network:')
    print('\t'+'+---------------------------------------+-----------------------+')
    print('\t| '+'Local interface name'+'\t\t\t| '+'CIDR Range'+'\t\t|')
    print('\t'+'+---------------------------------------+-----------------------+')
    for local_interface in host.networks:
        print('\t| '+str(local_interface)+'\t\t\t\t\t| '+str(host.networks[local_interface])+'   \t|')
    print('\t'+'+---------------------------------------+-----------------------+')
    sys.exit()

# Set some defaults for the optional arguments
target_tcp_ports_to_scan = '21,22,23,53,80,443,3306,8080'
target_timeout_seconds = 1
target_ping_sweep_types = 'icmp'
target_ping_count = 1
target_tcp_udp_port = 443
output_file_name = None #os.path.join(os.getcwd(),'deesko_scan_from_'+str(os.uname()[1])+'_'+core.create_timestamp_str()+'.json')
target_oui_lookup = False
be_verbose = False

for opt, arg in opts:
    if opt in ('-d', '--discover'):
        target_to_discover = str(arg)
    elif opt in ('-P', '--Ports'):
        target_tcp_ports_to_scan = str(arg)
    elif opt in ('-o', '--output'):
        output_file_name = str(arg)
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
    elif opt in ('-v', '--verbose'):
        be_verbose = True
    else:
        print('ERROR!')
        print('Usage: deesko.py -d <IP address, or CIDR range, or local interface name>')
        print('\t'+'-P <string of comma-separated ports, or range>')
        print('\t'+'-o <full path to output file for the downloaded scan report in .json format, default False (no report)>')
        print('\t'+'-t <timeout (optional, default 1s)>')
        print('\t'+'-s <ping sweep types, default "icmp">')
        print('\t'+'-c <ping count, default 1>')
        print('\t'+'-p <TCP port used for TCP ping sweep, default 443>')
        print('\t'+'-l <to perform OUI lookup, default False>')
        print('\t'+'-v <to be verbose and show "Closed" and "Filtered" ports, default False>')
        sys.exit()

#print('target_to_discover',target_to_discover)
#print('target_timeout_seconds',target_timeout_seconds)
#print('target_ping_sweep_types',target_ping_sweep_types)
#print('target_ping_count',target_ping_count)
#print('target_tcp_udp_port',target_tcp_udp_port)
#print('target_oui_lookup',target_oui_lookup)
#print('output_file_name',output_file_name)

host.discover(
        option = target_to_discover,
        tcp_ports_to_scan = target_tcp_ports_to_scan,
        timeout_seconds = target_timeout_seconds,
        ping_sweeps = target_ping_sweep_types, 
        ping_count = target_ping_count, 
        tcp_udp_port = target_tcp_udp_port,
        oui_lookup = target_oui_lookup,
        output = output_file_name,
        verbose = be_verbose
    )