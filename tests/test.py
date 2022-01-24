#!/usr/bin/python3

import sys, os

try:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scripts import core
    host = core.system()
    host.discover(
        option = '192.168.0.100', #'10.1.1.1', #'10.1.1.0/24', #'eth1',
        tcp_ports_to_scan = '21-23',
        timeout_seconds=1, 
        ping_sweeps='icmp', 
        ping_count=1, 
        tcp_udp_port=443,
        oui_lookup=True
    )
    host.export('scans')
    print('Success!')    
except:
    print('Test failed!')
