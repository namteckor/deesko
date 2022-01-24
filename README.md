# deesko
"deesko" is a prototype Python script to automate initial network discovery (mostly relying on Scapy).  
**Only use for educational purposes on networks that you own and have explicit authorization to scan!**  

Its goal is **not** to replace nmap or rustscan, just to showcase what can be done with Scapy in terms of "network discovery automation".  

Usage:

sudo path/to/deesko.py -d <IP address, or CIDR range, or local interface name> -t <timeout in seconds, default 1s> -s <ping sweep types, "icmp,tcp,udp", default "icmp"> -c <ping count, default 1> -p <TCP or UDP port used for TCP ping sweep, default 443> -l <to perform OUI MAC address lookup, default False>  

Ex1: sudo ./deesko.py -d 192.168.0.0/25  
Ex2: sudo ./deesko.py -d eth1 -t 2 -s "icmp,tcp" -c 4 -p 80 -l  

In Ex1, we are telling deesko to scan the 192.168.0.0/25 subnet with the default values for the optional switches.  
In Ex2, we are telling deesko to scan the network attached to our local eth1 interface (assuming eth1 has a valid IP address assigned and network attached), use a timeout of 2 seconds (-t 2), perform both a default ICMP ping sweep AND an additional TCP ping sweep (-s "icmp,tcp") on port 80 (-p 80), send 4 ICMP echo requests during the ICMP ping sweep (-c 4) and attempt to lookup the MAC OUI vendor (-l) since we are scanning a local/directly-connected network. The optional TCP ping sweep is an attempt to discover hosts when/where ICMP may be blocked.  
Increasing the timeout (-t) and/or ping count (-c) will make things slower.  

You may need to add "python" (ex: on Windows) or "python3" (ex: on Linux) before path/to/deesko.py, or make deesko.py executable to use without.  

A .json summary file including the scan results will be created in the folder where you run deesko.py from.  
Ex: *discovery_scan_from_HOSTNAME_YYYY-MM-DD_hhmmss.json*  
Below is an example of its content, this was run against a Metasploitable 2 VM from Parrot OS (also tested on Kali and Windows 10):  
  &ensp;{  
    &ensp;&ensp;"192.168.0.0/25": {  
        &ensp;&ensp;&ensp;"192.168.0.100": {  
            &ensp;&ensp;&ensp;&ensp;"ipv4_address": "192.168.0.100",  
            &ensp;&ensp;&ensp;&ensp;"mac_address": "00:00:00:00:00:00",  
            &ensp;&ensp;&ensp;&ensp;"oui_vendor": "Vendor Name",  
            &ensp;&ensp;&ensp;&ensp;"arping": "responded to scapy_arping()",  
            &ensp;&ensp;&ensp;&ensp;"icmpv4_ping": "responded to ICMPv4 ping",  
            &ensp;&ensp;&ensp;&ensp;"tcp_ports_open": [
            &ensp;&ensp;&ensp;&ensp;&ensp;21,              
            &ensp;&ensp;&ensp;&ensp;&ensp;22,  
            &ensp;&ensp;&ensp;&ensp;&ensp;23,  
            &ensp;&ensp;&ensp;&ensp;&ensp;53,  
            &ensp;&ensp;&ensp;&ensp;&ensp;80,  
            &ensp;&ensp;&ensp;&ensp;&ensp;3306  
            &ensp;&ensp;&ensp;&ensp;],  
            &ensp;&ensp;&ensp;&ensp;"tcp_ports_open_count": 6,   
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_21": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_22": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_23": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_53": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_80": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_443": "Closed",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_3306": "Open",  
            &ensp;&ensp;&ensp;&ensp;"tcp_port_scan_8080": "Closed",
        &ensp;&ensp;&ensp;}  
    &ensp;&ensp;}  
&ensp;}  
