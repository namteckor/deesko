# deesko
"deesko" is a prototype Python script to automate initial network discovery (mostly relying on Scapy).  
**Only use for educational purposes on networks that you own and have explicit authorization to scan!**  

Its goal is **not** to replace nmap or rustscan, just to showcase what can be done with Scapy in terms of "network discovery automation".  

Usage:

&ensp;sudo path/to/deesko.py -d <IP address, or CIDR range, or local interface name>  
  &ensp;&ensp;-P <list of TCP ports to stealthily scan on discovered hosts, default "21-23,53,80,389,443,502,636,990,3306,3389,5432,8080">  
  &ensp;&ensp;-A <to perform active OS fingerprinting on discovered live hosts using "nmap -O" (requires nmap), default False>  
  &ensp;&ensp;-o <output file - full path to output file for the downloaded scan report in .json format, default False (no report)>  
  &ensp;&ensp;-t <timeout in seconds, default 1s>  
  &ensp;&ensp;-s <ping sweep types, "icmp,tcp", default "icmp">  
  &ensp;&ensp;-c <ping count, default 1>  
  &ensp;&ensp;-p <TCP port used for TCP ping sweep, default 443>  
  &ensp;&ensp;-l <to perform OUI MAC address lookup, default False>  
  &ensp;&ensp;-v <to be verbose and show "Closed" and "Filtered" ports, default False>  

Ex1: sudo ./deesko.py -d 192.168.0.0/25  
Ex2: sudo ./deesko.py -d eth1 -P 21-23,53,80,443 -o scan_results.json -t 2 -s "icmp,tcp" -c 4 -p 80 -l -v   

In Ex1, we are telling deesko to scan the 192.168.0.0/25 subnet with the default values for the optional switches.  
In Ex2, we are telling deesko to scan the network attached to our local eth1 interface (assuming eth1 has a valid IP address assigned and network attached), perform a TCP stealth scan on discovered hosts on ports 21, 22, 23, 53, 80, and 443 (-P 21-23,53,80,443), use a timeout of 2 seconds (-t 2), perform both a default ICMP ping sweep AND an additional TCP ping sweep (-s "icmp,tcp") on port 80 (-p 80), send 4 ICMP echo requests during the ICMP ping sweep (-c 4) and attempt to lookup the MAC OUI vendor (-l) since we are scanning a local/directly-connected network. The optional TCP ping sweep is an attempt to discover hosts when/where ICMP may be blocked. The -v switch at the end will make the output verbose so deesko will also display the "Closed" and "Filtered" ports, not just the "Open" ports.  
Increasing the number of ports to scan (-P), the timeout (-t) and/or the ping count (-c) will make things slower.  

You may need to add "python" (ex: on Windows) or "python3" (ex: on Linux) before path/to/deesko.py, or make deesko.py executable to use without the preceding "python3" keyword on Linux.

Below is an example of using the -o output switch ("scan_results.json"), this was run against a Metasploitable 2 VM from Parrot OS (also tested on Kali and Windows 10):  
  &ensp;{  
    &ensp;&ensp;"192.168.0.0/25": {  
        &ensp;&ensp;&ensp;"discovered_hosts_count": 1,  
        &ensp;&ensp;&ensp;"discovered_hosts_summary": {  
        &ensp;&ensp;&ensp;&ensp;"192.168.0.100": {  
        &ensp;&ensp;&ensp;&ensp;&ensp;"nmap": "OS details: Linux 2.6.9 - 2.6.33"  
        &ensp;&ensp;&ensp;&ensp;}    
        &ensp;&ensp;&ensp;},  
        &ensp;&ensp;&ensp;"discovered_hosts_details": {  
        &ensp;&ensp;&ensp;&ensp;"192.168.0.100": {  
            &ensp;&ensp;&ensp;&ensp;&ensp;"ipv4_address": "192.168.0.100",  
            &ensp;&ensp;&ensp;&ensp;&ensp;"os": {  
              &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;"nmap": "OS details: Linux 2.6.9 - 2.6.33  
            &ensp;&ensp;&ensp;&ensp;&ensp;},   
            &ensp;&ensp;&ensp;&ensp;&ensp;"mac_address": "00:00:00:00:00:00",  
            &ensp;&ensp;&ensp;&ensp;&ensp;"oui_vendor": "Vendor Name",  
            &ensp;&ensp;&ensp;&ensp;&ensp;"arping": "responded to scapy_arping()",  
            &ensp;&ensp;&ensp;&ensp;&ensp;"icmpv4_ping": "responded to ICMPv4 ping",  
            &ensp;&ensp;&ensp;&ensp;&ensp;"tcp_ports_open_count": 30,   
            &ensp;&ensp;&ensp;&ensp;&ensp;"tcp_ports_open": [  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;21,              
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;22,  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;23,  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;25,  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;53,  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;80,  
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;111,            
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;139,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;445,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;512,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;513,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;514,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;1099,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;1524,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;2049,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;2121,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;3306,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;3632,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;5432,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;5900,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;6000,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;6667,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;6697,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;8009,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;8180,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;8787,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;32843,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;36401,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;55238,   
            &ensp;&ensp;&ensp;&ensp;&ensp;&ensp;59355   
            &ensp;&ensp;&ensp;&ensp;&ensp;],  
            &ensp;&ensp;&ensp;&ensp;&ensp;"tcp_ports_closed_or_filtered_count": 65506,   
            &ensp;&ensp;&ensp;&ensp;&ensp;"tcp_ports_closed_or_filtered": "0-20,24,26-52,54-79,81-110,112-138,140-444,446-511,515-1098,1100-1523,1525-2048,2050-2120,2122-3305,3307-3631,3633-5431,5433-5899,5901-5999,6001-6666,6668-6696,6698-8008,8010-8179,8181-8786,8788-32842,32844-36400,36402-55237,55239-59354,59356-65535"   
        &ensp;&ensp;&ensp;&ensp;}  
    &ensp;&ensp;&ensp;}  
&ensp;}  
