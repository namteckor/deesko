import os, platform, ipaddress, json, datetime, requests
import scapy.all as scapy
from colorama import Fore, Back, Style
#import csv, subprocess, shutil

disko_root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
path_to_oui_csv = os.path.join(os.path.join(disko_root_dir,'other'),'oui.csv')

# Convert a dictionary to a json file
def dico_to_json(dico, filename, rel_path = os.getcwd()):
    with open(os.path.join(rel_path,filename+'.json'), 'w') as outfile:
        json.dump(dico, outfile, indent=4)

# Function to create a timestamp string at a given moment, can be used to timestamp log files by including in filename and keeping multiple version over time
def create_timestamp_str(str_ts_format = '%Y-%m-%d_%H%M%S'):
    now_dt = datetime.datetime.now()
    now_str = datetime.datetime.strftime(now_dt, str_ts_format)
    return now_str

def load_oui_csv():
    print('')
    if os.path.isfile(path_to_oui_csv):        
        print('')
        print('\t'+'[INFO] Found oui.csv in '+os.path.dirname(path_to_oui_csv)+', no need to download.')
    else:
        print('')
        print('\t'+'[INFO] oui.csv not found in '+os.path.dirname(path_to_oui_csv)+', starting download...')
        print('')
        oui_csv = requests.get('http://standards-oui.ieee.org/oui/oui.csv')        
        oui_csv_file = open(path_to_oui_csv, 'w', encoding='utf-8', newline = '\n')
        oui_csv_file.write(oui_csv.text)
        oui_csv_file.close()
        if os.path.isfile(path_to_oui_csv):
            print('\t'+'[INFO] ... oui.csv download successful!')
        else:
            print('\t'+'[INFO] !!! oui.csv download failed !!!')
    file_to_parse = open(path_to_oui_csv, 'r', encoding='utf-8')
    parsed_ouis = {}
    for i, line in enumerate(file_to_parse):
        # Skip the header (column names)
        if i == 0:
            continue
        line_split = line.rstrip().split(',')
        no_dash_oui = line_split[1]
        parsed_ouis[no_dash_oui[0:2]+'-'+no_dash_oui[2:4]+'-'+no_dash_oui[4:6]] = line_split[2].replace('"','')
    return parsed_ouis

def lookup_mac_address_oui_details(mac_address, oui_lookup_dictionary):    
    if (mac_address is None) or (mac_address in ['na', 'n/a', 'NA', 'N/A']):
        return None
    else:
        mac_address_oui = mac_address.replace(':','-').upper()[0:8]
        if mac_address_oui in oui_lookup_dictionary:
            return oui_lookup_dictionary[mac_address_oui]
        else:
            return 'oui details not found or unavailable, unknown vendor'

def arp_cache_lookup(ip_addr_str, system_option=platform.system()):
    mac_address_match = False
    if system_option == 'Windows':
        arp_command = 'arp -a'
        line_command_match_option = ip_addr_str+' '
        mac_location = 1
    elif system_option == 'Linux':
        arp_command = 'arp -a'
        line_command_match_option = '('+ip_addr_str+')'
        mac_location = 3
    else:
        return None
    arp_cache_resp = os.popen(arp_command).read()
    # create a list object containing the line content of arp_cache_resp, then loop over each line
    line_split = arp_cache_resp.splitlines(False)
    for line in line_split:
        if line_command_match_option in line:
            ip_mac_line = line.split()
            mac_address = ip_mac_line[mac_location].replace('-',':').upper()
            mac_address_match = True
            break    
    if mac_address_match:
        return mac_address
    else:
        return 'ARP Cache Lookup failed!'

def system_ping(ip_addr_str, ping_count=4, timeout_seconds=1, system_option=platform.system(), extras=None, quiet=True):
    if system_option == 'Windows':
        ping_command = 'ping -n '+str(ping_count)+' '+ip_addr_str+' -w '+str(timeout_seconds*1000)
    elif system_option == 'Linux':
        ping_command = 'ping -c '+str(ping_count)+' '+ip_addr_str+' -W '+str(timeout_seconds)
    else:
        return None
    
    if extras is not None:
        ping_command = ping_command + ' ' + extras
    
    if not quiet:
        print('\t\t'+'Performing os.system() command: '+ping_command)
    return os.system(ping_command)

def evaluate_network_range(cidr_network_or_range_str):
    ips_in_range = []
    if '-' in cidr_network_or_range_str:
        ip_builder = []        
        ip_components = cidr_network_or_range_str.split('.')
        for ip_component in ip_components:
            if '-' in ip_component:
                ip_builder.append([int(ip_component.split('-')[0]),int(ip_component.split('-')[-1])+1])
            else:
                ip_builder.append([int(ip_component), int(ip_component)+1])
        for i1 in range(ip_builder[0][0],ip_builder[0][-1]):
            for i2 in range(ip_builder[1][0],ip_builder[1][-1]):
                for i3 in range(ip_builder[2][0],ip_builder[2][-1]):
                    for i4 in range(ip_builder[3][0],ip_builder[3][-1]):
                        ips_in_range.append(str(i1)+'.'+str(i2)+'.'+str(i3)+'.'+str(i4))
        return ips_in_range
    elif '/' not in cidr_network_or_range_str:
        ips_in_range.append(cidr_network_or_range_str)
        return ips_in_range
    else:
        # noticed some weird behavior when using /32 mask with ipaddress.ip_network, does not behave like explained in the documentation, working around...
        if '/32' in cidr_network_or_range_str:
            single_ip = cidr_network_or_range_str.split('/32')[0]
            ips_in_range.append(single_ip)
            return ips_in_range
        else:
            return list(ipaddress.ip_network(
                    cidr_network_or_range_str,
                    strict=False #so that the IP address can have host bits set, otherwise it complains and expect a pure IP network address
                ).hosts())

def system_ping_sweep(cidr_network_str, ping_count=1, timeout_seconds=1, system_option=platform.system(), skip_address_list=None):
    ping_sweep_results = {'online': [],'offline':[]}
    if skip_address_list is not None:
        addresses_to_skip = skip_address_list.split(',')
    else:
        addresses_to_skip = []
    
    if system_option == 'Windows':
        extra_cmd = '> NUL'
    elif system_option == 'Linux':
        extra_cmd = '> /dev/null'
    else:
        extra_cmd = None
    
    print('\t'+'Running ping sweep .system_ping_sweep() for target IP range '+str(cidr_network_str))
    
    #network_to_scan = ipaddress.ip_network(
    #                cidr_network_str,
    #                strict=False #so that the IP address can have host bits set, otherwise it complains and expect a pure IP network address
    #            )
    
    list_of_ip_addresses = evaluate_network_range(cidr_network_str)
    #print('\t'+'Ping sweep list of IPs',list_of_ip_addresses)
    # Careful here, potential_ip_host from .hosts() is an IPv4Address object, must first convert to string when passing to get_mac() function    
    for potential_ip_host in list_of_ip_addresses: #network_to_scan.hosts():	        
        
        skip_ip_host = False
        for skip_ip in addresses_to_skip:
            if str(potential_ip_host) == skip_ip:
                skip_ip_host = True
                skip_reason = 'IP address '+str(potential_ip_host)+' in list of excluded addresses: '+', '.join(addresses_to_skip)
        #if not (str(network_to_scan.network_address) == str(network_to_scan.broadcast_address)):
        #    if str(potential_ip_host) == str(network_to_scan.network_address):
        #        skip_ip_host = True
        #        skip_reason = 'IP address '+str(potential_ip_host)+' is the network address'
        #    if str(potential_ip_host) == str(network_to_scan.broadcast_address):
        #        skip_ip_host = True
        #        skip_reason = 'IP address '+str(potential_ip_host)+' is the broadcast address'
        # If potential_ip_host is the network address, broadcast address, or current host, then skip and continue to next
  
        if skip_ip_host:
            print(Fore.BLUE+'\t\t'+'Skipping host with IP address',str(potential_ip_host))
            print('\t\t'+'Reason -> '+skip_reason+Style.RESET_ALL)
            continue

        print('\t\t'+'Trying host:',str(potential_ip_host))
        
        response = system_ping(
                ip_addr_str = str(potential_ip_host), 
                ping_count = ping_count,
                timeout_seconds = timeout_seconds,
                system_option = system_option,
                extras = extra_cmd,
                quiet = False
            )
    
        if response == 0:
            print(Fore.GREEN+'\t\t\t'+str(potential_ip_host)+' online!'+Style.RESET_ALL)
            ping_sweep_results['online'].append(str(potential_ip_host))
        else:
            print('\t\t\t'+str(potential_ip_host)+' no response...')
            ping_sweep_results['offline'].append(str(potential_ip_host))

    print('\t'+'Ping sweep complete')
    return ping_sweep_results
    
def scapy_ping(ip_addr_str, timeout_seconds=1):
    ping_request = scapy.IP(dst=ip_addr_str)/scapy.ICMP()
    #ping_response = scapy.sr1(ping_request, timeout=timeout_seconds)
    #print(ping_response)
    #return ping_response
    print('')
    ans, unans = scapy.sr(ping_request, timeout=timeout_seconds, verbose=0)   
    print('\t'+'----- answers -----')
    ans.summary(lambda s,r: r.sprintf(Fore.GREEN+'\t'+'%IP.src% is online'+Style.RESET_ALL))    
    print('\t'+'------------------')    
    #print('\t'+'----- no answer -----')
    #unans.nsummary()
    return (ans, unans)

def scapy_get_mac(ip_addr_str,timeout_seconds=1): 
    """
    arp_request = scapy.ARP(pdst = ip_addr_str) 
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff") 
    arp_request_broadcast = broadcast / arp_request 
    # the "p" at the end of the function name .srp() means that we're sending at L2 instead of L3
    answered_list = scapy.srp(arp_request_broadcast, timeout = timeout_seconds, verbose = False)[0] 
    if not answered_list:
        return None
    else:
        return answered_list[0][1].hwsrc.upper()
    """
    # scapy already has a built-in function ".getmacbyip()" for that...
    return scapy.getmacbyip(ip_addr_str)

def scapy_arping(cidr_str):
    ans, unans = scapy.arping(cidr_str, verbose=0)
    print('\t\t'+'----- answers -----')
    #ans.nsummary()
    ans.summary( lambda s,r : r.sprintf(Fore.GREEN+'\t\t'+'%ARP.psrc% is at %Ether.src%'+Style.RESET_ALL) ) # %Ether.src% %ARP.psrc%
    print('\t\t'+'------------------')
    #print('\t'+'----- no answer -----')
    #unans.nsummary()
    return (ans, unans)
    
def scapy_tcp_ping(ip_addr_str_or_cidr,tcp_port=443,timeout_seconds=1):    
    ans, unans = scapy.sr( scapy.IP(dst=ip_addr_str_or_cidr)/scapy.TCP(dport=tcp_port,flags="S"), timeout=timeout_seconds, verbose=0 )
    print('\t\t'+'----- answers -----')
    ans.summary( lambda s,r : r.sprintf(Fore.GREEN+'\t\t'+'%IP.src% is online (scanned on TCP port '+str(tcp_port)+' ['+'%TCP.sport%'+'])'+Style.RESET_ALL) )
    print('\t\t'+'------------------')
    return (ans, unans)
    
def scapy_udp_ping(ip_addr_str_or_cidr,udp_port=0,timeout_seconds=1):
    print('')
    ans, unans = scapy.sr( scapy.IP(dst=ip_addr_str_or_cidr)/scapy.UDP(dport=udp_port), timeout=timeout_seconds, verbose=0 )
    print('\t'+'----- answers -----')
    ans.summary( lambda s,r : r.sprintf(Fore.GREEN+'\t'+'%IP.src% is online (scanned on UDP port '+str(udp_port)+Style.RESET_ALL) )
    print('\t'+'------------------')
    return (ans, unans)

def scan_tcp_port_stealthily(dst_ip_addr_str, dst_port, timeout_seconds=2):
    
    """
    F = FIN = 0x01
    S = SYN = 0x02
    R = RST = 0x04
    P = PSH = 0x08
    A = ACK = 0x10
    U = URG = 0x20
    E = ECE = 0x40
    C = CWR = 0x80
    """
    
    # Set the source and destination ports, with proper variable type (integer)
    src_port = scapy.RandShort()
    dst_port_int = int(dst_port)
    
    # Prepare the stealth scan with a TCP SYN (flag='S') request
    stealth_scan_request = scapy.IP(dst=dst_ip_addr_str)/scapy.TCP(sport=src_port,dport=dst_port_int,flags='S')
    # Send the stealth scan request and assign response to variable
    stealth_scan_response = scapy.sr1(stealth_scan_request,timeout=timeout_seconds,verbose=0)

    # First case, the response is None so 'No response'
    if stealth_scan_response is None: #if(str(type(stealth_scan_response))=="<class ‘NoneType’>"):
        scan_result = 'No response'
    # If we did get a response, then we evaluate...
    elif(stealth_scan_response.haslayer(scapy.TCP)):
        # TCP response and we received a SYN/ACK, meaning the port is open, listening and actively accepting connections
        # In this case we follow by sending a "nevermind" RST
        if(stealth_scan_response.getlayer(scapy.TCP).flags == 0x12): # (0x12)hex = (18)dec => SYN/ACK
            send_rst = scapy.sr(scapy.IP(dst=dst_ip_addr_str)/scapy.TCP(sport=src_port,dport=dst_port_int,flags='R'),timeout=timeout_seconds,verbose=0)
            scan_result = 'Open'
        # TCP response and we received a RST/ACK
        elif (stealth_scan_response.getlayer(scapy.TCP).flags == 0x14): # (0x14)hex = (20)dec => RST/ACK            
            scan_result = 'Closed'
        else:
            scan_result = 'Filtered'
    elif(stealth_scan_response.haslayer(scapy.ICMP)):
        if(int(stealth_scan_response.getlayer(scapy.ICMP).type)==3 and int(stealth_scan_response.getlayer(scapy.ICMP).code) in [1,2,3,9,10,13]):
            scan_result = 'Filtered'
    else:
        scan_result = 'Unknown'
    
    return scan_result

### the "system" class abstracts the host/machine on which the Python code is running
### instantiate first, for example host = core.system()
### then use built-in class functions:
###     host.show(<'sys','int','ip','net','route','arp','discovered'>)
###     host.discover(<local_interface_name,network_cidr>,<timeout_seconds=1>)
###     host.arp_cache_lookup(<ip_addr_str>)
###     host.ping(<ip_addr_str>, <timeout_seconds=1>, <ping_count=4>, <ping_type='system'>)

class system:
    def __init__(self):
        self.hostname = str(platform.node())
        self.platform = str(platform.platform())
        self.system = str(platform.system())
        self.release = str(platform.release())
        self.version = str(platform.version())     
        self.processor = str(platform.processor())
        self.architecture = str(platform.architecture())
        self.machine_type = str(platform.machine())
        self.ip_config()
        self.parse_ip_config()          
        self.discovered = {}
        # Parse and load an OUI lookup dictionary content in memory for re-use and multiple lookup
        self.oui_lookup_dictionary = load_oui_csv() #load_oui_txt()
            
    def ip_config(self):
        if self.system == 'Windows':
            ip_config_cmd = 'ipconfig /all'
        else:
            ip_config_cmd = 'sudo ifconfig' #'ip addr' #"ifconfig"
        self.system_ip_config = os.popen(ip_config_cmd).read()
        
    def parse_ip_config(self):
        parsed_interfaces = {}
        if self.system == 'Windows':            
            for line in self.system_ip_config.splitlines():
                line_rstrip = line.rstrip()        
                #if line_rstrip (line stripped from special characters using rstrip()) is empty then continue and proceed to next line
                if not line_rstrip:
                    continue
                elif 'adapter' in line_rstrip:                
                    adapter = line_rstrip.replace(':','')
                    parsed_interfaces[adapter] = {}
                else:
                    if 'Physical Address. . . . . . . . . : ' in line_rstrip:
                        parsed_interfaces[adapter]['mac_address'] = line_rstrip.split('Physical Address. . . . . . . . . : ')[-1]
                        parsed_interfaces[adapter]['mac_address_oui'] = line_rstrip.split('Physical Address. . . . . . . . . : ')[-1][0:8]            
                    if 'IPv4 Address. . . . . . . . . . . : ' in line_rstrip:
                        parsed_interfaces[adapter]['ipv4_address'] = line_rstrip.split('IPv4 Address. . . . . . . . . . . : ')[-1].replace('(Preferred)','')
                    if 'Subnet Mask . . . . . . . . . . . : ' in line_rstrip:
                        parsed_interfaces[adapter]['ipv4_subnet_mask'] = line_rstrip.split('Subnet Mask . . . . . . . . . . . : ')[-1]
                    if 'Default Gateway . . . . . . . . . : ' in line_rstrip:
                        parsed_interfaces[adapter]['ipv4_default_gateway'] = line_rstrip.split('Default Gateway . . . . . . . . . : ')[-1]
        elif self.system == 'Linux':
            for line in self.system_ip_config.splitlines():
                line_rstrip = line.rstrip()
                line_rstrip_lstrip = line_rstrip.lstrip()
                #if line_rstrip_lstrip (line stripped from special characters using rstrip()) is empty then continue and proceed to next line
                if not line_rstrip_lstrip:
                    continue
                elif ('flags' in line_rstrip_lstrip) and ('mtu' in line_rstrip_lstrip):
                    adapter = line_rstrip_lstrip.split(' ')[0].replace(':','')
                    parsed_interfaces[adapter] = {}
                else:
                    if 'ether' in line_rstrip_lstrip:
                        parsed_interfaces[adapter]['mac_address'] = line_rstrip_lstrip.split(' ')[1]
                        parsed_interfaces[adapter]['mac_address_oui'] = line_rstrip_lstrip.split(' ')[1][0:8]
                    if ('inet' in line_rstrip_lstrip) and ('netmask' in line_rstrip_lstrip) and ('inet6' not in line_rstrip_lstrip):
                        parsed_interfaces[adapter]['ipv4_address'] = line_rstrip_lstrip.split(' ')[1]
                    if 'netmask' in line_rstrip_lstrip:
                        parsed_interfaces[adapter]['ipv4_subnet_mask'] = line_rstrip_lstrip.split(' ')[4]
        connected_networks = {}
        host_ips = []
        for interface in parsed_interfaces:
            if 'ipv4_address' in parsed_interfaces[interface]:
                connected_network = ipaddress.ip_network(
                        (parsed_interfaces[interface]['ipv4_address'],parsed_interfaces[interface]['ipv4_subnet_mask']),
                        strict=False #so that the IP address can have host bits set, otherwise it complains and expect a pure IP network address
                )
                connected_networks[interface] = connected_network
                host_ips.append(parsed_interfaces[interface]['ipv4_address'])
        self.interfaces = parsed_interfaces
        self.networks = connected_networks
        self.ips = host_ips
    
    def show(self, show_option):
        if show_option in ['details','sys','system','SYS','SYSTEM','platform','PLATFORM']:
            self.system_details_show()
        elif show_option in ['int','interface','interfaces','INT','INTERFACE','INTERFACES']:
            self.interfaces_show()
        elif show_option in ['ip','IP','ip int']:
            self.ip_interfaces_show()
        elif show_option in ['route','ROUTE','ip route','ip r','IP ROUTE','IP R']:
            self.ip_route_show()
        elif show_option in ['arp','ARP','arp cache','ARP cache','arp -a']:
            self.arp_cache_show()
        elif show_option in ['net','NET','network','NETWORK','networks','NETWORKS','connected','CONNECTED']:
            self.connected_networks_show()
        elif show_option in ['discovered']:
            self.discovered_networks_show()
        else:
            print('')
            print(Fore.YELLOW+'\t'+'Option "'+show_option+'" not supported!')
            print("""
                Available show() options are:
                'sys'           .show('sys')        to view the host system details
                'int'           .show('int')        to view the host interfaces
                'ip'            .show('ip')         to view the host interfaces with IPv4 addresses
                'net'           .show('net')        to view the connected networks
                'route'         .show('route')      to view the current content of the host IP routing table
                'arp'           .show('arp')        to view the current content for the host ARP cache 
                'discovered'    .show('discovered') to view already discovered networks
            """)
            print(Style.RESET_ALL)
    
    def system_details_show(self):
        print('')
        print('\t'+'System details:')
        print('\t\t'+'hostname'+'\t'+'='+'\t'+self.hostname)
        print('\t\t'+'platform'+'\t'+'='+'\t'+self.platform)
        print('\t\t'+'system'+'\t\t'+'='+'\t'+self.system)
        print('\t\t'+'release'+'\t\t'+'='+'\t'+self.release)
        print('\t\t'+'version'+'\t\t'+'='+'\t'+self.version)
        print('\t\t'+'processor'+'\t'+'='+'\t'+self.processor)
        print('\t\t'+'architecture'+'\t'+'='+'\t'+self.architecture)
        print('\t\t'+'machine type'+'\t'+'='+'\t'+self.machine_type)
        print('')
    
    def interfaces_show(self):
        print('')
        print('\t'+'System interfaces:')
        print('\t\t'+'\n\t\t'.join(map(str, list(self.interfaces.keys()))))
        print('')
        
    def ip_interfaces_show(self):
        print('')
        print('\t'+'Interfaces with IPv4 addresses:')
        for interface in self.interfaces:       
            if 'ipv4_address' in self.interfaces[interface]:
                print('\t\t'+interface)
                print('\t\t\t'+'IPv4 Address'+'\t'+self.interfaces[interface]['ipv4_address'])
                print('\t\t\t'+'Subnet Mask'+'\t'+self.interfaces[interface]['ipv4_subnet_mask'])
            else:
                continue
        print('')
    
    def connected_networks_show(self):
        print('')
        print('\t'+'Connected local networks:')
        for interface in self.networks:
            print('\t\t'+self.networks[interface]+' connected via interface '+interface)
        print('')
    
    def ip_route_show(self):
        if self.system == 'Windows':
            ip_route_command = 'route print'
        elif self.system == 'Linux':
            ip_route_command = 'ip r'
        else:
            print(Fore.YELLOW+'\t'+'Unsupported system "'+self.system+'"!'+Style.RESET_ALL)
            return None
        ip_route_resp = os.popen(ip_route_command).read()
        print('')
        print('\t'+'Current IP route table:')
        for line in ip_route_resp.splitlines():            
            print('\t\t'+line)
        print('')
    
    def arp_cache_show(self):
        if self.system == 'Windows':
            arp_command = 'arp -a'
            mac_location = 1
        elif self.system == 'Linux':
            arp_command = 'arp -a'
            mac_location = 3
        else:
            print(Fore.YELLOW+'\t'+'Unsupported system "'+self.system+'"!'+Style.RESET_ALL)
            return None
        arp_cache_resp = os.popen(arp_command).read()
        print('')
        print('\t'+'Current ARP cache:')
        for line in arp_cache_resp.splitlines():            
            print('\t\t'+line)
        print('')
    
    def arp_cache_lookup(self, ip_addr_str):
        rv = arp_cache_lookup(ip_addr_str)
        print(rv)
    
    def discovered_networks_show(self):
        print(json.dumps(self.discovered, indent = 4))
    
    def ping(self, ip_addr, timeout_seconds=1, ping_count=4, ping_type='system'):
        ip_addr_str = str(ip_addr)
        if ping_type == 'system':
            system_ping(
                    ip_addr_str, 
                    ping_count=ping_count, 
                    timeout_seconds=timeout_seconds, 
                    system_option=self.system
                )
        elif ping_type == 'scapy':
            scapy_ping(
                    ip_addr_str,
                    timeout_seconds=timeout_seconds
                )
        else:
            print('')
            print(Fore.YELLOW+'\t'+'ping_type "'+ping_type+'" not supported!')
            print("""
                Supported ping_types are:
                'system'    ping_type='system'
                'scapy'     ping_type='scapy'
            """)
            print(Style.RESET_ALL)
            return None
    
    def export(self,export_option):
        if export_option in ['discovered','discovery','scan','scans']:
            filename = 'discovery_scan_from_'+self.hostname+'_'+create_timestamp_str()
            dico_to_json(self.discovered, filename)
    
    def discover(self, option, timeout_seconds=1, ping_sweeps='icmp', ping_count=1, tcp_udp_port=443, oui_lookup=False):
        
        # option shall be either an existing host interface name with IPv4 address or a network in CIDR notation, entered as string, ex: 'eth0'
       
        ping_sweeps_list = ping_sweeps.split(',')
        # at a minimum, always do an ICMPv4 "icmp" ping sweep, so add it by default if not present
        if ('icmp' not in ping_sweeps_list) or ('ping' not in ping_sweeps_list) or ('ICMPv4' not in ping_sweeps_list) or ('ICMP' not in ping_sweeps_list):
            ping_sweeps_list.append('icmp')
        
        is_connected_network = False
        is_range = False
        
        if option in self.interfaces:
            if 'ipv4_address' in self.interfaces[option]:
                network_to_scan = ipaddress.ip_network(
                        (self.interfaces[option]['ipv4_address'],self.interfaces[option]['ipv4_subnet_mask']),
                        strict=False #so that the IP address can have host bits set, otherwise it complains and expect a pure IP network address
                )
                is_connected_network = True
            else:
                print('')
                print(Fore.YELLOW+'\t'+'Error: interface "'+option+'" does not have an IPv4 address assigned')
                print('\t'+'Please provide a network in CIDR notation (ex: 10.0.0.0/24) or a local interface name with an IPv4 address assigned, see list below:')
                self.ip_interfaces_show()
                print(Style.RESET_ALL)
                return None
        else:      
            try:
                if '-' in option:
                    network_to_scan = option
                    is_range = True                   
                else:
                    network_to_scan = ipaddress.ip_network(option,strict=False)
                if network_to_scan in list(self.networks.values()):
                    print('\t'+str(network_to_scan)+' is a local/connected network')
                    is_connected_network = True
                elif not is_range:
                    for connected_net in list(self.networks.values()):
                        if network_to_scan.subnet_of(connected_net):
                            print('')
                            print('\t'+'[INFO] '+str(network_to_scan)+' is a subset/part of connected network: '+str(connected_net))
                            print('')
                            is_connected_network = True
            except:
                print('')
                print(Fore.YELLOW+'\t'+'Error - invalid argument "option": '+option)
                print('\t'+'"option" shall be either an existing host interface name with IPv4 address or a network in CIDR notation'+Style.RESET_ALL)
                print('')
                return None
        
        print('\t'+'***** '+'Starting discovery for '+str(network_to_scan)+' *****')
        print('')
        
        if str(network_to_scan) not in self.discovered:
            self.discovered[str(network_to_scan)] = {}
        
        # if we are dealing with a directly connected network or interface, start with an arping scan
        if is_connected_network:
            print('\t'+'Running scapy_arping()')
            arping_results = scapy_arping(str(network_to_scan))
            # let's loop over the responses/answers we received to analyze which hosts are online
            for item in arping_results[0]: # arping_results[0] is for the answers, [1] would be for the unanswers
                # item[1] is for the repsonse we received; [0] would be for the request we sent
                self.discovered[str(network_to_scan)][item[1].sprintf('%ARP.psrc%')] = {
                    'ipv4_address': item[1].sprintf('%ARP.psrc%'),
                    'mac_address':item[1].sprintf('%Ether.src%'),
                    'oui_vendor': None,
                    'arping': 'responded to scapy_arping()'
                }
            print('\t'+'scapy_arping() complete')
            print('')

        # test ICMP ping
        # start with an ICMP ping sweep            
        if ('icmp' in ping_sweeps_list) or ('ping' in ping_sweeps_list) or ('ICMPv4' in ping_sweeps_list) or ('ICMP' in ping_sweeps_list):
            ping_sweep_results = system_ping_sweep(
                cidr_network_str = str(network_to_scan), 
                ping_count=ping_count, 
                timeout_seconds=timeout_seconds, 
                system_option=self.system, 
                skip_address_list= ','.join(self.ips)
            )
               
            for online_ip in ping_sweep_results['online']:
                if online_ip in self.discovered[str(network_to_scan)]:
                    self.discovered[str(network_to_scan)][online_ip]['icmpv4_ping'] = 'responded to ICMPv4 ping'
                else:
                    self.discovered[str(network_to_scan)][online_ip] = {
                        'ipv4_address': online_ip,
                        'mac_address': None,
                        'oui_vendor': None,
                        'arping': None,                        
                        'icmpv4_ping': 'responded to ICMPv4 ping'
                    }
        print('')          
        if ('tcp' in ping_sweeps_list) or ('TCP' in ping_sweeps_list):
            print('\t'+'Running TCP ping sweep for target IP range '+str(network_to_scan))
            list_of_ip_addresses = evaluate_network_range(str(network_to_scan))
            for potential_ip_host in list_of_ip_addresses: #network_to_scan.hosts():
                # let's first evaluate if the IP address belong to our current scanning host, or is the network/broadcast address
                # technically, .hosts() should not return the network and broadcast IP addresses for most cases, but it does not hurt to double check...
                
                skip_ip_host = False
                for skip_ip in self.ips:
                    if str(potential_ip_host) == str(skip_ip):
                        skip_ip_host = True
                        skip_reason = 'IP address '+str(potential_ip_host)+' belongs to current scanning host: '+', '.join(self.ips)
                #if not (str(network_to_scan.network_address) == str(network_to_scan.broadcast_address)):
                #    if str(potential_ip_host) == str(network_to_scan.network_address):
                #        skip_ip_host = True
                #        skip_reason = 'IP address '+str(potential_ip_host)+' is the network address'
                #    if str(potential_ip_host) == str(network_to_scan.broadcast_address):
                #        skip_ip_host = True
                #        skip_reason = 'IP address '+str(potential_ip_host)+' is the broadcast address'
                # If potential_ip_host is the network address, broadcast address, or current host, then skip and continue to next
  
                if skip_ip_host:
                    print(Fore.BLUE+'\t\t'+'Skipping host with IP address',str(potential_ip_host))
                    print('\t\t'+'Reason: '+skip_reason+Style.RESET_ALL)
                    continue
                
                print('\t\t'+'Running TCP Ping scan on host '+str(potential_ip_host)+' port '+str(tcp_udp_port))
                tcp_ping_results = scapy_tcp_ping(
                        ip_addr_str_or_cidr=str(potential_ip_host),
                        tcp_port=tcp_udp_port,
                        timeout_seconds=timeout_seconds
                    )
                for item in tcp_ping_results[0]:   
                    item_ip = str(item[1].sprintf('%IP.src%'))
                    if item_ip in self.discovered[str(network_to_scan)]:
                        self.discovered[str(network_to_scan)][item_ip]['tcp_ping'] = 'responded to TCP ping on port '+str(tcp_udp_port)
                    else:
                        self.discovered[str(network_to_scan)][item_ip] = {
                            'ipv4_address': item_ip,
                            'mac_address': None,
                            'oui_vendor': None,
                            'arping': None,
                            'icmpv4_ping': None,
                            'tcp_ping': 'responded to TCP ping on port '+str(tcp_udp_port)
                        }
                for item in tcp_ping_results[1]:
                    item_ip = str(item[0].sprintf('%IP.dst%'))
                    if item_ip in self.discovered[str(network_to_scan)]:
                        self.discovered[str(network_to_scan)][item_ip]['tcp_ping'] = 'did NOT respond to TCP ping on port '+str(tcp_udp_port)
                        
            print('\t'+'TCP ping sweep complete')
            print('')
        
        if ('udp' in ping_sweeps_list) or ('UDP' in ping_sweeps_list):
            print(Fore.YELLOW+'\t'+'UDP ping sweep not implemented yet!'+Style.RESET_ALL)
            print('')
        
        # if we are scanning a range, and some discovered IP addresses belong to directly connected networks, then issue ARP requests to get the MAC address
        if is_range:
            for discovered_ip in self.discovered[str(network_to_scan)]:
                for connected_net in list(self.networks.values()):
                    if ipaddress.ip_address(discovered_ip) in connected_net.hosts():
                        print('\t'+'[INFO] '+'discovered IP address '+str(discovered_ip)+' is local, trying to get MAC address...')
                        print('')
                        if scapy_get_mac(str(discovered_ip)) is None:
                            self.discovered[str(network_to_scan)][discovered_ip]['mac_address'] = arp_cache_lookup(str(discovered_ip))
                        else:
                            self.discovered[str(network_to_scan)][discovered_ip]['mac_address'] = scapy_get_mac(str(discovered_ip))
        
        print('\t'+'Running stealthy TCP scan on discovered hosts')
        for count, discovered_ip in enumerate(self.discovered[str(network_to_scan)]):            
            if count > 0:
                print('\t\t'+'***********************************************')
            for default_port in [21, 22, 23, 53, 80, 443, 3306, 8080]:                
                tcp_scan_result = scan_tcp_port_stealthily(str(discovered_ip), default_port, timeout_seconds=timeout_seconds)
                self.discovered[str(network_to_scan)][str(discovered_ip)]['tcp_port_scan_'+str(default_port)] = tcp_scan_result
                if tcp_scan_result == 'Open':
                    print(Fore.GREEN+'\t\t'+str(discovered_ip)+':'+str(default_port)+' -> '+tcp_scan_result+Style.RESET_ALL)
                else:
                    print(Fore.YELLOW+'\t\t'+str(discovered_ip)+':'+str(default_port)+' -> '+tcp_scan_result+Style.RESET_ALL)
        print('\t'+'Stealthy TCP scan on discovered hosts complete')
        print('')
        
        for discovered_ip in self.discovered[str(network_to_scan)]:
            self.discovered[str(network_to_scan)][discovered_ip]['oui_vendor'] = lookup_mac_address_oui_details(
                    self.discovered[str(network_to_scan)][discovered_ip]['mac_address'],
                    self.oui_lookup_dictionary
                )
    
        
