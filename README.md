![Abaco stripe](abaco/Abaco_background-1000x275.png)
# WinPcap-igmp-join
Example of how to join a IGMPv2 multicast group when using WinPcap.
> Usage example : sendigmp.exe "rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578}" 

Requires WinPCAP develooper resources. Tested against version 4.1.3 (https://www.winpcap.org/devel.htm).

Example Usage :
Join a multicast group:
```
	    D:\WpdPack\Examples-pcap\sendpack\Debug>sendigmp.exe rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} 1 239 255 255 250
	    1. rpcap://\Device\NPF_{4F2C580A-26CC-40A1-A339-578B4B473B85} (Network adapter 'Microsoft' on local host)
	    2. rpcap://\Device\NPF_{6FDD06EA-8BFD-460B-A3AC-9789FE3E1600} (Network adapter 'Microsoft' on local host)
	    3. rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} (Network adapter 'Intel(R) 82579LM Gigabit Network Connection' on local host)
	    4. rpcap://\Device\NPF_{6793231A-CC1D-4CCB-88F1-C57C4BEA9E44} (Network adapter 'Microsoft' on local host)
	    
	    IGMP Joining 239.255.255.250...
```
Leave a multicast group:
```	    
	    D:\WpdPack\Examples-pcap\sendpack\Debug>sendigmp.exe rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} 0 239 255 255 250
	    1. rpcap://\Device\NPF_{4F2C580A-26CC-40A1-A339-578B4B473B85} (Network adapter 'Microsoft' on local host)
	    2. rpcap://\Device\NPF_{6FDD06EA-8BFD-460B-A3AC-9789FE3E1600} (Network adapter 'Microsoft' on local host)
	    3. rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} (Network adapter 'Intel(R) 82579LM Gigabit Network Connection' on local host)
	    4. rpcap://\Device\NPF_{6793231A-CC1D-4CCB-88F1-C57C4BEA9E44} (Network adapter 'Microsoft' on local host)
	    
	    IGMP Leave 239.255.255.250...
```
 Example of how to check the GS12 memberships:
```
	    (Abaco Systems GBX410 Routing) #show mac-address-table igmpsnooping
	    
	          MAC Address         Type      Description             Interfaces
	    -----------------------  -------  ----------------  -------------------------
	    00:02:01:00:5E:7F:FF:19  Dynamic  Network Assist    Fwd: 0/2
	    00:02:01:00:5E:7F:FF:FA  Dynamic  Network Assist    Fwd: 0/2
	    00:02:01:00:5E:7F:FF:FF  Dynamic  Network Assist    Fwd: 0/2
```
After issuing a Leave command i.e. sendigmp.exe rpcap://\Device\NPF_{39EFC0AD-AE9B-40EC-82CF-9306C91F4013} 0 239 255 255 255
```
      (Abaco Systems GBX410 Routing) #show mac-address-table igmpsnooping
	    
	          MAC Address         Type      Description             Interfaces
	    -----------------------  -------  ----------------  -------------------------
	    00:02:01:00:5E:7F:FF:19  Dynamic  Network Assist    Fwd: 0/2
	    00:02:01:00:5E:7F:FF:FA  Dynamic  Network Assist    Fwd: 0/2
```
# Links
* Code conforms to https://www.ietf.org/rfc/rfc2236.txt 
* Wireshark example can be found at https://wiki.wireshark.org/IGMP 
* Abaco Systems rugged [GS12 Switch](https://www.abaco.com/products/gs12/p3520)
* Abaco Systems rugged [GBX410 Switch](https://www.abaco.com/products/neternity-gbx410/p2015)
![Abaco stripe](abaco/Abaco Footer1000x100.png)
