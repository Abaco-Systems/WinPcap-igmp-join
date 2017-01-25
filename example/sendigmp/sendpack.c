/* Usage example : sendigmp.exe "rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578}" 
** Code conforms to https://www.ietf.org/rfc/rfc2236.txt 
** Wireshark example can be found at https://wiki.wireshark.org/IGMP 
**
** Requires WinPCAP develooper resources. Tested against version 4.1.3 (https://www.winpcap.org/devel.htm).
**
** Author : Ross Newma (ross.newman@abaco.com) 
** Example Usage :
**	    
**	    D:\WpdPack\Examples-pcap\sendpack\Debug>sendigmp.exe rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} 1 239 255 255 250
**	    1. rpcap://\Device\NPF_{4F2C580A-26CC-40A1-A339-578B4B473B85} (Network adapter 'Microsoft' on local host)
**	    2. rpcap://\Device\NPF_{6FDD06EA-8BFD-460B-A3AC-9789FE3E1600} (Network adapter 'Microsoft' on local host)
**	    3. rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} (Network adapter 'Intel(R) 82579LM Gigabit Network Connection' on local host)
**	    4. rpcap://\Device\NPF_{6793231A-CC1D-4CCB-88F1-C57C4BEA9E44} (Network adapter 'Microsoft' on local host)
**	    
**	    IGMP Joining 239.255.255.250...
**	    
**	    D:\WpdPack\Examples-pcap\sendpack\Debug>sendigmp.exe rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} 0 239 255 255 250
**	    1. rpcap://\Device\NPF_{4F2C580A-26CC-40A1-A339-578B4B473B85} (Network adapter 'Microsoft' on local host)
**	    2. rpcap://\Device\NPF_{6FDD06EA-8BFD-460B-A3AC-9789FE3E1600} (Network adapter 'Microsoft' on local host)
**	    3. rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} (Network adapter 'Intel(R) 82579LM Gigabit Network Connection' on local host)
**	    4. rpcap://\Device\NPF_{6793231A-CC1D-4CCB-88F1-C57C4BEA9E44} (Network adapter 'Microsoft' on local host)
**	    
**	    IGMP Leave 239.255.255.250...
**
** Example of how to check the GS12 memberships:
**
**	    (GE Fanuc GBX410 Routing) #show mac-address-table igmpsnooping
**	    
**	          MAC Address         Type      Description             Interfaces
**	    -----------------------  -------  ----------------  -------------------------
**	    00:02:01:00:5E:7F:FF:19  Dynamic  Network Assist    Fwd: 0/2
**	    00:02:01:00:5E:7F:FF:FA  Dynamic  Network Assist    Fwd: 0/2
**	    00:02:01:00:5E:7F:FF:FF  Dynamic  Network Assist    Fwd: 0/2
**	    
** After issuing a Leave command i.e. sendigmp.exe rpcap://\Device\NPF_{39EFC0AD-AE9B-40EC-82CF-9306C91F4013} 0 239 255 255 255
**
**	    (GE Fanuc GBX410 Routing) #show mac-address-table igmpsnooping
**	    
**	          MAC Address         Type      Description             Interfaces
**	    -----------------------  -------  ----------------  -------------------------
**	    00:02:01:00:5E:7F:FF:19  Dynamic  Network Assist    Fwd: 0/2
**	    00:02:01:00:5E:7F:FF:FA  Dynamic  Network Assist    Fwd: 0/2
*/

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

typedef unsigned short int word16;  // 16-bit word is a short int
typedef unsigned int       word32;  // 32-bit word is an int

#pragma pack(1)
typedef struct
{
	INT8 mac_destination[6];
	INT8 mac_source[6];
	INT16 type;
} ethernet;

#pragma pack(1)
typedef struct
{
	INT8 type;
	INT8 len;
	INT16 router_alert;
} options;

#pragma pack(1)
typedef struct
{
	INT8 version_len;
	INT8 dsf;
	INT16 len;
	INT16 id;
	INT8 flags;
	INT8 offset;
	INT8 ttl;
	INT8 protocol;
	INT16 checksum;
	INT8 sourceip[4];
	INT8 destinationip[4];
	options opts;
} ipv4;

typedef struct
{
	INT8 type;
	INT8 mrt;
	INT16 checksum;
	INT8 ip_mcast[4];
} igmpv2;

typedef struct
{
	ethernet ethernet_header;
	ipv4 ip;
	igmpv2 igmp;
} igmp_packet;

void list(void)
{
	pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }
    
    /* Print the list */
    for(d= alldevs; d != NULL; d= d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
}

static int
in_cksum(u_short *addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;

    /*
     * Our algorithm is simple, using a 32 bit accumulator (sum), we add
     * sequential 16 bit words to it, and at the end, fold back all the
     * carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1) {
        *(u_char *)(&answer) = *(u_char *)w ;
        sum += answer;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return(answer);
}

enum
{
	MEMBERSHIP_QUEARY = 0x11,  /* Membership Query */
	MEMBERSHIP_REPORT = 0x16,  /* Membership Report */
	LEAVE_GROUP = 0x17         /* Leave Group */
};

int main(int argc, char **argv)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	u_char mcast_addr[4];
	int len, join;
	int test=0;
	igmp_packet igmp;
	
	/* Check the validity of the command line */
	if (argc != 7)
	{
		printf("usage: %s interface join/leave[0|1] mcast1[0-255] mcast2[0-255] mcast3[0-255] mcast4[0-255]", argv[0]);
		return 1;
	}

	join = atoi(argv[2]);
        mcast_addr[0] = atoi(argv[3]);
        mcast_addr[1] = atoi(argv[4]);
        mcast_addr[2] = atoi(argv[5]);
        mcast_addr[3] = atoi(argv[6]);


	/* This will list your adapters i.e. rpcap://\Device\NPF_{F7AE2C5A-3C42-4CCA-B034-BD4B3CE9D578} */
	/* Use this to get your adapter name (machine specific) */
	list();

	if (join)
	{
		printf("\nIGMP Joining %d.%d.%d.%d...\n", mcast_addr[0],mcast_addr[1],mcast_addr[2],mcast_addr[3]);
	}
	else
	{
		printf("\nIGMP Leave %d.%d.%d.%d...\n", mcast_addr[0],mcast_addr[1],mcast_addr[2],mcast_addr[3]);
	}

	/* Open the adapter */
	if ((fp = pcap_open_live(argv[1],		// name of the device
							 65536,			// portion of the packet to capture. It doesn't matter in this case 
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 2;
	}

	/* Ethernet header */
	/* Supposing to be on ethernet, set mac BROADCAST FF:FF:FF:FF:FF:FF */
	igmp.ethernet_header.mac_destination[0]=0x01;
	igmp.ethernet_header.mac_destination[1]=0x00;
	igmp.ethernet_header.mac_destination[2]=0x53;
	igmp.ethernet_header.mac_destination[3]=mcast_addr[1] & 0x7f;
	igmp.ethernet_header.mac_destination[4]=mcast_addr[2];
	igmp.ethernet_header.mac_destination[5]=mcast_addr[3];
	
	/* set mac source to dummy Radstone MAC 00:80:8e:xx:xx:xx */
	/* NOTE: Radstone is the MAC address range used by Abaco Systems (formally Radstone Technologies) */
	igmp.ethernet_header.mac_source[0]=0x00;
	igmp.ethernet_header.mac_source[1]=0x80;
	igmp.ethernet_header.mac_source[2]=0x8e;
	igmp.ethernet_header.mac_source[3]=0x01;
	igmp.ethernet_header.mac_source[4]=0x02;
	igmp.ethernet_header.mac_source[5]=0x03;
	
	igmp.ethernet_header.type=0x0008;

	/* IPV4 header */
	igmp.ip.version_len = 0x46;
	igmp.ip.dsf = 0x00;
	igmp.ip.len = 0x2000;
	igmp.ip.id = 0xdd58;
	igmp.ip.flags = 0x0;
	igmp.ip.offset = 0x00;
	igmp.ip.ttl = 0x01;
	igmp.ip.protocol = 0x02;
	igmp.ip.checksum = 0x0000;
	igmp.ip.sourceip[0] = 0xc0;
	igmp.ip.sourceip[1] = 0xa8;
	igmp.ip.sourceip[2] = 0x00;
	igmp.ip.sourceip[3] = 0x01;
	igmp.ip.destinationip[0] = mcast_addr[0];
	igmp.ip.destinationip[1] = mcast_addr[1];
	igmp.ip.destinationip[2] = mcast_addr[2];
	igmp.ip.destinationip[3] = mcast_addr[3];
	igmp.ip.opts.type = 0x94;
	igmp.ip.opts.len = 0x04;
	igmp.ip.opts.router_alert = 0x0000;

        /* Generate the IPV4 checksum */
	igmp.ip.checksum = in_cksum((u_short*)&igmp.ip.version_len, 24); 


	/* IGMPv2 header */
	if (join)
	{
		igmp.igmp.type = MEMBERSHIP_REPORT;
	}
	else
	{
		igmp.igmp.type = LEAVE_GROUP;
	}
	igmp.igmp.mrt = 0x0;
	igmp.igmp.checksum = 0x0;
	igmp.igmp.ip_mcast[0] = mcast_addr[0];
	igmp.igmp.ip_mcast[1] = mcast_addr[1];
	igmp.igmp.ip_mcast[2] = mcast_addr[2];
	igmp.igmp.ip_mcast[3] = mcast_addr[3];

	/* Generate the IGMPv2 checksum */
	igmp.igmp.checksum = in_cksum((u_short*)&igmp.igmp.type, 8); 

        /* set the IGMPv2 checksum */
	memcpy(packet, &igmp, sizeof(igmp_packet));
	len=sizeof(igmp_packet);

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet,				// buffer with the packet
		(int)len				// size
		) != 0)
	{
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 3;
	}

	pcap_close(fp);	
	return 0;
}

