#include <sys/types.h>

#define MAX_HOSTNAME_LEN 32

#define MAX_CONFIDENCE 2 //Highest possible confidence value

/*
    Confidence values:
    0 - thru dhcp request
    1 - Queried by arp
    2 - Arp query sender / mdns sender / generic ipv4 sender
*/

enum confidence_val{
    cfv_dhcp_requester,
    cfv_arp_queried,
    cfv_packet_sender
};

/*Logged device */
struct dev_info{
    u_char mac[6];
    u_char ipv4[4];
    enum confidence_val ipv4_confidence; //Confidence value
    char hostname[MAX_HOSTNAME_LEN]; //Only store first MAX_HOSTNAME_LEN characters of hostname
};

/* Ethernet header */
struct eth_header {    
    u_char ether_dhost[6]; /* Destination host address */
    u_char ether_shost[6]; /* Source host address */
    u_short ether_type;               /* IP? ARP? RARP? etc */
};

/* IP header */
struct ipv4_header {
    u_char ip_vhl; /* version << 4 | header length >> 2 */
    u_char ip_tos; /* type of service */
    u_short ip_len;              /* total length */
    u_short ip_id;               /* identification */
    u_short ip_off;              /* fragment offset field */
    u_char ip_ttl;                 /* time to live */
    u_char ip_p;                   /* protocol */
    u_short ip_sum;              /* checksum */
    u_char ip_src[4];
    u_char ip_dst[4]; /* source and dest address */
};

/* TCP header */
struct tcp_header {
    u_short port_src;
    u_short port_dest;
    uint sq_num;
    uint ack_num;
    u_short flags;
    u_short window;
    u_short checksum;
    u_short urg_pointer;
    u_char tcp_options[12]; // tcp options are not actually 12 individual bytes, this is just a placeholder
};

/* ARP header */
struct arp_header {
    u_short hardware_type;
    u_short protocol_type; // 0x0800 is ipv4
    u_char hardware_size;
    u_char protocol_size;
    u_short opcode;
    u_char sender_mac[6];
    u_char sender_ipv4[4];
    u_char target_resolv_mac[6];
    u_char target_resolv_ipv4[4];
};

/* UDP header */
struct udp_header {
    u_short src_port;
    u_short dst_port;
    u_short len;
    u_short checksum;
};

/* DHCP header */
struct dhcp_header {
    u_char opcode;
    u_char htype;
    u_char hlen;
    u_char hops;
    u_int xid; //Transaction id
    u_short secs; //Seconds since client tried to lease
    u_short flags;
    u_int client_addr; //Only if client already has a valid ip
    u_int assign_addr; //Address that the server is assigning to the client
    u_int next_serv_addr; //Address to use in next step, may or may not be same ip
    u_int gateway_addr;
    u_char hardware_addr[6]; //Client hardware (mac) address
    u_char haddr_padding[10];
    u_char serv_name[64]; //Server name OR dhcp options
    u_char file[128]; //Boot filename, optional to request certain boot file type
    //Ends with variable length OPTIONS structure
};

/* MDNS header */
struct mdns_header {
    u_short xid;
    u_short flags;
    u_short questions;
    u_short answer_rrs;
    u_short authority_rrs;
    u_short additional_rrs;
    //TODO: Finish struct
};