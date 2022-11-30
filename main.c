#include <bits/types/struct_timeval.h>
#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <endian.h>
#include <time.h>
#include <sys/socket.h>

char interrupted = 0;
pcap_t *handle;

u_char local_mac[6];

u_char target_ipv4[4];

u_char router_ipv4[4];
u_char router_mac[6];

/*Logged device */
struct dev_info{
    u_char mac[6];
    u_char ipv4[4];
    char hostname[16]; //Only store first 16 characters of hostname
};

struct dev_info loggedips[2048];
u_int loggedipsidx = 0;

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
    struct in_addr ip_src, ip_dst; /* source and dest address */
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

void interruptHandler(int dummy) {
    interrupted = 1;
    pcap_close(handle);
}

void updateip(u_int index, u_char *ipbytes, u_char *macbytes, char *hostname, u_short hostname_len){
    u_char n;
    for(n = 0; n < 4; n++){
        loggedips[index].ipv4[n] = ipbytes[n];
    }
    u_char did_update_value = 0;    
    if(macbytes != NULL){
        for(n = 0; n < 6; n++){
            if(loggedips[index].mac[n] != macbytes[n]){
                loggedips[index].mac[n] = macbytes[n];
                did_update_value = 1;
            }
        }
    }
    if(hostname != NULL){
        for(n = 0; n < 15 && n < hostname_len; n++){
            if(loggedips[index].hostname[n] != hostname[n]){            
                loggedips[index].hostname[n] = hostname[n];
                did_update_value = 1;
            }
        }
        loggedips[loggedipsidx].hostname[n] = '\0';
    }
    if(did_update_value){
        printf("Update ip %d.%d.%d.%d ", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);
        if(macbytes != NULL){
            printf("MAC %02X:%02X:%02X:%02X:%02X:%02X ", macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5]);
        }
        if(hostname != NULL){
            printf("hostname %s ", hostname);
        }
        printf("\n");
    }
}

void logip(u_char *ipbytes, u_char *macbytes, char *hostname, u_short hostname_len){
    for(u_int i = 0; i < loggedipsidx; i++){
        u_char n;
        for(n = 0; n < 4; n++){
            if(loggedips[i].ipv4[n] != ipbytes[n]){
                goto out;
            }
        }
        updateip(i, ipbytes, macbytes, hostname, hostname_len);
        return;
        out:;
    }
    u_char n;
    for(n = 0; n < 4; n++){
        loggedips[loggedipsidx].ipv4[n] = ipbytes[n];
    }
    printf("Logged ip %d.%d.%d.%d ", ipbytes[0], ipbytes[1], ipbytes[2], ipbytes[3]);
    if(macbytes != NULL){
        for(n = 0; n < 6; n++){
            loggedips[loggedipsidx].mac[n] = macbytes[n];
        }
        printf("MAC %02X:%02X:%02X:%02X:%02X:%02X ", macbytes[0], macbytes[1], macbytes[2], macbytes[3], macbytes[4], macbytes[5]);
    }
    if(hostname != NULL){
        for(n = 0; n < 15 && n < hostname_len; n++){
            loggedips[loggedipsidx].hostname[n] = hostname[n];
        }
        loggedips[loggedipsidx].hostname[n] = '\0';
        printf("hostname %s", hostname, n);
    }
    printf("(logged %d)\n", loggedipsidx);
    loggedipsidx++;
}

void handle_dhcp_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);

    struct ipv4_header *ipv4head = (struct ipv4_header*)(packet + sizeof(struct eth_header));

    struct udp_header *udphead = (struct udp_header*)(packet + sizeof(struct eth_header) + sizeof(struct ipv4_header));

    struct dhcp_header *dhcphead = (struct dhcp_header*)(packet + sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header));

    //printf("Captured dhcp packet from ");
    //printf("%02X:%02X:%02X:%02X:%02X:%02X\n", dhcphead->hardware_addr[0], dhcphead->hardware_addr[1], dhcphead->hardware_addr[2], dhcphead->hardware_addr[3], dhcphead->hardware_addr[4], dhcphead->hardware_addr[5]);

    u_char *dhcp_options = (u_char*)(packet + sizeof(struct eth_header) + sizeof(struct ipv4_header) + sizeof(struct udp_header) + sizeof(struct dhcp_header));

    u_char *options_read_idx = dhcp_options ;
    u_char current_option_len;

    options_read_idx += 4; //DHCP Magic cookie

    u_char current_option = *options_read_idx;

    char loggable = 0;

    u_char *ipv4_bytes;
    u_char *mac_bytes;
    char hostname_bytes_mem[16] = {};
    char *hostname_bytes_ptr = NULL;
    u_short hostname_len;

    while(current_option != 0xff){ //END option
        current_option_len = *(options_read_idx + 1);
        switch(current_option){
            case 50:
                //printf("Requested IP: %d.%d.%d.%d\n", *(options_read_idx + 2), *(options_read_idx + 3), *(options_read_idx + 4), *(options_read_idx + 5));
                loggable = 1;
                ipv4_bytes = options_read_idx + 2;
                mac_bytes = (dhcphead->hardware_addr);
                break;
            case 12:{
                //printf("Host name: ");
                u_char i;
                for(i = 2; i < current_option_len + 2 && i < 15; i++){
                    hostname_bytes_mem[i-2] = *(options_read_idx + i);
                }
                hostname_bytes_mem[i-2] = '\0';
                hostname_bytes_ptr = hostname_bytes_mem;
                hostname_len = current_option_len;
                //printf("\n");
                break;
            }
        }
        options_read_idx += current_option_len + 2;
        current_option = *(options_read_idx);
    }
    if(loggable){
        logip(ipv4_bytes, mac_bytes, hostname_bytes_ptr, hostname_len);
    }
    //printf("\n");
}

void handle_mdns_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);

    struct ipv4_header *ipv4head = (struct ipv4_header*)(packet + sizeof(struct eth_header));

    struct udp_header *udphead = (struct udp_header*)(packet + sizeof(struct eth_header) + sizeof(struct ipv4_header));

    //We could parse mdns or we could just
    logip((u_char*)(&(ipv4head->ip_src)), NULL, NULL, 0);
}

void handle_udp_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);

    struct ipv4_header *ipv4head = (struct ipv4_header*)(packet + sizeof(struct eth_header));

    struct udp_header *udphead = (struct udp_header*)(packet + sizeof(struct eth_header) + sizeof(struct ipv4_header));

    if((be16toh(udphead->dst_port) == 67 && be16toh(udphead->src_port) == 68) || (be16toh(udphead->dst_port) == 68 && be16toh(udphead->src_port) == 67)){
        handle_dhcp_packet(args, header, packet);
        return;
    }

    if(be16toh(udphead->dst_port) == 5353 && be16toh(udphead->src_port) == 5353){
        handle_mdns_packet(args, header, packet);
        return;
    }
}

void handle_ipv4_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);

    struct ipv4_header *ipv4head = (struct ipv4_header*)(packet+ sizeof(struct eth_header));
    
    switch (ipv4head->ip_p) {
        case(17): //UDP
            handle_udp_packet(args, header, packet);                
            return;
    }
}

void handle_arp_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);
    struct arp_header *arphead = (struct arp_header*)(packet + sizeof(struct eth_header));
    u_char sender_ipv4[4];

    u_short opcode = be16toh(arphead->opcode);

    //printf("ARP Packet @ %s", ctime(&tv->tv_sec));

    /*if(opcode == 1){ //Request
        printf("%d.%d.%d.%d (",
        arphead->sender_ipv4[0], arphead->sender_ipv4[1], arphead->sender_ipv4[2], arphead->sender_ipv4[3]);

        printf("%02X:%02X:%02X:%02X:%02X:%02X",
        arphead->sender_mac[0], arphead->sender_mac[1], arphead->sender_mac[2], arphead->sender_mac[3], arphead->sender_mac[4], arphead->sender_mac[5]);

        printf("): Who is %d.%d.%d.%d?\n",
        arphead->target_resolv_ipv4[0], arphead->target_resolv_ipv4[1], arphead->target_resolv_ipv4[2], arphead->target_resolv_ipv4[3]);
    }
    else if(opcode == 2){ //Reply
        printf("%d.%d.%d.%d: To ",
        arphead->sender_ipv4[0], arphead->sender_ipv4[1], arphead->sender_ipv4[2], arphead->sender_ipv4[3]);

        printf("%d.%d.%d.%d (",
        arphead->target_resolv_ipv4[0], arphead->target_resolv_ipv4[1], arphead->target_resolv_ipv4[2], arphead->target_resolv_ipv4[3]);

        printf("%02X:%02X:%02X:%02X:%02X:%02X): ",
        arphead->target_resolv_mac[0], arphead->target_resolv_mac[1], arphead->target_resolv_mac[2], arphead->target_resolv_mac[3], arphead->target_resolv_mac[4], arphead->target_resolv_mac[5]);

        printf("I am %02X:%02X:%02X:%02X:%02X:%02X\n",
        arphead->sender_mac[0], arphead->sender_mac[1], arphead->sender_mac[2], arphead->sender_mac[3], arphead->sender_mac[4], arphead->sender_mac[5]);
    }*/
    logip((u_char*)&(arphead->target_resolv_ipv4), NULL, NULL, 0);
    logip((u_char*)&(arphead->sender_ipv4), (u_char*)&(arphead->sender_mac), NULL, 0);

    /*printf("Query MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    arphead->target_resolv_mac[0], arphead->target_resolv_mac[1], arphead->target_resolv_mac[2], arphead->target_resolv_mac[3], arphead->target_resolv_mac[4], arphead->target_resolv_mac[5]);*/
    //printf("\n");
}

void cap_packet(u_char  *args, const struct pcap_pkthdr *header, const u_char *packet){
    struct timeval *tv = (struct timeval*)header;
    bpf_u_int32 *caplen = (bpf_u_int32*)(header+sizeof(struct timeval));
    bpf_u_int32 *totlen = (bpf_u_int32*)(header+sizeof(struct timeval)+sizeof(bpf_u_int32));

    struct eth_header *ethhead = (struct eth_header*)packet;
    u_short packet_type = be16toh(ethhead->ether_type);
    switch (packet_type)
    {
    case 0x0800: //ipv4
        handle_ipv4_packet(args, header, packet);
        return;
    case 0x0806: //ARP
        handle_arp_packet(args, header, packet);
        return;
    default:
        break;
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devs = malloc(10 * sizeof(pcap_if_t));

    char filter_exp[] = "";
    struct bpf_program fp;

    struct pcap_pkthdr header;

    pcap_findalldevs(&devs, errbuf);
    if (devs == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    pcap_if_t dev = devs[0];
    printf("Device: %s\n", dev.name);

    bpf_u_int32 mask;           /* The netmask of our sniffing device */
    bpf_u_int32 net;            /* The IP of our sniffing device */

    if (pcap_lookupnet(dev.name, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev.name);
        net = 0;
        mask = 0;
    }
    
    handle = pcap_open_live(dev.name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev.name, errbuf);
        return(2);
    }
    if(pcap_datalink(handle) != DLT_EN10MB){
        fprintf(stderr, "Not ethernet, quitting!");
        return(2);
    }
    
    signal(SIGINT, interruptHandler);

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    printf("Success, starting sniffing\n\n");
    pcap_loop(handle, -1, cap_packet, NULL);
    printf("Sniffing ended\n");

    return(0);
}
