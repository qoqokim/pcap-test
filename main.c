#include <stdio.h>
#include <pcap.h>
#include <stdint.h>  // for uint8_t
#include <netinet/in.h>  //for ntohs
#include <netinet/ether.h>  //for ETHERTYPE_IP
#include <linux/in.h> //for IPPROTO_TCP

/* netinet/ether.h
struct ether_header {   // size: 14byte
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};
*/

struct Ipv4_header {  // size: 20byte
    uint8_t ip_hlen:4,ip_v:4;  // little endian (changing the order)
    uint8_t ip_tos;   // type of service
    uint16_t ip_tlen;
    uint16_t ip_id;
    uint16_t ip_off;
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint16_t ip_sum;
    uint8_t ip_src[4];  // 4byte
    uint8_t ip_dst[4];  // 4byte
};

struct tcp_header {
    uint16_t tcp_sport;  // 2byte
    uint16_t tcp_dport;  // 2byte
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint8_t tcp_re:4,tcp_off:4;   // little endian (changing the order)
    uint8_t tcp_flag;
    uint16_t tcp_win;
    uint16_t tcp_sum;
    uint16_t tcp_urp;   // urgent pointer
};


void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}


int main(int argc, char* argv[])  {

    if (argc!=2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf [PCAP_ERRBUF_SIZE];
    int i=0,j=0;

    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);   // open handle
    if (handle ==NULL) {
        printf("pcap_open_live error %s\n(%s)",dev,errbuf);
        return -1;
    }

    printf("pcap open start! ---------- \n\n");


    while(1) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf(" pcap_next_ex error \n");
            return -1;
        }

        printf("\n------  packet sniff %d  ------\n",++j);


        struct ether_header *ether;
        ether = (struct ether_header*)packet;
        u_short eth_type;
        eth_type = ntohs(ether->ether_type);

        if(eth_type == ETHERTYPE_IP){  //0x0800 = ipv4

            packet += sizeof(struct ether_header);

            struct Ipv4_header* ip;
            ip = (struct Ipv4_header*)packet;

            u_char p;
            p=ip->ip_protocol;

            u_char hlen;
            hlen = ip->ip_hlen;

            u_short tlen;
            tlen = ntohs(ip->ip_tlen);

            if (p == IPPROTO_TCP) { // 6 = TCP
                printf("< TCP > \n");

                printf("Dst MAC :  ");
                for (i=0;i <6;i++) {
                    printf("%02x ",ether->ether_dhost[i]);
                }
                printf("\n");
                printf("Src MAC :  ");
                for (int i=0;i <6;i++) {
                    printf("%02x ",ether->ether_shost[i]);
                }
                printf("\n");
                printf("Dst IP :   ");
                for (i=0;i<4;i++) {
                    printf("%d",ip->ip_dst[i]);
                    if (i!=3) {
                        printf(".");
                    }
                }
                printf("\n");
                printf("Src IP :   ");
                for (i=0;i<4;i++) {
                    printf("%d",ip->ip_src[i]);
                    if (i!=3) {
                        printf(".");
                    }
                }
                printf("\n");

                packet += hlen*4;

                struct tcp_header* tcp;
                tcp = (struct tcp_header*)packet;
                u_char tcplen;
                tcplen = (tcp->tcp_off);

                printf("Dst Port :  %d \n",ntohs(tcp->tcp_dport));
                printf("Src Port :  %d \n",ntohs(tcp->tcp_sport));

                packet += tcplen*4;

                if ((tlen -(hlen+tcplen)*4) > 0) { //tlen-hlen-tcplen
                    printf("payload : ");
                    for (i=0;i<16 && i<tlen-(hlen+tcplen)*4;i++){
                        printf("%02x ",packet[i]);
                    }
                    printf("\n");
                }
            }       
            else
                printf("\n");

        }
    }
    pcap_close(handle);
}
