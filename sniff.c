#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>         // tcp
#include <arpa/inet.h>          // Include this for inet_ntoa



/* Ethernet header */
struct ethheader {
    u_char  ether_dhost[6];    /* destination host address */
    u_char  ether_shost[6];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};


/* TCP Header */
struct tcpheader {
    u_short tcp_sport;               /* source port */
    u_short tcp_dport;               /* destination port */
    u_int   tcp_seq;                 /* sequence number */
    u_int   tcp_ack;                 /* acknowledgement number */
    u_char  tcp_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
    u_char  tcp_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;                 /* window */
    u_short tcp_sum;                 /* checksum */
    u_short tcp_urp;                 /* urgent pointer */
};


// HTTP
void print_http(const u_char *payload, int payload_size)
{
    if (payload_size >= 5 && memcmp(payload, "HTTP/", 5) == 0)
    {
        printf("HTTP Response:\n");
        printf("%.*s\n", payload_size, payload);
    }
    else
    {
        printf("Non-HTTP Data (First 16 bytes):\n");
        int max_print = 16;
        int i;
        for(i=0; i<payload_size && i<max_print ; payload)
        {
            printf("%02X ", payload[i]);
        }
        if (payload_size > max_print)
        {
            printf("...");
        }
        printf("\n");
    }
}


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *ethernet = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
    
    
    printf("Got a packet\n");
    printf("Src MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", 
        ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2], 
        ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
    printf("Dst MAC : %02X:%02X:%02X:%02X:%02X:%02X\n",
        ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2], 
        ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);
    printf("Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP  : %s\n", inet_ntoa(ip->iph_destip));
    printf("Src PORT: %u\n", ntohs(tcp->tcp_sport));
    printf("Dst PORT: %u\n", ntohs(tcp->tcp_dport));

    int tcp_header_size = TH_OFF(tcp) * 4;

    // Calculate the size of the payload
    int payload_size = ntohs(ip->iph_len) - sizeof(struct ipheader) - tcp_header_size;

    // Check if there is payload data
    if (payload_size > 0)
    {
        print_http(packet + sizeof(struct ethheader) + sizeof(struct ipheader) + tcp_header_size, payload_size);
    }

    printf("\n");

}

int main(void)
{
    pcap_t *handle;                     // pcap_t 구조체 포인트 선언
    char errbuf[PCAP_ERRBUF_SIZE];      // 오류메시지를 저장하는 버퍼 생성
    struct  bpf_program fp;             // bpf 프로그램을 저장하는 데 사용되는 
    char filter_exp[] = "tcp";          // bpf 필터 표현식을 포함하는 문자열이다. icmp, tcp, udp?
    bpf_u_int32 net;                    // 패킷을 캡처하는 데 사용되는 인터페이스의 네트워크 마스크를 저장하는데 사용

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);   
    /* pcap세션을 연다 
    0 캡처할 인터페이스 이름 
    1 캡처할 패킷의 최대길이
    2 promiscuous 모드 활성화할지 1이 활성화
    3 패킷을 캡처할 시간(밀리초)
    4 오류 메시지를 저장할 버퍼 */

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    /* 
    0 핸들러선택
    1 패킷 캡쳐 횟수 설정 -1 계속하기
    2 패킷을 처리할 때 콜백 함수
    3 콜백함수에 들어갈 인자
    */

   pcap_close(handle);

}