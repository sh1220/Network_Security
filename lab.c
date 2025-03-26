#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>



/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
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

char *mac_to_str(const u_char *mac) {
    static char str[18];  // "xx:xx:xx:xx:xx:xx" + NULL
    snprintf(str, sizeof(str),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);
    return str;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *) (packet + sizeof(struct ethheader)); // ethernet은 고정 길이라서 이렇게 가능
    int ip_header_len = ip->iph_ihl * 4;  // ip는 가변길이라서 ihl에 4를 곱해서 ip길이 계산

    struct tcpheader* tcp = (struct tcpheader*)((u_char*)ip + ip_header_len);
    int tcp_header_len = TH_OFF(tcp) * 4;  // tcp도 가변길이라서 data offset 필드 * 4로 길이 계산

    char* payload = (char*)tcp + tcp_header_len;
    int payload_len = ntohs(ip->iph_len) - ip_header_len - tcp_header_len; 
    printf("Ethernet Header\n");
    printf("From: %s\n", mac_to_str(eth->ether_shost));  
    printf("To: %s\n\n", mac_to_str(eth->ether_dhost));  

    printf("IP Header\n");
    printf("From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("To: %s\n\n", inet_ntoa(ip->iph_destip));  

    printf("TCP Header\n");
    printf("From: %d\n", ntohs(tcp->tcp_sport));  
    printf("To: %d\n\n", ntohs(tcp->tcp_dport));

    if (payload_len > 0) {
        printf("Payload (%d bytes):\n", payload_len);
        for (int i = 0; i < payload_len; i++) {
            // 가독성을 위해 출력 가능한 문자만 그대로 출력하고, 나머진 . 으로 표시
            printf("%c", payload[i]);
        }
        printf("\n");
    }
  }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s5", BUFSIZ, 1, 1000, errbuf);
  // nc로 열어서 127.0.0.1로 테스트할때는 lo(루프백) 인터페이스로 설정
  // 직접 패킷 잡아서 해볼려면 enp0s3처럼 실제 인터페이스로 설정

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}


