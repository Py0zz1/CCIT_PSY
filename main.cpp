#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
   
#define BUF_SIZE 100
#define ETH_HEADER_SIZE 14 // IP_HEADER_JMP --> ETH_HEADER_SIZE Fixed
#define SNAPLEN 65536
struct ether_add
{
    uint8_t mac_add[6];
};
struct ether_header
{
    struct ether_add src_mac;
    struct ether_add des_mac;
    uint16_t eth_type;
    //14bytes
};

struct ip_header
{
    uint8_t ip_version : 4;     // unsigned char --> uint8_t Fixed
    uint8_t ip_header_length : 4;
    uint8_t ip_TOS;
    uint16_t ip_total_length;
    uint16_t ip_iden;
    uint8_t flag_x : 1;
    uint8_t flag_D : 1;
    uint8_t flag_M : 1;
    uint8_t offset_part_1 : 5;
    uint8_t offset_part_2;
    uint8_t TTL;
    uint8_t ip_protocol;
    uint16_t chk_sum;
    struct in_addr ip_src_add;
    struct in_addr ip_des_add;
    //20bytes
};

struct tcp_header
{
    uint16_t src_port;
    uint16_t des_port;
    uint32_t sqn_num;
    uint32_t ack_num;
    uint8_t offset : 4;
    uint8_t ns : 1;
    uint8_t reserve : 3;
    uint8_t flag_cwr : 1;
    uint8_t flag_ece : 1;
    uint8_t flag_urgent : 1;
    uint8_t flag_ack : 1;
    uint8_t flag_push : 1;
    uint8_t flag_reset : 1;
    uint8_t flag_syn : 1;
    uint8_t flag_fin : 1;
    uint16_t window;
    uint16_t chk_sum;
    uint16_t urgent_point;
    //20bytes
};
void net_err(uint32_t chk,pcap_if_t *alldevs);
void print_ether_header(const uint8_t *pkt_data);
int print_ip_header(const uint8_t *pkt_data);
int print_tcp_header(const uint8_t *pkt_data);
void print_data(const uint8_t *pkt_data);

int main(int argc, char **argv)
{
    int IP_HEADER_SIZE,TCP_HEADER_SIZE;
    pcap_if_t *alldevs = NULL;
    pcap_if_t *dev;
    pcap_t *use_dev;
    char errbuf[BUF_SIZE];
    char FILTER_RULE[BUF_SIZE] = "tcp";
    struct bpf_program rule_struct;
    int i, dev_num, res;
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;

    //port설정 인자값이 있으면 port룰 설정
    //없으면, 모든 패킷 감청
    if (argc>=2 && argv[1])         // argc Check Fixed
    {
        strcpy(FILTER_RULE, "port ");
        strcat(FILTER_RULE, argv[1]); // FILTER_RULE (port)설정
    }


    if (pcap_findalldevs(&alldevs, errbuf) < 0)
    {
        printf("Device Find Error\n");
        return -1;
    }

    for (dev = alldevs, i = 0; dev != NULL; dev = dev->next)
        printf("%d번 Device : %s (%s)\n", ++i, dev->name, dev->description);

    printf("사용할 디바이스 번호 입력 : ");
    scanf("%d", &dev_num);

    for (dev = alldevs, i = 0; i < dev_num - 1; dev = dev->next, i++);

    if ((use_dev = pcap_open_live(dev->name, SNAPLEN, 1, 1000, errbuf)) == NULL)
    {
        net_err(1,alldevs);         // pcap_freealldevs(alldevs) overlap Fixed!
    }
    printf("pcap_open 성공!\n");
    printf("FILTER_RULE : %s\n", FILTER_RULE);
    //////////                    pcap_open_success                ////////////


    if ((pcap_compile(use_dev, &rule_struct, FILTER_RULE, 1, NULL)) < 0)
    {
        net_err(2,alldevs);         // pcap_freealldevs(alldevs) overlap Fixed!
    }

    if (pcap_setfilter(use_dev, &rule_struct) < 0)
    {
        net_err(3,alldevs);         // pcap_freealldevs(alldevs) overlap Fixed!
    }

    pcap_freealldevs(alldevs); //캡처 네트워크를 제외한 네트워크 해제
    

    while ((res = pcap_next_ex(use_dev, &header, &pkt_data)) >= 0)
    {
        if (res == 0) continue;


        print_ether_header(pkt_data);
        pkt_data += ETH_HEADER_SIZE;

        IP_HEADER_SIZE = print_ip_header(pkt_data); // IP_Header_Size Check Fixed
        pkt_data += IP_HEADER_SIZE;

        TCP_HEADER_SIZE = print_tcp_header(pkt_data); // TCP_Header_Size Check Fixed
        pkt_data += TCP_HEADER_SIZE;

        if(header->caplen - (ETH_HEADER_SIZE+IP_HEADER_SIZE+TCP_HEADER_SIZE)) // DATA_packet Check Fixed
            print_data(pkt_data);
    }

}



///////////////////////////////////print_function///////////////////////////////////////
void print_ether_header(const uint8_t *pkt_data)
{
    struct ether_header *eh;
    eh = (struct ether_header *)pkt_data;
    uint16_t ether_type = ntohs(eh->eth_type);
    if (ether_type == 0x0800) printf("======= IPv4 =======\n");
    printf("Src MAC : ");
    for (int i = 0; i <= 5; i++) printf("%02X ", eh->src_mac.mac_add[i]);
    printf("\nDes MAC : ");
    for (int i = 0; i <= 5; i++)printf("%02X ", eh->des_mac.mac_add[i]);
    printf("\n");
}

int print_ip_header(const uint8_t *pkt_data)
{
    struct ip_header *ih;
    ih = (struct ip_header *)pkt_data;
    if (ih->ip_protocol == 0x06)
    {
        printf("(TCP)");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("(TCP)");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
    if (ih->ip_protocol == 0x17)
    {
        printf("(UDP)");
        printf("Src IP : %s\n", inet_ntoa(ih->ip_src_add));
        printf("(UDP)");
        printf("Des IP : %s\n", inet_ntoa(ih->ip_des_add));
    }
    return ((char)ih->ip_header_length)*5;
}
int print_tcp_header(const uint8_t *pkt_data)
{
    struct tcp_header *th;
    th = (struct tcp_header *)pkt_data;

    printf("Src Port : %d\n", ntohs(th->src_port));
    printf("Des Port : %d\n", ntohs(th->des_port));
    printf("====================\n\n");

    return ((char)th->offset)*5;
}

void print_data(const uint8_t *pkt_data)
{
    printf("========DATA========\n");
    for(int i=0; i<14; i++)
        printf("%x",pkt_data[i]);
    printf("\n====================\n\n");
}


void net_err(uint32_t chk,pcap_if_t *alldevs)
{
    switch(chk)
    {
    case 1:
        printf("pcap_open ERROR!\n");
        pcap_freealldevs(alldevs);
        break;
    case 2:
        printf("pcap_compile ERROR!\n");
        pcap_freealldevs(alldevs);
        break;
    case 3:
        printf("pcap_setfilter ERROR!\n");
        pcap_freealldevs(alldevs);
    default:
        printf("ERROR!\n");
    }
}
