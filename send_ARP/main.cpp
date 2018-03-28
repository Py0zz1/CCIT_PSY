#include <pcap.h>   // pcap libc
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>  // inet libc
#include <thread>       // Thread libc
#include "header.h"     // header define

using namespace std;

#define ERRBUF_SIZ 1024
#define SNAPLEN 65536
#define BUF_SIZ 1024
#define FILTER_RULE "tcp"
#define ETHER_HEADER_SIZE 14

pcap_t *use_dev;
struct pcap_pkthdr *header;
const uint8_t *pkt_data;


void err_print(int err_num);
void init_dev(char *dev_name);
void find_mac(const uint8_t pkt_data, char *victim_ip, char *gateway_ip);

void cap_pkt()
{
    int res;
    cout << "DD";




}

int main(int argc, char **argv)
{
    if(argc != 4)
    {
        err_print(0);
        return -1;
    }
    init_dev(argv[1]);
    printf("dadad");
    cout <<"DDdadasda"<<endl;
    thread t1(cap_pkt);

     t1.join();




}

void find_mac(const uint8_t pkt_data,char *victim_ip,char *gateway_ip)
{

    struct arp_header *ah;
    ah = (struct arp_header *)pkt_data;
    cout << victim_ip <<endl;

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
