#include <netinet/in.h>
struct VG_IP
{
  char *victim_ip;
  char *gateway_ip;
};
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

struct arp_header
{
    uint16_t hrd_type;
    uint16_t proto_type;
    uint8_t hrd_len;
    uint8_t proto_len;
    uint16_t oper;
    struct ether_add s_mac;
    struct in_addr s_ip;
    struct ether_add t_mac;
    struct in_addr t_ip;
};

struct ip_header
{
    uint8_t ip_version : 4;
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
