#include <stdint.h>
#include <stdlib.h>

#pragma once
#define ARPHEADER_H

#pragma pack(push,1)


struct allpacket
{
    u_char e_dmac[6];
    u_char e_smac[6];
    u_short type;

    u_short hd_type;
    u_short protocol_type;
    u_char hd_size;
    u_char protocol_size;
    u_short opcode;
    u_char a_s_mac[6];
    u_char a_s_protocol[4];
    u_char a_t_mac[6];
    u_char a_t_protocol[4];
};
#pragma pack(pop)


#define ETHERTYPE_ARP   0x0806
#define ARPOP_REQUEST   1
#define ARPOP_REPLY     2
