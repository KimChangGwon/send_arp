#include <stdint.h>
#include <net/ethernet.h>
#define ARPOP_REQUEST 1
#define ARPOP_REPLY 2
#pragma pack(1)
struct arphdr{
	uint16_t ar_hrd;
	uint16_t ar_pro;
	uint8_t ar_hln;
	uint8_t ar_pln;
	uint16_t ar_op;
};
#pragma pop()

#pragma pack(1)
struct ether_arp{
	struct arphdr ea_hdr;
	uint8_t arp_sha[6];	//sender hardware address
	uint32_t arp_spa;	//sender protocol address
	uint8_t arp_tha[6];	//target hardware address
	uint32_t arp_tpa;	//target protocol address
};
#pragma pop()

#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op ea_hdr.ar_op


#pragma pack(1)
struct arp_packet{
	struct ether_header ether_header;
	struct ether_arp ether_arp;
};
#pragma pop()

void make_ether_header(struct ether_header * ether_header, uint8_t * dest, uint8_t * source, uint16_t type);
void make_arp_header(struct ether_arp * ether_arp, uint8_t * sha, uint32_t spa, uint8_t * tha, uint32_t tpa, uint32_t op);
