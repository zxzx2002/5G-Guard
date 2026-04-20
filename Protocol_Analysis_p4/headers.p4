#include <core.p4>
#include <v1model.p4>
#define CPU_PORT 255
const bit<16> ETHERTYPE_IPV4 = 0x0800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>   version;
    bit<4>   ihl;
    bit<6>   dscp;
    bit<2>   ecn;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header gtp_t {
    bit<8>  flags;
    bit<8>  msgType;
    bit<16> length;
    bit<32> teid;
}

header gtp_optional_t{
    bit<8> sequence_number_1;
    bit<8> sequence_number_2;
    bit<8> N_PDU;
    bit<8> next_extension_header_type;
}

header extension_header_t{
    bit<8> length;
    bit<8> pdu_session;
    bit<8> QFI;
    bit<8> extension_header;
}

struct metadata {
    bit<32> num;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t udp;
    gtp_t gtp;   
    gtp_optional_t gtp_optional;
    extension_header_t extension_header;
    ipv4_t inner_ipv4;
    udp_t inner_udp;
}