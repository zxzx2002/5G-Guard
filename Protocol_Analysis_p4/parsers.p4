/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/

parser TofinoIngressParser(
        packet_in pkt,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        transition select(ig_intr_md.resubmit_flag) {
            1 : parse_resubmit;
            0 : parse_port_metadata;
        }
    }

    state parse_resubmit {
        // Parse resubmitted packet here.
        transition reject;
    }

    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition accept;
    }
}

// The parsing process starts here

parser MyIngressParser(packet_in packet,
                out headers hdr,
		        out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md)
{
    TofinoIngressParser() tofino_parser;
    state start {
        tofino_parser.apply(packet, ig_intr_md);
        transition parse_ethernet;
    }



    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }


    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            6 : parse_tcp;    //add
            default: accept;
        }
    }
    state parse_tcp {     //add
    packet.extract(hdr.tcp);
    transition accept;
}

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            2152: parse_gtp;
            default: accept;
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.flags) {
            0x34: parse_gtp_optional;
            default: accept;
        }
    }

    state parse_gtp_optional {
        packet.extract(hdr.gtp_optional);
        transition select(hdr.gtp_optional.next_extension_header_type) {
            0x85: parse_extension_header;
            default: accept;
        }
    }

    state parse_extension_header {
        packet.extract(hdr.extension_header);
        transition select(hdr.extension_header.QFI){
            1: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}
/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/
// MyIngressDeparser

control MyIngressDeparser(packet_out packet,
	 inout headers hdr,
	in metadata meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)  {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);//add
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_optional);
        packet.emit(hdr.extension_header);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);

    }
}






parser MyEgressParser(
       packet_in packet,
	    out headers hdr,
	    out metadata meta,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        packet.extract(eg_intr_md);
        transition parse_ethernet;
    }


    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            6 : parse_tcp;     //add
            default: accept;
        }
    }
    state parse_tcp {     //add
    packet.extract(hdr.tcp);
    transition accept;
}

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            2152: parse_gtp;
            default: accept;
        }
    }

    state parse_gtp {
        packet.extract(hdr.gtp);
        transition select(hdr.gtp.flags) {
            0x34: parse_gtp_optional;
            default: accept;
        }
    }

    state parse_gtp_optional {
        packet.extract(hdr.gtp_optional);
        transition select(hdr.gtp_optional.next_extension_header_type) {
            0x85: parse_extension_header;
            default: accept;
        }
    }

    state parse_extension_header {
        packet.extract(hdr.extension_header);
        transition select(hdr.extension_header.QFI){
            1: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            17: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }




}

control MyEgressDeparser(
        packet_out packet,
        inout headers hdr,
        in metadata meta,
        in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtp);
        packet.emit(hdr.gtp_optional);
        packet.emit(hdr.extension_header);
        packet.emit(hdr.inner_ipv4);
        packet.emit(hdr.inner_udp);
    }
}