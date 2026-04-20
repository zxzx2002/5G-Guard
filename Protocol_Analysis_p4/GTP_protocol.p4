#include <core.p4>
#include <tna.p4>

#include "include/headers.p4"
#include "include/parsers.p4"

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(
        inout headers hdr,
        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

	action drop(){
		ig_dprsr_md.drop_ctl = 0x1;
	}

    action set_egress_port(bit<9> egress_port){
        ig_tm_md.ucast_egress_port = egress_port;
    }

    table forwarding {
        key = {ig_intr_md.ingress_port: exact;}
        actions = {set_egress_port; drop; NoAction;}
        size = 64;
        default_action = drop;
    }

   apply {
    if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
        if(!hdr.gtp.isValid()){
            hdr.gtp.setValid();        // Enable this protocol
            hdr.udp.setValid();
            hdr.gtp.flags = 0x34;        // Set up how this protocol is linked to the preceding and following protocols
            hdr.udp.dstPort=2152;
            hdr.gtp.length=65535;
        }

        set_egress_port(148);
    }else {
        drop();
   }
   }



}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
    inout metadata meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply{}
}  

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
Pipeline(MyIngressParser(),
         MyIngress(),
         MyIngressDeparser(),
         MyEgressParser(),
         MyEgress(),
         MyEgressDeparser()) pipe;

Switch(pipe) main;