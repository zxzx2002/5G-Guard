# 5G-Guard
Source code of 5G-Guard (CCC-2026)
## Paper
5G-Guard: A 5G-Specific and Timely Intrusion Detection System Using Programmable Switches
## Abstract
5G networks, with their inherent demands for high reliability and low latency, are particularly vulnerable to security threats such as distributed denial of service (DDoS) attacks, which can directly undermine these core service guarantees. However, existing intrusion detection systems (IDSs) struggle with the dual challenges of parsing complex 5G protocols and achieving timely detection. In this paper, we propose 5G-Guard, a 5G-specific and timely IDS framework leveraging programmable switches. Our core design employs a cross-plane architecture. Specifically, the switch data plane performs line-rate parsing of 5G protocols and conducts threshold-based DDoS detection, while the control plane hosts a learning-based model for fine-grained analysis and dynamically optimizes the data plane's detection thresholds. These two planes are tightly coordinated via gRPC for real-time communication. Implemented on an Intel Tofino switch, 5G-Guard reduces per-packet detection latency to sub-microsecond level and improves IDS throughput to 2.78 Mpps, while maintaining high detection accuracy.
## Source Code Usage
### Overview
We have provided three folders.
#### ControlPlane_ML_model/
It contains Python programs related to gRPC, used for controlling plane's gRPC communication and deploying the learning model; 
#### DataPlane_P4_threshold/
It contains the P4 program for the data plane, is used for threshold analysis and packet dropping processing of the features extracted by the data plane; 
#### Protocol_Analysis_p4/
A P4 program for the data plane, used for custom parsing of 5G protocols. Together, we also provide two 5G datasets in .pcap format for evaluation.
### Setup Instructions
As for the control plane python program, we utilize Python 3.8.   
As for the data plane P4 program, we utilize bf-sde-9.10.0 with Intel Tofino switch.
