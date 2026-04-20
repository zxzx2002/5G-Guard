# Overview
Since the control plane supports the deployment of various learning models, the key lies in how to upload the information obtained by the data plane to the model. Therefore, to ensure higher flexibility of use, we provide a case of cross-plane communication implemented using gRPC. The specific model can be deployed according to your needs. 
The input of the model provided by gRPC is (1) the number of data packets within a unit time and (2) the total number of bytes of the data packets.

# File Usage
## test_grpc.p4
It provides interfaces for the use of data plane registers and tables.

## grpc.py
It provides interfaces for the use of control plane to define the values in registers and tables.
