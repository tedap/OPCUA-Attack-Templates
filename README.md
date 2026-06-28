# OPCUA-Attack-Templates

This repository contains template code for attacks on four vulnerabilities in the open source OPC UA protocol, which were used, for the first time, to demonstrate that these vulnerabilities existed in real world implementations. The vulnerabilities were first detailed by researchers who carried out a formal security analysis on the protocol (see here: https://www.usenix.org/system/files/usenixsecurity25-diemunsch.pdf) which created the inspiration for this project. These templates were developed solely by me (Ted Parting) for an undergraduate project at the University of Birmingham, under the supervision of Tom Chothia. 

The `attack-templates` directory contains the templates for exploiting the vulnerabilities so they can be extended to other libraries. All attacks are developed using the `python-opcua` library, since implementations are interoperable. Steps for executing the attacks are listing in the respective directories of the vulnerabilities.
