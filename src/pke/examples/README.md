PALISADE Lattice Cryptography Library - Examples
=============================================

[License Information](License.md)

Document Description
===================
This document describes the examples included with the PALISADE lattice crypto library.

Examples Directory Description
==========================

Directory Objective
-------------------
This directory contains examples that, when linked with the library, demonstrate the capabilities of the system

File Listing
------------

*Example programs*

- [advanced-real-numbers.cpp](src/pke/examples/advanced-real-numbers.cpp): shows several advanced examples of approximate homomorphic encryption using CKKS
- [cross-correlation-bfvrns.cpp](src/pke/examples/cross-correlation-bfvrns.cpp): an example that demonstrates the use of serialization, DCRT, power-of-two-cyclotomics, and packed encoding for an application that computes cross-correlation using inner products.
- [depth-bfvrns.cpp](src/pke/examples/depth-bfvrns.cpp): demonstrates use of the BFVrns scheme for basic homomorphic encryption
- [depth-bfvrns-b.cpp](src/pke/examples/depth-bfvrns-b.cpp): demonstrates use of the BFVrnsB scheme for basic homomorphic encryption
- [depth-bgvrns.cpp](src/pke/examples/depth-bgvrns.cpp): demonstrates use of the BGVrns scheme for basic homomorphic encryption
- [evalatindex.cpp](src/pke/examples/evalatindex.cpp): demonstrates use of EvalAtIndex (rotation operation) for different schemes and cyclotomic rings
- [pke.cpp](src/pke/examples/pke.cpp): demonstrates use of encryption across several schemes
- [polynomial_evaluation.cpp](src/pke/examples/polynomial_evaluation.cpp): demonstrates an evaluation of a polynomial (power series) using CKKS
- [pre.cpp](src/pke/examples/pre.cpp): demonstrates use of proxy re-encryption across several schemes
- [pre-text.cpp](src/pke/examples/pre-text.cpp): demonstrates use of PALISADE for encryption, re-encryption and decryption of text
- [pre-buffer.cpp](src/pke/examples/pre-buffer.cpp): demonstrates use of PALISADE for encryption, re-encryption and decryption of packed vector of binary data
- [simple-integers.cpp](src/pke/examples/simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](src/pke/examples/simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-integers-serial.cpp](src/pke/examples/simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](src/pke/examples/simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-reals-serial.cpp](src/pke/examples/simple-reals-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using CKKS
- [simple-real-numbers.cpp](src/pke/examples/simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [threshold-fhe.cpp](src/pke/examples/threshold-fhe.cpp): shows several examples of threshold FHE in BGVrns, BFVrns, and CKKS

*Example client/server systems*

We also have examples of client/server type demos with simplistic (and
unsecured) file based IPC, to demonstrate the use of serialization
between heavyweight processes. The source code for these are in their
own subdirectories.

A client server pair that generates encrypted real data and sends it to a client for processing can be found in the subdirectory `real_number_serialization_client_server`. 

- [real-numbers-serialization-client.cpp](src/pke/examples/real_number_serialization_client_server/real-numbers-serialization-client.cpp): client side of system. 
- [real-numbers-serialization-server.cpp](src/pke/examples/real_number_serialization_client_server/real-numbers-serialization-server.cpp): the server side of the system
- [utils.h](src/pke/examples/real_number_serialization_client_server/utils.h): utility functions for the demo


A client server trio that supports proxy reencryption by a server betweeen two clients is in the subdirectory `pre_server`. 

- [pre-client.cpp](src/pke/examples/pre_server/pre-client.cpp): client(s) side of system. 
- [pre-server.cpp](src/pke/examples/pre_server/pre-server.cpp): the server side of the system
- [pre-utils.h](src/pke/examples/pre_server/utils.h): utility functions for the demo encapsulating the IPC

