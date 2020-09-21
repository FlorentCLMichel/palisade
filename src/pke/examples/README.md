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

Example programs
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
- [simple-integers.cpp](src/pke/examples/simple-integers.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-bgvrns.cpp](src/pke/examples/simple-integers-bgvrns.cpp): simple example showing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-integers-serial.cpp](src/pke/examples/simple-integers-serial.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BFVrns
- [simple-integers-serial-bgvrns.cpp](src/pke/examples/simple-integers-serial-bgvrns.cpp): simple example showing typical serialization/deserialization calls for a prototype computing homomorphic additions, multiplications, and rotations for vectors of integers using BGVrns
- [simple-real-numbers.cpp](src/pke/examples/simple-real-numbers): simple example showing homomorphic additions, multiplications, and rotations for vectors of real numbers using CKKS
- [threshold-fhe.cpp](src/pke/examples/threshold-fhe.cpp): shows several examples of threshold FHE in BGVrns, BFVrns, and CKKS
