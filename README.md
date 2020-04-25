PALISADE Lattice Cryptography Library
=====================================

PALISADE is a general lattice cryptography library that currently includes efficient implementations of the following lattice cryptography capabilities:
* Homomorphic Encryption (HE): 
   * Brakerski/Fan-Vercauteren scheme (3 variants)
   * Brakerski-Gentry-Vaikuntanathan scheme
   * Cheon-Kim-Kim-Song scheme
   * Ducas-Micciancio (FHEW) and Chillotti-Gama-Georgieva-Izabachene (TFHE) schemes
   * Stehle-Steinfeld scheme
* Proxy Re-Encryption for all HE schemes
* Digital Signature
* Identity-Based Encryption
* Ciphertext-Policy Attribute-Based Encryption

PALISADE is a cross-platform C++11 library supporting Linux, Windows, and macOS. The supported compilers are g++ v6.1 or later and clang++ v6.0 or later. 

The library also includes unit tests and sample application demos.

PALISADE is available under the BSD 2-clause license.

The library is based on modular architecture with the following layers:

* Math operations layer supporting low-level modular arithmetic, number theoretic transforms, and integer sampling.  This layer is implemented to be portable to multiple hardware computation substrates.
* Lattice operations layer supporting lattice operations, ring algebra, and lattice trapdoor sampling. 
* Crypto layer containing efficient implementations of lattice cryptography schemes.
* Encoding layer supporting multiple plaintext encodings for cryptographic schemes.

A major focus is on the usability of the schemes. For instance, all HE schemes with packing use the same common API, and are implemented using runtime polymorphism.

PALISADE implements efficient Residue Number System (RNS) algorithms to achieve high performance, e.g., PALISADE was used as the library for a winning genome-wide association studies solution at iDASH’18. 

By default, the library is built without external dependencies. But the user is also provided options to add GMP/NTL and/or tcmalloc third-party libraries if desired.

Further information about PALISADE:

[License Information](License.md)

[Library Wiki with documentation](https://gitlab.com/palisade/palisade-development/wikis/home)

[Code of Conduct](Code-of-conduct.md)

[Governance](Governance.md)

[Contributing to PALISADE](Contributing.md)


Build Instructions
=====================================

We use CMake to build PALISADE. The high-level (platform-independent) procedure for building PALISADE is as follows (for OS-specific instructions, see the section "Detailed information about building PALISADE" at the bottom of this page):

1. Install system prerequisites (if not already installed), including a C++ compiler with OMP support, cmake, make, and autoconf.

2. Clone the PALISADE repo to your local machine.

3. Download git submodules by running the following commands (PALISADE downloads submodules for cereal, google-benchmark, google-test, and gperftools open-source libraries):
```
git submodule sync --recursive
git submodule update --init  --recursive
```

4. Create a directory where the binaries will be built. The typical choice is a subfolder "build". In this case, the commands are:
```
mkdir build
cd build
cmake ..
```
	
Note that CMake will check for any system dependencies that are needed for the build process. If the CMake build does not complete successfully, please review the error CMake shows at the end. If the error does not go away (even though you installed the dependency), try running "make clean" to clear the CMake cache.
	
5. If you want to use any external libraries, such as NTL/GMP or tcmalloc, install these libraries.

6. Build PALISADE by running the following command (this will take few minutes; using the -j make command-line flag is suggested to speed up the build)
```
make
```
If you want to build only library files or some other subset of PALISADE, please review the last paragraph of this page.  

After the "make" completes, you should see the PALISADE library files in the lib folder, binaries of demos in bin/demo, binaries of benchmarks in bib/benchmark, and binaries for unit tests in the unittest folder.

7. Install PALISADE to a system directory (if desired or for production purposes)
```
make install
```	
You would probably need to run "sudo make install" unless you are specifying some other install location. You can change the install location by running
"cmake -DCMAKE_INSTALL_PREFIX=/your/path ..". The header files are placed in the "include/palisade" folder of the specified path, and the binaries of the library are copied directly to the "lib" folder. For example, if no installation path is provided in Ubuntu (and many other Unix-based OSes), the header and library binary files will be placed in "/usr/local/inlude/palisade" and "/usr/local/lib", respectively.

Testing and cleaning the build
-------------------

Run unit tests to make sure all capabilities operate as expected
```
make testall
```

Run sample code to test, e.g., 
```
bin/examples/pke/simple-integers
```

To remove the files built by make, you can execute
```
make clean
```

Supported Operating Systems
--------------------------
PALISADE CI continually tests our builds on the following operating systems:

* Ubuntu [18.04]
* macOS [Mojave]
* Centos 7
* NVIDIA Xavier [Linux for Tegra 4.2.2]
* MinGW (64-bit) on Windows 10

PALISADE users have reported successful operation on the following systems:

* Free BSD 
* Ubuntu [16.04]

Please let us know the results if you have run PALISADE any additional systems not listed above. 

Detailed information about building PALISADE
------------------------------
	
More detailed steps for some common platforms are provided in the following Wiki articles:

[Instructions for building PALISADE in Linux](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-Linux)

[Instructions for building PALISADE in Windows](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-Windows)

[Instructions for building PALISADE in macOS](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-PALISADE-in-macOS)

PALISADE provides many CMake/make configuration options, such as installing specific modules of the library, compiling only libraries w/o any unit tests and demos, choosing the Debug mode for compilation, turning on/off NTL/GMP. These options are described in detail in the following Wiki article:

[Configuration flags to customize the build](https://gitlab.com/palisade/palisade-development/wikis/Configuration-flags-to-customize-the-build)

[Instructions for building C++ projects that use PALISADE](https://gitlab.com/palisade/palisade-development/wikis/Instructions-for-building-projects-that-use-PALISADE) 