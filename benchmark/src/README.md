# Benchmarking

Palisade uses the [Google microbenchmark support library](https://github.com/google/benchmark#running-benchmarks) to measure performance. Performance testing code can be found in `/benchmark/src`. After building, binaries are written to `/your_build_folder/bin/benchmark`. To build only tests and their dependencies, use the following command in the build folder:

```
make allbenchmark
```

To run the benchmark `benchmark-to-run` from the build folder for linux or macOS, run:

```
./bin/benchmark/benchmark-to-run
```

For Windows run:

 ```
 bin/benchmark/benchmark-to-run.exe
 ```

By default each benchmark is run once and that single result is reported. However benchmarks are often noisy and a single result may not be representative of the overall behavior. For this reason it's possible to repeatedly rerun the benchmark.

The number of runs of each benchmark is specified globally by the `--benchmark_repetitions` command-line flag or on a per benchmark basis by calling Repetitions on the registered benchmark object. When a benchmark is run more than once, the mean, median and standard deviation of the runs are reported.

Additionally the `--benchmark_report_aggregates_only={true|false}`, `--benchmark_display_aggregates_only={true|false}` flags can be used to change how repeated tests are reported. By default the result of each repeated run is reported. When the report aggregates only option is true, only the aggregates (i.e. mean, median and standard deviation, maybe complexity measurements if they were requested) of the runs are reported, to both reporters - standard output (console), and the file. However, when only the display aggregates only option is true, only the aggregates are displayed in the standard output, while the file output still contains everything.

OMP can also affect the benchmarking time. In order to reduce noise, it is advisable to set the number of threads not higher than the number of physical cores (as hyperthreading introduces a lot of variability).

```
export OMP_NUM_THREADS=number_of_cores
```

In order to remove the noise related to multithreading, set the number of threads to 1

```
export OMP_NUM_THREADS=1
```

## lib-benchmark

[lib-benchmark](lib-benchmark.cpp) is the main PALISADE library benchmark that contains performance tests for standard operations in the following schemes: BFVrns, CKKS, BGVrns. It also contains several performance tests for NTT and INTT transformations.

An example output after running `lib-benchmark` is as follows:

```
-------------------------------------------------------------------
Benchmark                         Time             CPU   Iterations
-------------------------------------------------------------------
NTTTransform1024               10.3 us         10.3 us        64120
INTTTransform1024              10.4 us         10.4 us        67201
NTTTransform4096               48.6 us         48.6 us        14371
INTTTransform4096              50.4 us         50.4 us        13848
BFVrns_KeyGen                  1188 us         1188 us          590
BFVrns_MultKeyGen              3824 us         3824 us          183
BFVrns_EvalAtIndexKeyGen       3867 us         3867 us          181
BFVrns_Encryption              1117 us         1117 us          626
BFVrns_Decryption               224 us          224 us         3113
BFVrns_Add                     20.4 us         20.4 us        34894
BFVrns_MultNoRelin             3567 us         3567 us          196
BFVrns_MultRelin               5191 us         5191 us          134
BFVrns_EvalAtIndex             1639 us         1639 us          427
CKKS_KeyGen                    1180 us         1180 us          593
CKKS_MultKeyGen                2179 us         2179 us          321
CKKS_EvalAtIndexKeyGen         2212 us         2212 us          317
CKKS_Encryption                1047 us         1047 us          669
CKKS_Decryption                 295 us          295 us         2368
CKKS_Add                       30.3 us         30.3 us        22968
CKKS_MultNoRelin                113 us          113 us         6138
CKKS_MultRelin                 1604 us         1604 us          436
CKKS_Relin                     1555 us         1555 us          450
CKKS_Rescale                    378 us          378 us         1852
CKKS_EvalAtIndex               1619 us         1619 us          431
BGVrns_KeyGen                   998 us          998 us          701
BGVrns_MultKeyGen              1516 us         1516 us          462
BGVrns_EvalAtIndexKeyGen       1549 us         1549 us          451
BGVrns_Encryption              1118 us         1118 us          626
BGVrns_Decryption               119 us          119 us         5902
BGVrns_Add                     30.3 us         30.3 us        23289
BGVrns_MultNoRelin              114 us          114 us         6145
BGVrns_MultRelin               1372 us         1372 us          509
BGVrns_Relin                   1326 us         1326 us          529
BGVrns_EvalAtIndex             1386 us         1386 us          504
```

## poly-benchmark

[poly-1k](poly-benchmark-1k.cpp), [poly-4k](poly-benchmark-4k.cpp), [poly-16k](poly-benchmark-16k.cpp), [poly-64k](poly-test-64k.cpp)
contains performance tests for primitive polynomial operations with ring sizes 1k, 4k, 16k, 64k, respectively.

The following operations are used to evaluate the performance: addition, Hadamard (component-wise) multiplication, NTT and INTT. These operations (especially NTT and iNTT) are the main bottleneck operations for all lattice cryptographic capabilities.

All operations are performed for NativePoly and DCRTPoly with settings for 1, 2, 4 and 8 towers (`tower` is the number of residues in the RNS representation of each large integer).

An example output after running `poly-benchmark-xk` is as follows:

```
-------------------------------------------------------------
Benchmark                   Time             CPU   Iterations
-------------------------------------------------------------
Native_add               1.23 us         1.23 us       570344
DCRT_add/towers:1        1.36 us         1.36 us       515252
DCRT_add/towers:2        2.69 us         2.69 us       260023
DCRT_add/towers:4        5.16 us         5.16 us       135897
DCRT_add/towers:8        10.1 us         10.1 us        69543
Native_mul               3.72 us         3.72 us       188534
DCRT_mul/towers:1        3.51 us         3.51 us       199335
DCRT_mul/towers:2        6.85 us         6.85 us       101571
DCRT_mul/towers:4        13.5 us         13.5 us        51500
DCRT_mul/towers:8        27.1 us         27.1 us        25879
Native_ntt               11.5 us         11.5 us        61099
DCRT_ntt/towers:1        11.8 us         11.8 us        59778
DCRT_ntt/towers:2        23.3 us         23.3 us        29982
DCRT_ntt/towers:4        46.5 us         46.5 us        15062
DCRT_ntt/towers:8        93.1 us         93.1 us         7519
Native_intt              12.3 us         12.3 us        56893
DCRT_intt/towers:1       12.6 us         12.6 us        55820
DCRT_intt/towers:2       25.0 us         25.0 us        27986
DCRT_intt/towers:4       50.0 us         50.0 us        13987
DCRT_intt/towers:8       99.7 us         99.7 us         7018
```

## other

There are several other benchmarking tests:

* [basic_test](basic_test.cpp) - trivial benchmarking
* [binfhe-ap](binfhe-ap.cpp) - boolean functions performance tests for **FHEW** scheme with AP bootstrapping technique. Please see "Bootstrapping in FHEW-like Cryptosystems" for details on both bootstrapping techniques
* [binfhe-ginx](binfhe-ginx.cpp) - boolean functions performance tests for **FHEW** scheme with GINX bootstrapping technique. Please see "Bootstrapping in FHEW-like Cryptosystems" for details on both bootstrapping techniques
* [compare-bfvrns-vs-bfvrnsB](compare-bfvrns-vs-bfvrnsB.cpp) - performance comparison between **BFVrns** and **BFVrnsB** schemes for similar parameter sets
* [compare-bfvrns-vs-bgvrns](compare-bfvrns-vs-bgvrns.cpp) - performance comparison between **BFVrns** and **BGVrns** schemes for similar parameter sets
* [Encoding](Encoding.cpp) - performance tests for different encoding techniques
* [IntegerMath](IntegerMath.cpp) - performance tests for the big integer operations
* [Lattice](Lattice.cpp) - performance tests for the Lattice operations.
* [NbTheory](NbTheory.cpp) - performance tests of number theory functions
* [VectorMath](VectorMath.cpp) - performance tests for the big vector operations
