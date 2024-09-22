The basis of this project can be found here: https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/45558f406a67923938c8e697d6489489aa902cdd/src/23-http

# Prerequisites

This project requires HdrHistogram. You can install this package on your system;

```
$ sudo dnf install HdrHistogram_c.x86_64 HdrHistogram_c-devel.x86_64
```

# Building

To build the bpf_validator tool, run;

```
$ make
```

# Running bpf_validator

`bpf_validator` run independently of any load generator or system under test.  By default the tool monitors packets on port `8000`.

To run the tool;

```
$ sudo ./bpf_validator
```

You can then run the load test. After the load test has complete, kill the `bpf_validator` process with `CTRL+C` and the summary statistics will be written to stdout;

```
$ sudo ./bpf_validator 

libbpf: loading object 'bpf_validator_bpf' from buffer
...
libbpf: map '.rodata.str1.1': created successfully, fd=7

^C

Printing HdrHistogram stats:

       Value   Percentile   TotalCount 1/(1-Percentile)

       0.485     0.000000            1         1.00
       0.556     0.100000           27         1.11
       0.590     0.200000           52         1.25
       0.614     0.300000           80         1.43
       0.636     0.400000          104         1.67
       0.658     0.500000          130         2.00
       0.665     0.550000          143         2.22
       0.673     0.600000          156         2.50
       0.680     0.650000          169         2.86
       0.688     0.700000          183         3.33
       0.693     0.750000          195         4.00
       0.697     0.775000          203         4.44
       0.699     0.800000          208         5.00
       0.709     0.825000          216         5.71
       0.713     0.850000          224         6.67
       0.720     0.875000          228         8.00
       0.721     0.887500          231         8.89
       0.723     0.900000          234        10.00
       0.727     0.912500          238        11.43
       0.730     0.925000          241        13.33
       0.736     0.937500          244        16.00
       0.745     0.943750          246        17.78
       0.747     0.950000          247        20.00
       0.754     0.956250          249        22.86
       0.762     0.962500          251        26.67
       0.775     0.968750          252        32.00
       0.779     0.971875          253        35.56
       0.783     0.975000          254        40.00
       0.786     0.978125          255        45.71
       0.792     0.981250          256        53.33
       0.792     0.984375          256        64.00
       0.799     0.985938          257        71.11
       0.799     0.987500          257        80.00
       0.806     0.989062          258        91.43
       0.806     0.990625          258       106.67
       0.806     0.992188          258       128.00
       0.885     0.992969          259       142.22
       0.885     0.993750          259       160.00
       0.885     0.994531          259       182.86
       0.885     0.995313          259       213.33
       0.885     0.996094          259       256.00
       0.961     0.996484          260       284.44
       0.961     1.000000          260          inf
#[Mean    =        0.649, StdDeviation   =        0.069]
#[Max     =        0.961, Total count    =          260]
#[Buckets =           22, SubBuckets     =         2048]

50.0th Percentile: 0.657919
90.0th Percentile: 0.722943
99.0th Percentile: 0.799231
99.9th Percentile: 0.961023
99.99th Percentile: 0.961023

260 requests in 25.903915s
Av Throughput: 10.037093 req/sec

```
