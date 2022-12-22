# Performance

```text
hash/16B                time:   [238.39 ns 238.63 ns 238.92 ns]
                        thrpt:  [63.865 MiB/s 63.942 MiB/s 64.007 MiB/s]
hash/256B               time:   [449.11 ns 449.41 ns 449.75 ns]
                        thrpt:  [542.84 MiB/s 543.24 MiB/s 543.61 MiB/s]
hash/1KiB               time:   [1.1607 µs 1.1612 µs 1.1618 µs]
                        thrpt:  [840.53 MiB/s 840.97 MiB/s 841.37 MiB/s]
hash/16KiB              time:   [2.9230 µs 2.9282 µs 2.9342 µs]
                        thrpt:  [5.2003 GiB/s 5.2110 GiB/s 5.2203 GiB/s]
hash/1MiB               time:   [160.08 µs 160.25 µs 160.42 µs]
                        thrpt:  [6.0877 GiB/s 6.0942 GiB/s 6.1005 GiB/s]

prf/16B                 time:   [242.64 ns 242.82 ns 243.02 ns]
                        thrpt:  [62.789 MiB/s 62.839 MiB/s 62.887 MiB/s]
prf/256B                time:   [258.81 ns 258.97 ns 259.16 ns]
                        thrpt:  [942.03 MiB/s 942.74 MiB/s 943.32 MiB/s]
prf/1KiB                time:   [325.40 ns 325.67 ns 325.98 ns]
                        thrpt:  [2.9256 GiB/s 2.9283 GiB/s 2.9308 GiB/s]
prf/16KiB               time:   [1.7278 µs 1.7291 µs 1.7307 µs]
                        thrpt:  [8.8164 GiB/s 8.8246 GiB/s 8.8312 GiB/s]
prf/1MiB                time:   [104.47 µs 104.62 µs 104.79 µs]
                        thrpt:  [9.3194 GiB/s 9.3343 GiB/s 9.3477 GiB/s]

stream/16B              time:   [256.70 ns 256.94 ns 257.19 ns]
                        thrpt:  [59.330 MiB/s 59.386 MiB/s 59.443 MiB/s]
stream/256B             time:   [271.24 ns 271.40 ns 271.59 ns]
                        thrpt:  [898.94 MiB/s 899.55 MiB/s 900.08 MiB/s]
stream/1KiB             time:   [336.22 ns 336.54 ns 336.89 ns]
                        thrpt:  [2.8308 GiB/s 2.8338 GiB/s 2.8365 GiB/s]
stream/16KiB            time:   [1.6667 µs 1.6685 µs 1.6704 µs]
                        thrpt:  [9.1347 GiB/s 9.1452 GiB/s 9.1548 GiB/s]
stream/1MiB             time:   [90.925 µs 91.087 µs 91.251 µs]
                        thrpt:  [10.702 GiB/s 10.721 GiB/s 10.740 GiB/s]

aead/16B                time:   [338.50 ns 338.86 ns 339.25 ns]
                        thrpt:  [44.978 MiB/s 45.030 MiB/s 45.077 MiB/s]
aead/256B               time:   [354.53 ns 354.90 ns 355.36 ns]
                        thrpt:  [687.03 MiB/s 687.91 MiB/s 688.63 MiB/s]
aead/1KiB               time:   [419.52 ns 420.12 ns 421.02 ns]
                        thrpt:  [2.2652 GiB/s 2.2700 GiB/s 2.2732 GiB/s]
aead/16KiB              time:   [1.7387 µs 1.7398 µs 1.7410 µs]
                        thrpt:  [8.7646 GiB/s 8.7706 GiB/s 8.7761 GiB/s]
aead/1MiB               time:   [88.251 µs 88.627 µs 89.281 µs]
                        thrpt:  [10.938 GiB/s 11.019 GiB/s 11.066 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU.)
