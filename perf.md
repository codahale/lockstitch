# Performance

```text
hash/16B                time:   [243.88 ns 244.07 ns 244.29 ns]
                        thrpt:  [62.462 MiB/s 62.518 MiB/s 62.566 MiB/s]
hash/256B               time:   [450.09 ns 450.25 ns 450.43 ns]
                        thrpt:  [542.02 MiB/s 542.23 MiB/s 542.43 MiB/s]
hash/1KiB               time:   [1.1718 µs 1.1725 µs 1.1735 µs]
                        thrpt:  [832.19 MiB/s 832.88 MiB/s 833.41 MiB/s]
hash/16KiB              time:   [2.8599 µs 2.8631 µs 2.8666 µs]
                        thrpt:  [5.3229 GiB/s 5.3295 GiB/s 5.3355 GiB/s]
hash/1MiB               time:   [157.67 µs 157.83 µs 158.00 µs]
                        thrpt:  [6.1806 GiB/s 6.1872 GiB/s 6.1936 GiB/s]

prf/16B                 time:   [239.18 ns 239.29 ns 239.42 ns]
                        thrpt:  [63.732 MiB/s 63.766 MiB/s 63.795 MiB/s]
prf/256B                time:   [250.39 ns 250.50 ns 250.62 ns]
                        thrpt:  [974.13 MiB/s 974.62 MiB/s 975.06 MiB/s]
prf/1KiB                time:   [375.87 ns 375.98 ns 376.10 ns]
                        thrpt:  [2.5357 GiB/s 2.5365 GiB/s 2.5373 GiB/s]
prf/16KiB               time:   [2.8644 µs 2.8656 µs 2.8669 µs]
                        thrpt:  [5.3224 GiB/s 5.3248 GiB/s 5.3270 GiB/s]
prf/1MiB                time:   [170.48 µs 170.51 µs 170.56 µs]
                        thrpt:  [5.7257 GiB/s 5.7272 GiB/s 5.7284 GiB/s]

stream/16B              time:   [274.72 ns 274.83 ns 274.95 ns]
                        thrpt:  [55.496 MiB/s 55.522 MiB/s 55.544 MiB/s]
stream/256B             time:   [481.48 ns 481.72 ns 482.02 ns]
                        thrpt:  [506.49 MiB/s 506.81 MiB/s 507.06 MiB/s]
stream/1KiB             time:   [1.2671 µs 1.2676 µs 1.2682 µs]
                        thrpt:  [770.04 MiB/s 770.39 MiB/s 770.73 MiB/s]
stream/16KiB            time:   [5.6742 µs 5.6826 µs 5.6907 µs]
                        thrpt:  [2.6813 GiB/s 2.6852 GiB/s 2.6891 GiB/s]
stream/1MiB             time:   [344.81 µs 345.25 µs 345.74 µs]
                        thrpt:  [2.8246 GiB/s 2.8285 GiB/s 2.8322 GiB/s]

aead/16B                time:   [496.56 ns 496.80 ns 497.05 ns]
                        thrpt:  [30.699 MiB/s 30.714 MiB/s 30.729 MiB/s]
aead/256B               time:   [701.54 ns 701.72 ns 701.93 ns]
                        thrpt:  [347.81 MiB/s 347.92 MiB/s 348.01 MiB/s]
aead/1KiB               time:   [1.5513 µs 1.5518 µs 1.5523 µs]
                        thrpt:  [629.11 MiB/s 629.32 MiB/s 629.51 MiB/s]
aead/16KiB              time:   [5.9902 µs 5.9959 µs 6.0016 µs]
                        thrpt:  [2.5425 GiB/s 2.5449 GiB/s 2.5473 GiB/s]
aead/1MiB               time:   [348.48 µs 349.07 µs 349.65 µs]
                        thrpt:  [2.7930 GiB/s 2.7976 GiB/s 2.8024 GiB/s]
```

(Benchmarks run on a GCE `n2-standard-4` with an Intel Ice Lake CPU.)
